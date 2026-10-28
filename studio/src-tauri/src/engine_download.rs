// SPDX-License-Identifier: GPL-3.0-or-later
//! Native download of the one pinned engine archive. No downloaded code runs.
use isohopper_core::engine::archive::{ARCHIVE_BYTES, ARCHIVE_SHA256};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};
#[path = "engine_download/cache.rs"]
mod cache;
#[path = "engine_download/network.rs"]
mod network;

const VERSION: &str = "1.1.18";
const FILE_NAME: &str = "ventoy-1.1.18-linux.tar.gz";
const DOWNLOAD_URL: &str =
    "https://github.com/ventoy/Ventoy/releases/download/v1.1.18/ventoy-1.1.18-linux.tar.gz";

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub job_id: String,
    pub phase: String,
    pub active: bool,
    pub cancel_requested: bool,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub expected_sha256: String,
    pub version: String,
    pub cache_hit: bool,
    pub message: String,
}

#[derive(Clone, Copy)]
struct Pin {
    bytes: u64,
    sha256: &'static str,
}
const PIN: Pin = Pin {
    bytes: ARCHIVE_BYTES as u64,
    sha256: ARCHIVE_SHA256,
};
struct Job {
    state: Mutex<Snapshot>,
    selected: AtomicBool,
}
impl Job {
    fn finish(&self, result: Result<bool, String>) {
        // A worker panic must not strand the UI in an active state.
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match result {
            Ok(hit) => {
                state.phase = "ready".into();
                state.cache_hit = hit;
                state.message = "Verified engine archive selected.".into();
            }
            Err(error) => {
                state.phase = if state.cancel_requested {
                    "cancelled"
                } else {
                    "failed"
                }
                .into();
                state.message = error.chars().take(1024).collect();
            }
        }
        state.active = false;
        self.state.clear_poison();
    }
    fn request_cancel(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Engine download state is unavailable")?;
        if !state.active || self.selected.load(Ordering::Acquire) {
            return Err("Engine download is already finished.".into());
        }
        state.cancel_requested = true;
        state.message = "Cancelling engine download.".into();
        Ok(())
    }
    fn new(id: String, pin: Pin) -> Self {
        Self {
            selected: AtomicBool::new(false),
            state: Mutex::new(Snapshot {
                job_id: id,
                phase: "checking_cache".into(),
                active: true,
                cancel_requested: false,
                completed_bytes: 0,
                total_bytes: pin.bytes,
                expected_sha256: pin.sha256.into(),
                version: VERSION.into(),
                cache_hit: false,
                message: "Checking the engine cache.".into(),
            }),
        }
    }
    fn snapshot(&self) -> Result<Snapshot, String> {
        self.state
            .lock()
            .map(|s| s.clone())
            .map_err(|_| "Engine download state is unavailable".into())
    }
    fn progress(&self, phase: &str, completed: u64) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Engine download state is unavailable")?;
        if state.cancel_requested {
            return Err("Engine download cancelled.".into());
        }
        state.phase = phase.into();
        state.completed_bytes = completed;
        state.message = match phase {
            "checking_cache" => "Checking the engine cache.",
            "verifying" => "Verifying the pinned engine archive.",
            _ => "Downloading the pinned engine archive.",
        }
        .into();
        Ok(())
    }
    fn check_cancel(&self) -> Result<(), String> {
        if self.snapshot()?.cancel_requested {
            Err("Engine download cancelled.".into())
        } else {
            Ok(())
        }
    }
    fn select(&self, hit: bool, select: impl FnOnce() -> Result<(), String>) -> Result<(), String> {
        // This lock makes cancel versus final selection a single decision.
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Engine download state is unavailable")?;
        if state.cancel_requested {
            return Err("Engine download cancelled.".into());
        }
        select()?;
        self.selected.store(true, Ordering::Release);
        state.cache_hit = hit;
        state.completed_bytes = state.total_bytes;
        Ok(())
    }
}
#[derive(Default)]
struct Registry(Mutex<Option<Arc<Job>>>);
impl Registry {
    fn register(&self, job: Arc<Job>) -> Result<(), String> {
        let mut current = self
            .0
            .lock()
            .map_err(|_| "Engine download registry is unavailable")?;
        if let Some(old) = current.as_ref()
            && old.snapshot()?.active
        {
            return Err("An engine download is already running.".into());
        }
        *current = Some(job);
        Ok(())
    }
    fn snapshot(&self) -> Result<Option<Snapshot>, String> {
        self.0
            .lock()
            .map_err(|_| "Engine download registry is unavailable")?
            .as_ref()
            .map(|job| job.snapshot())
            .transpose()
    }
    fn cancel(&self, id: &str) -> Result<(), String> {
        let current = self
            .0
            .lock()
            .map_err(|_| "Engine download registry is unavailable")?;
        let job = current.as_ref().ok_or("No engine download exists.")?;
        if job.snapshot()?.job_id != id {
            return Err("Unknown engine download job.".into());
        }
        job.request_cancel()
    }
}
fn run_worker<G>(job: &Job, guard: G, work: impl FnOnce() -> Result<bool, String>) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(work))
        .unwrap_or_else(|_| Err("Engine download stopped unexpectedly.".into()));
    // `work` and all its temporary files/handles are gone before completion or
    // guard release lets another native operation begin.
    job.finish(result);
    drop(guard);
}

fn restore_cache(
    root: &Path,
    pin: Pin,
    select: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<bool, String> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("Inspect engine cache directory: {error}")),
        Ok(_) => (),
    }
    let cache = cache::Directory::open(root)?;
    let path = cache.path.join(FILE_NAME);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("Inspect engine cache file: {error}")),
        Ok(_) => (),
    }
    let mut file = cache::open_regular(&path)?;
    let identity = cache::identity(&file)?;
    if !verify(
        &mut file,
        &Job::new(String::new(), pin),
        pin,
        "checking_cache",
    )? {
        return Ok(false);
    }
    cache.check()?;
    cache::same_file(&path, &identity)?;
    drop(file);
    select(&path)?;
    Ok(true)
}
struct Download {
    body: Box<dyn Read>,
    length: Option<u64>,
}

fn obtain(
    root: &Path,
    job: &Job,
    pin: Pin,
    fetch: impl FnOnce() -> Result<Download, String>,
    select: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<bool, String> {
    job.check_cancel()?;
    let cache = cache::Directory::open(root)?;
    let destination = cache.path.join(FILE_NAME);
    let existing = match fs::symlink_metadata(&destination) {
        Ok(_) => {
            let mut file = cache::open_regular(&destination)?;
            let identity = cache::identity(&file)?;
            if verify(&mut file, job, pin, "checking_cache")? {
                cache.check()?;
                cache::same_file(&destination, &identity)?;
                drop(file);
                job.select(true, || select(&destination))?;
                return Ok(true);
            }
            Some(identity)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(format!("Inspect engine cache: {error}")),
    };
    job.progress("downloading", 0)?;
    let mut download = fetch()?;
    job.check_cancel()?;
    if download.length.is_some_and(|length| length != pin.bytes) {
        return Err("Engine archive size does not match the pinned release.".into());
    }
    cache.check()?;
    let mut temporary = tempfile::Builder::new()
        .prefix(".engine-")
        .suffix(".part")
        .tempfile_in(&cache.path)
        .map_err(|e| format!("Create engine download: {e}"))?;
    let mut hasher = Sha256::new();
    let mut completed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        job.check_cancel()?;
        // Read one extra byte at the limit; never trust Content-Length.
        let limit = ((pin.bytes - completed).saturating_add(1)).min(buffer.len() as u64) as usize;
        let count = download
            .body
            .read(&mut buffer[..limit])
            .map_err(|e| format!("Read engine download: {e}"))?;
        job.check_cancel()?;
        if count == 0 {
            break;
        }
        completed += count as u64;
        if completed > pin.bytes {
            return Err("Engine archive exceeds the pinned size.".into());
        }
        temporary
            .write_all(&buffer[..count])
            .map_err(|e| format!("Write engine download: {e}"))?;
        hasher.update(&buffer[..count]);
        job.progress("downloading", completed)?;
    }
    drop(download);
    if completed != pin.bytes {
        return Err("Engine archive size does not match the pinned release.".into());
    }
    job.progress("verifying", completed)?;
    if format!("{:x}", hasher.finalize()) != pin.sha256 {
        return Err("Engine archive SHA-256 does not match the pinned release.".into());
    }
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| format!("Flush engine download: {e}"))?;
    // into_temp_path closes the writable handle before verification/publication.
    let temporary = temporary.into_temp_path();
    let mut read_only = cache::open_regular(&temporary)?;
    if !verify(&mut read_only, job, pin, "verifying")? {
        return Err("Saved engine archive SHA-256 or size changed.".into());
    }
    drop(read_only);
    job.check_cancel()?;
    cache.check()?;
    if let Some(identity) = existing {
        cache::same_file(&destination, &identity)?;
        // Unlink this invalid cache entry only; never follow it or overwrite a
        // competing destination. A failed fetch leaves the old entry untouched.
        fs::remove_file(&destination).map_err(|e| format!("Replace invalid engine cache: {e}"))?;
    }
    temporary
        .persist_noclobber(&destination)
        .map_err(|e| format!("Publish verified engine cache: {}", e.error))?;
    cache.check()?;
    job.select(false, || select(&destination))?;
    Ok(false)
}

fn verify(file: &mut fs::File, job: &Job, pin: Pin, phase: &str) -> Result<bool, String> {
    let before = file
        .metadata()
        .map_err(|e| format!("Inspect engine archive: {e}"))?;
    if before.len() != pin.bytes {
        return Ok(false);
    }
    let mut hasher = Sha256::new();
    let mut completed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        job.progress(phase, completed)?;
        let limit = ((pin.bytes - completed).saturating_add(1)).min(buffer.len() as u64) as usize;
        let count = file
            .read(&mut buffer[..limit])
            .map_err(|e| format!("Verify engine archive: {e}"))?;
        if count == 0 {
            break;
        }
        completed += count as u64;
        if completed > pin.bytes {
            return Ok(false);
        }
        hasher.update(&buffer[..count]);
    }
    let after = file
        .metadata()
        .map_err(|e| format!("Recheck engine archive: {e}"))?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err("Engine archive changed during verification.".into());
    }
    Ok(completed == pin.bytes && format!("{:x}", hasher.finalize()) == pin.sha256)
}

fn registry() -> &'static Registry {
    static REGISTRY: OnceLock<Registry> = OnceLock::new();
    REGISTRY.get_or_init(Registry::default)
}
pub fn start(root: PathBuf, guard: crate::NativeJob) -> Result<Snapshot, String> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).map_err(|e| format!("Create engine download ID: {e}"))?;
    let id = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let job = Arc::new(Job::new(id, PIN));
    let initial = job.snapshot()?;
    registry().register(job.clone())?;
    let worker = job.clone();
    if let Err(error) = std::thread::Builder::new()
        .name("engine-download".into())
        .spawn(move || {
            run_worker(&worker, guard, || {
                obtain(&root, &worker, PIN, network::fetch, |path| {
                    crate::preparation::inputs::select_archive(path).map(|_| ())
                })
            });
        })
    {
        let message = format!("Start engine download: {error}");
        job.finish(Err(message.clone()));
        return Err(message);
    }
    Ok(initial)
}
pub fn status() -> Result<Option<Snapshot>, String> {
    registry().snapshot()
}
pub fn cancel(id: &str) -> Result<(), String> {
    registry().cancel(id)
}
pub fn active() -> bool {
    status()
        .map(|job| job.is_some_and(|job| job.active))
        .unwrap_or(true)
}

/// Restore only verified local bytes; callers hold the native operation guard.
pub fn restore(root: PathBuf) -> Result<bool, String> {
    restore_cache(&root, PIN, |path| {
        crate::preparation::inputs::select_archive(path).map(|_| ())
    })
}

#[cfg(test)]
#[path = "engine_download/tests.rs"]
mod tests;
