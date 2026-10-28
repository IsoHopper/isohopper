// SPDX-License-Identifier: GPL-3.0-or-later
//! Native-owned preparation state. Renderer state is never a write capability.
// Windows runner state is also compiled by portable regression tests.
#![cfg_attr(not(windows), allow(dead_code))]
#[path = "preparation/inputs.rs"]
pub mod inputs;
#[path = "preparation/protocol.rs"]
mod protocol;
#[path = "preparation/targets.rs"]
pub mod targets;
#[cfg(windows)]
#[path = "preparation/windows.rs"]
mod windows;

use crate::imports::source_catalog::{SourceBatch, SourceInfo, SourceLease};
use serde::Serialize;
use std::fs::File;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

/// Review metadata only. It cannot reopen or lease a catalogue source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SourceManifestEntry {
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub job_id: String,
    pub phase: String,
    pub message: String,
    pub active: bool,
    pub cancel_requested: bool,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub bytes_written: u64,
    pub bytes_verified: u64,
    pub target_may_be_incomplete: bool,
    pub sources_released: bool,
    pub source_manifest: Vec<SourceManifestEntry>,
    pub target: Option<serde_json::Value>,
    pub image_sha256: Option<String>,
    pub description_digest: Option<String>,
    pub challenge: Option<String>,
}
#[derive(Clone)]
struct Confirmation {
    digest: String,
    challenge: String,
}
struct State {
    snapshot: Snapshot,
    confirmation: Option<Confirmation>,
    confirmation_queued: bool,
}
struct Job {
    state: Mutex<State>,
    abort: AtomicBool,
}
impl Job {
    fn finish(&self, result: Result<(), String>) -> Result<(), String> {
        self.update(|snapshot| {
            if let Err(error) = result {
                snapshot.phase = if snapshot.cancel_requested && !snapshot.target_may_be_incomplete
                {
                    "cancelled"
                } else {
                    "failed"
                }
                .into();
                snapshot.message = error;
            }
            snapshot.active = false;
        })
    }

    fn with_verified_archive<T>(
        &self,
        archive: &SourceLease,
        use_archive: impl FnOnce(&mut File, &SourceInfo) -> Result<T, String>,
    ) -> Result<T, String> {
        archive.with_verified_source_with_progress(
            |completed, total| self.verification_progress("verifying_archive", completed, total),
            use_archive,
        )
    }

    fn verification_progress(&self, phase: &str, completed: u64, total: u64) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Preparation state is unavailable")?;
        if state.snapshot.cancel_requested {
            return Err("Preparation cancelled during input verification.".into());
        }
        if completed > total {
            return Err("Invalid input verification progress.".into());
        }
        state.snapshot.phase = phase.into();
        state.snapshot.message =
            "Rechecking retained input bytes before starting the helper.".into();
        state.snapshot.completed_bytes = completed;
        state.snapshot.total_bytes = total;
        Ok(())
    }

    /// Publish metadata only after every transfer callback and the final source
    /// stability checks succeed. Earlier callbacks may already have sent handles
    /// on failure, but the UI never receives a partial or unverified manifest.
    fn transfer_sources(
        &self,
        sources: &SourceBatch,
        transfer: impl FnMut(&File, &SourceInfo) -> Result<(), String>,
    ) -> Result<(), String> {
        let manifest = sources
            .visit_verified_with_progress(
                |completed, total| {
                    self.verification_progress("verifying_sources", completed, total)
                },
                transfer,
            )?
            .into_iter()
            .map(|source| SourceManifestEntry {
                relative_path: source.relative_path,
                bytes: source.bytes,
                sha256: source.verification.digest,
            })
            .collect();
        self.update(|snapshot| snapshot.source_manifest = manifest)
    }

    /// Verify the complete source batch before launching. The archive's cursor
    /// and identity lease cover the connection callback through acknowledgement.
    /// Keep any partial channel in the caller's slot so errors still clean it up.
    fn transfer_inputs<C>(
        &self,
        sources: &SourceBatch,
        archive: &SourceLease,
        channel: &mut Option<C>,
        mut connect: impl FnMut(&mut Option<C>, &mut File, &SourceInfo) -> Result<(), String>,
        mut transfer: impl FnMut(&mut C, &File, &SourceInfo) -> Result<(), String>,
    ) -> Result<(), String> {
        self.transfer_sources(sources, |file, info| {
            if channel.is_none() {
                self.with_verified_archive(archive, |file, info| connect(channel, file, info))?;
            }
            transfer(
                channel.as_mut().ok_or("Missing helper channel")?,
                file,
                info,
            )
        })?;
        // An empty medium still needs its verified engine and helper session.
        if channel.is_none() {
            self.with_verified_archive(archive, |file, info| connect(channel, file, info))?;
        }
        channel.as_ref().ok_or("Missing helper channel")?;
        Ok(())
    }

    fn note_reply(
        &self,
        body: &isohopper_helper::prepare_protocol::ClientMessage,
    ) -> Result<(), String> {
        if matches!(
            body,
            isohopper_helper::prepare_protocol::ClientMessage::Confirm { .. }
        ) {
            self.update(|snapshot| snapshot.target_may_be_incomplete = true)?;
        }
        Ok(())
    }
    fn new(id: String) -> Self {
        Self {
            state: Mutex::new(State {
                snapshot: Snapshot {
                    job_id: id,
                    phase: "verifying_sources".into(),
                    message: "Rechecking retained source files before starting the helper.".into(),
                    active: true,
                    cancel_requested: false,
                    completed_bytes: 0,
                    total_bytes: 0,
                    bytes_written: 0,
                    bytes_verified: 0,
                    target_may_be_incomplete: false,
                    sources_released: false,
                    source_manifest: Vec::new(),
                    target: None,
                    image_sha256: None,
                    description_digest: None,
                    challenge: None,
                },
                confirmation: None,
                confirmation_queued: false,
            }),
            abort: AtomicBool::new(false),
        }
    }
    fn snapshot(&self) -> Result<Snapshot, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "Preparation state is unavailable")?
            .snapshot
            .clone())
    }
    fn update(&self, change: impl FnOnce(&mut Snapshot)) -> Result<(), String> {
        change(
            &mut self
                .state
                .lock()
                .map_err(|_| "Preparation state is unavailable")?
                .snapshot,
        );
        Ok(())
    }
    fn cancel(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Preparation state is unavailable")?;
        if !state.snapshot.active {
            return Err("Preparation is already finished".into());
        }
        state.snapshot.cancel_requested = true;
        state.confirmation = None;
        Ok(())
    }
    fn confirm(&self, digest: String, challenge: String) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Preparation state is unavailable")?;
        if !state.snapshot.active
            || state.snapshot.phase != "await_confirmation"
            || state.snapshot.cancel_requested
            || state.confirmation_queued
            || state.snapshot.description_digest.as_ref() != Some(&digest)
            || state.snapshot.challenge.as_ref() != Some(&challenge)
        {
            return Err("Confirmation does not match the current prepared job".into());
        }
        state.confirmation = Some(Confirmation { digest, challenge });
        state.confirmation_queued = true;
        Ok(())
    }
}

static JOB: OnceLock<Mutex<Option<Arc<Job>>>> = OnceLock::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
fn jobs() -> &'static Mutex<Option<Arc<Job>>> {
    JOB.get_or_init(|| Mutex::new(None))
}
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}
pub fn status() -> Result<Option<Snapshot>, String> {
    jobs()
        .lock()
        .map_err(|_| "Preparation state is unavailable")?
        .as_ref()
        .map(|j| j.snapshot())
        .transpose()
}
fn selected(id: &str) -> Result<Arc<Job>, String> {
    let job = jobs()
        .lock()
        .map_err(|_| "Preparation state is unavailable")?
        .as_ref()
        .cloned()
        .ok_or("No preparation job exists")?;
    if job.snapshot()?.job_id != id {
        return Err("Unknown preparation job".into());
    }
    Ok(job)
}
pub fn confirm(id: &str, digest: String, challenge: String) -> Result<(), String> {
    selected(id)?.confirm(digest, challenge)
}
pub fn cancel(id: &str) -> Result<(), String> {
    selected(id)?.cancel()
}

#[cfg(windows)]
pub use windows::start;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::imports::source_catalog::{PreparedSource, SourceCatalog};
    use std::fs::File;

    fn input_fixture(
        names: &[&str],
    ) -> (tempfile::TempDir, SourceCatalog, SourceBatch, SourceLease) {
        let root = tempfile::tempdir().unwrap();
        let mut catalogue = SourceCatalog::default();
        let mut prepared = Vec::new();
        for name in std::iter::once(&"archive.tar.gz").chain(names.iter()) {
            let path = root.path().join(name);
            std::fs::write(&path, name.as_bytes()).unwrap();
            prepared.push(PreparedSource::new(File::open(path).unwrap(), name).unwrap());
        }
        let infos = catalogue.insert_batch(prepared).unwrap();
        let archive = catalogue.lease(&infos[0].source_id).unwrap();
        let sources = catalogue
            .lease_batch(
                &infos[1..]
                    .iter()
                    .map(|i| i.source_id.clone())
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        (root, catalogue, sources, archive)
    }

    #[test]
    fn empty_inputs_connect_with_verified_retained_archive() {
        use std::io::Read;
        let (_root, mut catalogue, sources, archive) = input_fixture(&[]);
        let job = Job::new("empty-inputs".into());
        let mut channel = None;
        let mut connections = 0;
        job.transfer_inputs(
            &sources,
            &archive,
            &mut channel,
            |slot, file, info| {
                connections += 1;
                let snapshot = job.snapshot().unwrap();
                assert_eq!(snapshot.phase, "verifying_archive");
                assert_eq!((snapshot.completed_bytes, snapshot.total_bytes), (14, 14));
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes).unwrap();
                assert_eq!(bytes, b"archive.tar.gz");
                assert!(catalogue.release(&info.source_id).is_err());
                *slot = Some("archive acknowledged");
                Ok(())
            },
            |_, _, _| panic!("empty input must not transfer an ISO"),
        )
        .unwrap();
        assert_eq!(connections, 1);
        assert_eq!(channel, Some("archive acknowledged"));
        assert!(job.snapshot().unwrap().source_manifest.is_empty());
    }

    #[test]
    fn nonempty_inputs_connect_once_then_transfer_every_source() {
        let (_root, _catalogue, sources, archive) = input_fixture(&["first.iso", "last.iso"]);
        let job = Job::new("ordered-inputs".into());
        let mut channel = None;
        let mut connections = 0;
        job.transfer_inputs(
            &sources,
            &archive,
            &mut channel,
            |slot, _, _| {
                connections += 1;
                *slot = Some(vec!["archive acknowledged".to_string()]);
                Ok(())
            },
            |events, _, info| {
                events.push(info.relative_path.clone());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(connections, 1);
        assert_eq!(
            channel.unwrap(),
            ["archive acknowledged", "first.iso", "last.iso"]
        );
        assert_eq!(job.snapshot().unwrap().source_manifest.len(), 2);
    }

    #[test]
    fn cancelled_empty_inputs_never_connect() {
        let (_root, _catalogue, sources, archive) = input_fixture(&[]);
        let job = Job::new("cancelled-empty-inputs".into());
        job.cancel().unwrap();
        let mut channel: Option<()> = None;
        let error = job
            .transfer_inputs(
                &sources,
                &archive,
                &mut channel,
                |_, _, _| panic!("cancelled job must not launch"),
                |_, _, _| panic!("cancelled job must not transfer"),
            )
            .unwrap_err();
        assert!(error.contains("cancelled"), "{error}");
        assert!(channel.is_none());
    }

    #[test]
    fn empty_inputs_retain_partial_channel_for_failure_cleanup() {
        let (_root, _catalogue, sources, archive) = input_fixture(&[]);
        let job = Job::new("failed-empty-inputs".into());
        let mut channel = None;
        let error = job
            .transfer_inputs(
                &sources,
                &archive,
                &mut channel,
                |slot, _, _| {
                    *slot = Some("launched helper requires cleanup");
                    Err("archive acknowledgement failed".into())
                },
                |_, _, _| panic!("empty input must not transfer an ISO"),
            )
            .unwrap_err();
        assert_eq!(error, "archive acknowledgement failed");
        assert_eq!(channel, Some("launched helper requires cleanup"));
    }

    #[cfg(unix)]
    #[test]
    fn all_sources_and_archive_are_rehashed_before_connecting() {
        use std::io::Write;
        for (names, changed) in [
            (&["first.iso", "last.iso"][..], "last.iso"),
            (&[][..], "archive.tar.gz"),
        ] {
            let (root, _catalogue, sources, archive) = input_fixture(names);
            let path = root.path().join(changed);
            let before = std::fs::metadata(&path).unwrap();
            let mut writer = std::fs::OpenOptions::new().write(true).open(path).unwrap();
            writer
                .write_all(&vec![b'!'; before.len() as usize])
                .unwrap();
            writer
                .set_times(std::fs::FileTimes::new().set_modified(before.modified().unwrap()))
                .unwrap();
            let job = Job::new("changed-inputs".into());
            let mut channel: Option<()> = None;
            let error = job
                .transfer_inputs(
                    &sources,
                    &archive,
                    &mut channel,
                    |_, _, _| panic!("changed input must not launch"),
                    |_, _, _| panic!("changed input must not transfer"),
                )
                .unwrap_err();
            assert!(error.contains("checksum mismatch"), "{error}");
            assert!(channel.is_none());
        }
    }

    #[test]
    fn transferred_manifest_survives_catalogue_release_and_terminal_snapshots() {
        let root = tempfile::tempdir().unwrap();
        let mut catalogue = SourceCatalog::default();
        let mut sources = Vec::new();
        for (name, bytes) in [("Mac/boot.iso", b"abc"), ("Windows/boot.iso", b"xyz")] {
            let path = root.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            sources.push(PreparedSource::new(File::open(path).unwrap(), name).unwrap());
        }
        let infos = catalogue.insert_batch(sources).unwrap();
        let ids = [infos[1].source_id.clone(), infos[0].source_id.clone()];
        let batch = catalogue.lease_batch(&ids).unwrap();
        let job = Job::new("manifest-job".into());
        let mut transferred = Vec::new();
        job.transfer_sources(&batch, |file, info| {
            assert_eq!(file.metadata().unwrap().len(), info.bytes);
            let snapshot = job.snapshot().unwrap();
            assert_eq!(snapshot.phase, "verifying_sources");
            assert_eq!((snapshot.completed_bytes, snapshot.total_bytes), (6, 6));
            transferred.push(info.relative_path.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(transferred, ["Windows/boot.iso", "Mac/boot.iso"]);
        let manifest = job.snapshot().unwrap().source_manifest;
        assert_eq!(manifest[0].relative_path, infos[1].relative_path);
        assert_eq!(manifest[0].bytes, infos[1].bytes);
        assert_eq!(manifest[0].sha256, infos[1].verification.digest);
        assert_eq!(manifest[1].sha256, infos[0].verification.digest);
        drop(batch);
        catalogue.release_sources(&ids).unwrap();
        assert!(catalogue.list_sources().is_empty());
        job.update(|s| {
            s.sources_released = true;
            s.phase = "await_confirmation".into();
        })
        .unwrap();
        assert_eq!(job.snapshot().unwrap().source_manifest, manifest);
        job.update(|s| {
            s.active = false;
            s.phase = "succeeded".into();
        })
        .unwrap();
        let receipt = serde_json::to_value(job.snapshot().unwrap()).unwrap();
        assert_eq!(
            receipt["source_manifest"][0]["relative_path"],
            "Windows/boot.iso"
        );
        assert_eq!(job.snapshot().unwrap().source_manifest, manifest);
        let serialized = receipt.to_string();
        assert!(!serialized.contains("source_id"));
        assert!(!serialized.contains(&root.path().display().to_string()));
        assert!(catalogue.lease(&ids[0]).is_err());
    }

    #[test]
    fn failed_transfer_does_not_publish_a_partial_source_manifest() {
        let root = tempfile::tempdir().unwrap();
        let mut catalogue = SourceCatalog::default();
        let mut sources = Vec::new();
        for name in ["first.iso", "last.iso"] {
            let path = root.path().join(name);
            std::fs::write(&path, name).unwrap();
            sources.push(PreparedSource::new(File::open(path).unwrap(), name).unwrap());
        }
        let infos = catalogue.insert_batch(sources).unwrap();
        let ids: Vec<_> = infos.iter().map(|info| info.source_id.clone()).collect();
        let batch = catalogue.lease_batch(&ids).unwrap();
        let job = Job::new("failed-job".into());
        let mut count = 0;
        let error = job
            .transfer_sources(&batch, |_, _| {
                count += 1;
                if count == 2 {
                    Err("receiver rejected final source".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error, "receiver rejected final source");
        assert_eq!(count, 2);
        assert!(job.snapshot().unwrap().source_manifest.is_empty());
        assert!(catalogue.release_sources(&ids).is_err());
        drop(batch);
        catalogue.release_sources(&ids).unwrap();
    }

    #[test]
    fn cancelled_job_does_not_hash_or_transfer_sources() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("boot.iso");
        std::fs::write(&path, vec![b'a'; 1_000_000]).unwrap();
        let mut catalogue = SourceCatalog::default();
        let info = catalogue
            .insert_batch(vec![
                PreparedSource::new(File::open(path).unwrap(), "boot.iso").unwrap(),
            ])
            .unwrap()
            .remove(0);
        let batch = catalogue.lease_batch(&[info.source_id]).unwrap();
        let job = Job::new("cancelled-job".into());
        job.cancel().unwrap();
        let mut transferred = false;
        let result = job.transfer_sources(&batch, |_, _| {
            transferred = true;
            Ok(())
        });
        assert!(result.is_err());
        job.finish(result).unwrap();
        assert!(!transferred);
        let snapshot = job.snapshot().unwrap();
        assert!(snapshot.source_manifest.is_empty());
        assert_eq!(snapshot.completed_bytes, 0);
        assert_eq!(snapshot.phase, "cancelled");
        assert!(!snapshot.active);
    }

    #[test]
    fn cancelled_archive_verification_never_reaches_the_launch_callback() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("archive.tar.gz");
        std::fs::write(&path, vec![b'a'; 1_000_000]).unwrap();
        let mut catalogue = SourceCatalog::default();
        let info = catalogue
            .insert_batch(vec![
                PreparedSource::new(File::open(path).unwrap(), "archive.tar.gz").unwrap(),
            ])
            .unwrap()
            .remove(0);
        let archive = catalogue.lease(&info.source_id).unwrap();
        let job = Job::new("archive-job".into());
        job.cancel().unwrap();
        let mut launched = false;
        let result = job.with_verified_archive(&archive, |_, _| {
            launched = true;
            Ok(())
        });
        assert!(result.is_err());
        job.finish(result).unwrap();
        assert!(!launched);
        let snapshot = job.snapshot().unwrap();
        assert_eq!(snapshot.phase, "cancelled");
        assert!(!snapshot.active);
        assert!(snapshot.source_manifest.is_empty());
        assert!(catalogue.release(&info.source_id).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn real_checksum_mismatch_finishes_failed_without_source_transfer() {
        use std::io::Write;
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("boot.iso");
        std::fs::write(&path, b"abc").unwrap();
        let mut catalogue = SourceCatalog::default();
        let info = catalogue
            .insert_batch(vec![
                PreparedSource::new(File::open(&path).unwrap(), "boot.iso").unwrap(),
            ])
            .unwrap()
            .remove(0);
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let mut writer = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        writer.write_all(b"xyz").unwrap();
        writer
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let batch = catalogue.lease_batch(&[info.source_id]).unwrap();
        let job = Job::new("mismatch-job".into());
        let mut transferred = false;
        let result = job.transfer_sources(&batch, |_, _| {
            transferred = true;
            Ok(())
        });
        assert!(result.as_ref().unwrap_err().contains("checksum mismatch"));
        job.finish(result).unwrap();
        assert!(!transferred);
        let snapshot = job.snapshot().unwrap();
        assert_eq!(snapshot.phase, "failed");
        assert!(!snapshot.active);
        assert!(!snapshot.cancel_requested);
        assert!(snapshot.source_manifest.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn final_source_stability_failure_does_not_publish_a_manifest() {
        let root = tempfile::tempdir().unwrap();
        let mut catalogue = SourceCatalog::default();
        let mut sources = Vec::new();
        for name in ["first.iso", "last.iso"] {
            let path = root.path().join(name);
            std::fs::write(&path, name).unwrap();
            sources.push(PreparedSource::new(File::open(path).unwrap(), name).unwrap());
        }
        let infos = catalogue.insert_batch(sources).unwrap();
        let ids: Vec<_> = infos.iter().map(|info| info.source_id.clone()).collect();
        let batch = catalogue.lease_batch(&ids).unwrap();
        let job = Job::new("changed-job".into());
        let mut count = 0;
        let result = job.transfer_sources(&batch, |_, _| {
            count += 1;
            if count == 2 {
                // First source already passed its callback and local post-check.
                // The final all-source check must still catch this mutation.
                std::fs::write(root.path().join("first.iso"), b"changed-length").unwrap();
            }
            Ok(())
        });
        assert_eq!(count, 2);
        assert!(result.is_err());
        assert!(job.snapshot().unwrap().source_manifest.is_empty());
    }

    fn pending() -> Job {
        let job = Job::new("local-job".into());
        job.update(|s| {
            s.phase = "await_confirmation".into();
            s.description_digest = Some("a".repeat(64));
            s.challenge = Some("WIPE Serial-AbC".into());
        })
        .unwrap();
        job
    }
    #[test]
    fn terminal_success_stays_complete_after_finish_ack() {
        use isohopper_helper::prepare_protocol::ClientMessage;
        let job = pending();
        job.note_reply(&ClientMessage::Confirm {
            description_digest: "a".repeat(64),
            challenge: "WIPE Serial-AbC".into(),
        })
        .unwrap();
        assert!(job.snapshot().unwrap().target_may_be_incomplete);
        // A validated terminal response supplies the final physical state.
        job.update(|s| {
            s.phase = "succeeded".into();
            s.target_may_be_incomplete = false;
        })
        .unwrap();
        job.note_reply(&ClientMessage::FinishAck).unwrap();
        assert!(!job.snapshot().unwrap().target_may_be_incomplete);
    }
    #[test]
    fn confirmation_requires_exact_current_state_and_can_only_be_queued_once() {
        let job = pending();
        assert!(
            job.confirm("b".repeat(64), "WIPE Serial-AbC".into())
                .is_err()
        );
        assert!(
            job.confirm("a".repeat(64), "WIPE SERIAL-ABC".into())
                .is_err()
        );
        job.confirm("a".repeat(64), "WIPE Serial-AbC".into())
            .unwrap();
        assert!(
            job.confirm("a".repeat(64), "WIPE Serial-AbC".into())
                .is_err()
        );
        let mut state = job.state.lock().unwrap();
        assert_eq!(
            state.confirmation.take().unwrap().challenge,
            "WIPE Serial-AbC"
        );
        drop(state);
        assert!(
            job.confirm("a".repeat(64), "WIPE Serial-AbC".into())
                .is_err()
        );
    }
    #[test]
    fn cancel_supersedes_queued_confirmation_without_claiming_completion() {
        let job = pending();
        job.confirm("a".repeat(64), "WIPE Serial-AbC".into())
            .unwrap();
        job.cancel().unwrap();
        assert!(job.state.lock().unwrap().confirmation.is_none());
        assert!(job.snapshot().unwrap().active);
        assert!(job.snapshot().unwrap().cancel_requested);
        assert!(
            job.confirm("a".repeat(64), "WIPE Serial-AbC".into())
                .is_err()
        );
    }
}
