// SPDX-License-Identifier: GPL-3.0-or-later
//! Saved local selections. Reopening always rechecks bytes and creates fresh IDs.
use crate::imports::{
    ImportedImage,
    source_catalog::{MAX_SOURCES, PreparedSource, SourceCatalog},
};
use isohopper_core::engine::archive::{ARCHIVE_BYTES, ARCHIVE_SHA256};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
#[path = "session/storage.rs"]
mod storage;

const STATE_FILE: &str = "session.json";
const MAX_STATE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct RestoreReport {
    pub images: Vec<ImportedImage>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ImagePath {
    pub root: PathBuf,
    pub relative_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedImage {
    root: PathBuf,
    relative_path: String,
    bytes: u64,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedArchive {
    path: PathBuf,
    bytes: u64,
    sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u8,
    images: Vec<SavedImage>,
    archive: Option<SavedArchive>,
}
impl Default for Saved {
    fn default() -> Self {
        Self {
            version: 1,
            images: Vec::new(),
            archive: None,
        }
    }
}
struct Session {
    root: PathBuf,
    saved: Saved,
    live_ids: BTreeMap<String, SavedImage>,
    warnings: Vec<String>,
}
impl Session {
    fn load(root: PathBuf) -> Result<Self, String> {
        let saved = storage::read(&root)?.unwrap_or_default();
        validate(&saved)?;
        Ok(Self {
            root,
            saved,
            live_ids: BTreeMap::new(),
            warnings: Vec::new(),
        })
    }
    fn restore_into(
        &mut self,
        catalogue: &Mutex<SourceCatalog>,
        mut archive: impl FnMut(&Path) -> Result<(), String>,
    ) -> Result<RestoreReport, String> {
        let mut restored_records = Vec::new();
        for record in &self.saved.images {
            let restored = (|| -> Result<ImportedImage, String> {
                let file = isohopper_media::open_image(&record.root, &record.relative_path)
                    .map_err(|e| e.to_string())?;
                if file.metadata().map_err(|e| e.to_string())?.len() != record.bytes {
                    return Err("Saved image size changed.".into());
                }
                let prepared = PreparedSource::new(file, &record.relative_path)?;
                let mut catalogue = catalogue
                    .lock()
                    .map_err(|_| "Source catalogue is unavailable.")?;
                let info = catalogue.insert_batch(vec![prepared])?.remove(0);
                if info.bytes != record.bytes || info.verification.digest != record.sha256 {
                    catalogue.release_sources(std::slice::from_ref(&info.source_id))?;
                    return Err("Saved image SHA-256 changed.".into());
                }
                Ok(info)
            })();
            match restored {
                Ok(info) => {
                    self.live_ids.insert(info.source_id.clone(), record.clone());
                    restored_records.push(record.clone());
                }
                Err(_) => self.warnings.push(format!(
                    "Could not restore {}: file is missing, inaccessible, or changed. Choose it again.",
                    record.relative_path.chars().take(256).collect::<String>()
                )),
            }
        }
        if restored_records.len() != self.saved.images.len() {
            let mut cleaned = self.saved.clone();
            cleaned.images = restored_records;
            if let Err(error) = self.save(cleaned) {
                let ids: Vec<_> = self.live_ids.keys().cloned().collect();
                catalogue
                    .lock()
                    .map_err(|_| "Source catalogue is unavailable.")?
                    .release_sources(&ids)?;
                self.live_ids.clear();
                return Err(error);
            }
        }
        if let Some(record) = &self.saved.archive
            && archive(&record.path).is_err()
        {
            self.warnings.push("Saved engine archive is unavailable or failed verification. Choose or download it again.".into());
        }
        Ok(RestoreReport {
            images: catalogue
                .lock()
                .map_err(|_| "Source catalogue is unavailable.")?
                .list_sources(),
            warnings: self.warnings.clone(),
        })
    }
    fn remember(&mut self, paths: &[ImagePath], images: &[ImportedImage]) -> Result<(), String> {
        if paths.len() != images.len() {
            return Err("Imported image records are incomplete.".into());
        }
        let mut next = self.saved.clone();
        let mut ids = self.live_ids.clone();
        for (path, image) in paths.iter().zip(images) {
            let record = SavedImage {
                root: std::fs::canonicalize(&path.root)
                    .map_err(|e| format!("Remember image directory: {e}"))?,
                relative_path: path.relative_path.clone(),
                bytes: image.bytes,
                sha256: image.verification.digest.clone(),
            };
            if record.relative_path != image.relative_path {
                return Err("Imported image path changed.".into());
            }
            // A duplicate may be discarded by the UI while the original row
            // remains. Keep every live alias and its own verified fingerprint.
            if !ids.values().any(|old| same_image(old, &record)) {
                next.images.retain(|old| !same_image(old, &record));
                next.images.push(record.clone());
            }
            ids.insert(image.source_id.clone(), record);
        }
        self.save(next)?;
        self.live_ids = ids;
        Ok(())
    }
    fn forget(&mut self, ids: &[String]) -> Result<(), String> {
        let mut next = self.saved.clone();
        let mut remaining = self.live_ids.clone();
        for id in ids {
            remaining.remove(id);
        }
        for id in ids {
            if let Some(removed) = self.live_ids.get(id) {
                next.images.retain(|record| !same_image(record, removed));
                if let Some(retained) = remaining
                    .values()
                    .find(|record| same_image(record, removed))
                {
                    next.images.push(retained.clone());
                }
            }
        }
        self.save(next)?;
        self.live_ids = remaining;
        Ok(())
    }
    fn release_handles(&mut self, ids: &[String]) {
        for id in ids {
            self.live_ids.remove(id);
        }
    }
    fn remember_archive(&mut self, path: &Path) -> Result<(), String> {
        let mut next = self.saved.clone();
        next.archive = Some(SavedArchive {
            path: std::fs::canonicalize(path)
                .map_err(|e| format!("Remember engine archive: {e}"))?,
            bytes: ARCHIVE_BYTES as u64,
            sha256: ARCHIVE_SHA256.into(),
        });
        self.save(next)
    }
    fn save(&mut self, saved: Saved) -> Result<(), String> {
        validate(&saved)?;
        storage::write(&self.root, &saved)?;
        self.saved = saved;
        Ok(())
    }
}

fn same_image(left: &SavedImage, right: &SavedImage) -> bool {
    left.root == right.root && left.relative_path == right.relative_path
}
fn valid_path(path: &Path) -> bool {
    path.is_absolute() && path.as_os_str().len() <= 32768
}
fn validate(saved: &Saved) -> Result<(), String> {
    if saved.version != 1 || saved.images.len() > MAX_SOURCES {
        return Err("Saved session version or image count is unsupported.".into());
    }
    for image in &saved.images {
        if !valid_path(&image.root)
            || image.relative_path.len() > 4096
            || image.relative_path.is_empty()
            || image
                .relative_path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || image.relative_path.contains(['\\', ':', '\0'])
            || image.bytes == 0
            || image.sha256.len() != 64
            || !image
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("Saved image record is invalid.".into());
        }
    }
    if let Some(archive) = &saved.archive
        && (!valid_path(&archive.path)
            || archive.bytes != ARCHIVE_BYTES as u64
            || archive.sha256 != ARCHIVE_SHA256)
    {
        return Err("Saved engine archive pin is invalid.".into());
    }
    Ok(())
}

fn session() -> &'static Mutex<Option<Session>> {
    static SESSION: OnceLock<Mutex<Option<Session>>> = OnceLock::new();
    SESSION.get_or_init(|| Mutex::new(None))
}

/// Call under the shared native-operation guard, before picker/import commands.
pub fn initialize(root: PathBuf) -> Result<RestoreReport, String> {
    initialize_into(session(), crate::imports::source_catalog(), root, |path| {
        crate::preparation::inputs::restore_archive(path).map(|_| ())
    })
}

fn initialize_into(
    state: &Mutex<Option<Session>>,
    catalogue: &Mutex<SourceCatalog>,
    root: PathBuf,
    archive: impl FnMut(&Path) -> Result<(), String>,
) -> Result<RestoreReport, String> {
    let warnings = state
        .lock()
        .map_err(|_| "Saved session is unavailable.")?
        .as_ref()
        .map(|session| session.warnings.clone());
    if let Some(warnings) = warnings {
        return Ok(RestoreReport {
            images: catalogue
                .lock()
                .map_err(|_| "Source catalogue is unavailable.")?
                .list_sources(),
            warnings,
        });
    }
    // Do not hold the session lock while restoring either catalogue. Normal
    // picker/removal hooks acquire the session lock after catalogue locks.
    let mut restored = Session::load(root)?;
    let report = restored.restore_into(catalogue, archive)?;
    *state.lock().map_err(|_| "Saved session is unavailable.")? = Some(restored);
    Ok(report)
}
pub fn remember_images(paths: &[ImagePath], images: &[ImportedImage]) -> Result<(), String> {
    if let Some(session) = session()
        .lock()
        .map_err(|_| "Saved session is unavailable.")?
        .as_mut()
    {
        session.remember(paths, images)?;
    }
    Ok(())
}
pub fn forget_images(ids: &[String]) -> Result<(), String> {
    if let Some(session) = session()
        .lock()
        .map_err(|_| "Saved session is unavailable.")?
        .as_mut()
    {
        session.forget(ids)?;
    }
    Ok(())
}
/// Sealing closes source handles but keeps the user's saved library.
pub fn release_handles(ids: &[String]) -> Result<(), String> {
    if let Some(session) = session()
        .lock()
        .map_err(|_| "Saved session is unavailable.")?
        .as_mut()
    {
        session.release_handles(ids);
    }
    Ok(())
}
pub fn remember_archive(path: &Path) -> Result<(), String> {
    if let Some(session) = session()
        .lock()
        .map_err(|_| "Saved session is unavailable.")?
        .as_mut()
    {
        session.remember_archive(path)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "session/tests.rs"]
mod tests;
