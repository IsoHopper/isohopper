// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained native input selections. Paths are accepted only from native pickers.
use crate::imports::{
    self,
    source_catalog::{PreparedSource, SourceBatch, SourceCatalog, SourceInfo, SourceLease},
};
use isohopper_core::engine::archive::{ARCHIVE_BYTES, ARCHIVE_SHA256};
use serde::Serialize;
use std::{
    fs::File,
    path::Path,
    sync::{Mutex, OnceLock},
};

static ARCHIVE: OnceLock<Mutex<SourceCatalog>> = OnceLock::new();
fn archive_catalog() -> &'static Mutex<SourceCatalog> {
    ARCHIVE.get_or_init(|| Mutex::new(SourceCatalog::default()))
}

#[derive(Clone, Debug, Serialize)]
pub struct ArchiveSelection {
    pub archive_id: String,
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
    pub version: &'static str,
}
fn selection(info: SourceInfo) -> ArchiveSelection {
    ArchiveSelection {
        archive_id: info.source_id,
        name: info.name,
        bytes: info.bytes,
        sha256: info.verification.digest,
        version: "1.1.18",
    }
}

pub fn selected_archive() -> Result<Option<ArchiveSelection>, String> {
    Ok(archive_catalog()
        .lock()
        .map_err(|_| "Engine selection is unavailable")?
        .list_sources()
        .into_iter()
        .next()
        .map(selection))
}

pub fn select_archive(path: &Path) -> Result<ArchiveSelection, String> {
    let file = File::open(path).map_err(|e| format!("Open selected engine archive: {e}"))?;
    if file.metadata().map_err(|e| e.to_string())?.len() != ARCHIVE_BYTES as u64 {
        return Err("Choose the exact Ventoy 1.1.18 Linux archive (20,320,548 bytes).".into());
    }
    let prepared = PreparedSource::new(file, "ventoy-1.1.18-linux.tar.gz")?;
    let mut candidate = SourceCatalog::default();
    let info = candidate.insert_batch(vec![prepared])?.remove(0);
    if info.bytes != ARCHIVE_BYTES as u64 || info.verification.digest != ARCHIVE_SHA256 {
        return Err(
            "Engine archive SHA-256 does not match the pinned Ventoy 1.1.18 release.".into(),
        );
    }
    let mut current = archive_catalog()
        .lock()
        .map_err(|_| "Engine selection is unavailable")?;
    let ids: Vec<_> = current
        .list_sources()
        .into_iter()
        .map(|i| i.source_id)
        .collect();
    current.release_sources(&ids)?;
    *current = candidate;
    Ok(selection(info))
}

pub struct Inputs {
    pub source_ids: Vec<String>,
    pub sources: Option<SourceBatch>,
    pub archive_id: String,
    pub archive: Option<SourceLease>,
}
impl Inputs {
    pub fn lease(source_ids: Vec<String>, archive_id: String) -> Result<Self, String> {
        let sources = imports::source_catalog()
            .lock()
            .map_err(|_| "Source catalogue is unavailable")?
            .lease_batch(&source_ids)?;
        let archive = archive_catalog()
            .lock()
            .map_err(|_| "Engine selection is unavailable")?
            .lease(&archive_id)?;
        Ok(Self {
            source_ids,
            sources: Some(sources),
            archive_id,
            archive: Some(archive),
        })
    }

    /// Call only after the helper acknowledges a sealed image and closure of
    /// every original handle. Both locks cover lease drop, validation and release.
    pub fn release_after_seal(&mut self) -> Result<(), String> {
        let mut sources = imports::source_catalog()
            .lock()
            .map_err(|_| "Source catalogue is unavailable")?;
        let mut archive = archive_catalog()
            .lock()
            .map_err(|_| "Engine selection is unavailable")?;
        drop(self.sources.take());
        drop(self.archive.take());
        let archive_ids = std::slice::from_ref(&self.archive_id);
        sources.check_release_sources(&self.source_ids)?;
        archive.check_release_sources(archive_ids)?;
        sources.release_sources(&self.source_ids)?;
        archive.release_sources(archive_ids)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wrong_archive_size_is_rejected_before_selection() {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"not an engine archive").unwrap();
        assert!(
            select_archive(file.path())
                .unwrap_err()
                .contains("exact Ventoy")
        );
    }

    #[test]
    fn release_validation_does_not_close_an_unleased_source_when_another_is_leased() {
        let directory = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let mut prepared = Vec::new();
        for name in ["one.iso", "two.iso"] {
            let path = directory.path().join(name);
            std::fs::write(&path, name).unwrap();
            prepared.push(PreparedSource::new(File::open(path).unwrap(), name).unwrap());
        }
        let ids: Vec<_> = catalog
            .insert_batch(prepared)
            .unwrap()
            .into_iter()
            .map(|i| i.source_id)
            .collect();
        let lease = catalog.lease(&ids[1]).unwrap();
        assert!(catalog.check_release_sources(&ids).is_err());
        assert_eq!(catalog.list_sources().len(), 2);
        drop(lease);
        catalog.check_release_sources(&ids).unwrap();
        assert_eq!(catalog.list_sources().len(), 2);
        catalog.release_sources(&ids).unwrap();
        assert!(catalog.list_sources().is_empty());
    }
}
