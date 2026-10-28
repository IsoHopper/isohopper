// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
//! Backend-owned source handles. Source IDs are session-local references, not paths.
use isohopper_config::verify::{Verification, opened_file};
use same_file::Handle;
use serde::Serialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{File, Metadata},
    io::Seek,
    sync::{Arc, Mutex},
    time::SystemTime,
};

pub const MAX_SOURCES: usize = 128;

#[derive(Debug, Clone, Serialize)]
pub struct SourceInfo {
    pub source_id: String,
    pub name: String,
    pub relative_path: String,
    pub bytes: u64,
    pub verification: Verification,
}

#[derive(PartialEq, Eq)]
struct Snapshot {
    bytes: u64,
    modified: SystemTime,
}
impl Snapshot {
    fn read(metadata: Metadata) -> Result<Self, String> {
        if !metadata.is_file() || metadata.len() == 0 {
            return Err("Source must be a nonempty regular file.".into());
        }
        Ok(Self {
            bytes: metadata.len(),
            modified: metadata.modified().map_err(|e| e.to_string())?,
        })
    }
}

struct RetainedSource {
    // Handle owns the File as well as its stable OS identity: one retained FD.
    handle: Handle,
    snapshot: Snapshot,
    info: SourceInfo,
}
impl RetainedSource {
    fn unchanged(&self) -> Result<(), String> {
        let current = Snapshot::read(
            self.handle
                .as_file()
                .metadata()
                .map_err(|e| e.to_string())?,
        )?;
        let identity = Handle::from_file(
            self.handle
                .as_file()
                .try_clone()
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if current != self.snapshot || identity != self.handle {
            return Err(
                "Source identity, length or modification time changed; import it again.".into(),
            );
        }
        Ok(())
    }

    fn verify(&mut self) -> Result<(), String> {
        self.unchanged()?;
        let verified = opened_file(
            self.handle.as_file_mut(),
            "sha256",
            Some(&self.info.verification.digest),
        )
        .map_err(|e| format!("Source verification failed: {e}"))?;
        if verified.bytes != self.info.bytes {
            return Err("Source length changed; import it again.".into());
        }
        self.unchanged()?;
        self.handle
            .as_file_mut()
            .rewind()
            .map_err(|e| e.to_string())
    }
}

/// Hashing happens before insertion, outside the catalogue mutex. Dropping a
/// failed batch closes its prepared handles and exposes no source IDs.
pub struct PreparedSource(RetainedSource);
impl PreparedSource {
    pub fn new(file: File, relative: &str) -> Result<Self, String> {
        validate_relative_path(relative)?;
        let file = retain_read_only(file)?;
        let snapshot = Snapshot::read(file.metadata().map_err(|e| e.to_string())?)?;
        let mut handle = Handle::from_file(file).map_err(|e| e.to_string())?;
        let verification =
            opened_file(handle.as_file_mut(), "sha256", None).map_err(|e| e.to_string())?;
        let source = RetainedSource {
            handle,
            snapshot,
            info: SourceInfo {
                source_id: String::new(),
                name: relative.rsplit('/').next().unwrap_or(relative).into(),
                relative_path: relative.into(),
                bytes: verification.bytes,
                verification,
            },
        };
        source.unchanged()?;
        if source.info.bytes != source.snapshot.bytes {
            return Err("Source changed while hashing.".into());
        }
        Ok(Self(source))
    }
}

struct CatalogEntry {
    // Immutable import metadata can be listed without waiting for a long copy
    // operation to release the per-source file/cursor mutex.
    info: SourceInfo,
    source: Arc<Mutex<RetainedSource>>,
}
pub struct SourceCatalog {
    sources: BTreeMap<String, CatalogEntry>,
    limit: usize,
}
impl Default for SourceCatalog {
    fn default() -> Self {
        Self {
            sources: BTreeMap::new(),
            limit: MAX_SOURCES,
        }
    }
}
impl SourceCatalog {
    pub fn list_sources(&self) -> Vec<SourceInfo> {
        self.sources
            .values()
            .map(|entry| entry.info.clone())
            .collect()
    }

    pub fn remaining_capacity(&self) -> usize {
        self.limit.saturating_sub(self.sources.len())
    }

    pub fn insert_batch(
        &mut self,
        mut prepared: Vec<PreparedSource>,
    ) -> Result<Vec<SourceInfo>, String> {
        if prepared.len() > self.remaining_capacity() {
            return Err(format!(
                "Source catalogue is full (limit {}). Release unused sources or restart the application.",
                self.limit
            ));
        }
        // Resolve all random IDs before mutating the catalogue, including the
        // unlikely collision/error path, so insertion remains all-or-nothing.
        let mut ids = BTreeSet::new();
        for source in &mut prepared {
            let mut selected = None;
            for _ in 0..8 {
                let mut bytes = [0_u8; 32];
                getrandom::fill(&mut bytes)
                    .map_err(|e| format!("Source ID generation failed: {e}"))?;
                let id = format!(
                    "src_{}",
                    bytes
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect::<String>()
                );
                if !self.sources.contains_key(&id) && ids.insert(id.clone()) {
                    selected = Some(id);
                    break;
                }
            }
            source.0.info.source_id = selected.ok_or("Could not allocate a unique source ID.")?;
        }
        let mut infos = Vec::with_capacity(prepared.len());
        for source in prepared {
            infos.push(source.0.info.clone());
            self.sources.insert(
                source.0.info.source_id.clone(),
                CatalogEntry {
                    info: source.0.info.clone(),
                    source: Arc::new(Mutex::new(source.0)),
                },
            );
        }
        Ok(infos)
    }

    /// Clone a lease while briefly holding the catalogue mutex, then release
    /// that mutex before validating/copying. Only this source's cursor is locked.
    #[allow(dead_code)] // Consumed by the forthcoming native preparation job.
    pub fn lease(&self, source_id: &str) -> Result<SourceLease, String> {
        self.sources
            .get(source_id)
            .map(|entry| SourceLease(Arc::clone(&entry.source)))
            .ok_or_else(|| "Unknown or released source ID; import it again.".into())
    }

    /// Atomically retain an ordered selection while holding the catalogue lock.
    /// This only validates IDs and clones references; it performs no source I/O
    /// or cursor locking. Drop the catalogue guard before `verify_all`.
    #[allow(dead_code)] // Consumed by the forthcoming native preparation job.
    pub fn lease_batch(&self, ids: &[String]) -> Result<SourceBatch, String> {
        if ids.is_empty() || ids.len() > MAX_SOURCES {
            return Err(format!("Select between 1 and {MAX_SOURCES} source IDs."));
        }
        let mut seen = BTreeSet::new();
        let mut entries = Vec::with_capacity(ids.len());
        for id in ids {
            if !seen.insert(id) {
                return Err("Duplicate source ID in batch.".into());
            }
            entries.push(
                self.sources
                    .get(id)
                    .ok_or("Unknown or released source ID; import it again.")?,
            );
        }
        Ok(SourceBatch {
            leases: entries
                .into_iter()
                .map(|entry| SourceLease(Arc::clone(&entry.source)))
                .collect(),
        })
    }

    /// Explicit release only. A source used by any job cannot be evicted.
    #[allow(dead_code)] // Single-source convenience API; Studio releases batches.
    pub fn release(&mut self, source_id: &str) -> Result<(), String> {
        let source = self
            .sources
            .get(source_id)
            .ok_or("Unknown or released source ID.")?;
        if Arc::strong_count(&source.source) != 1 {
            return Err("Source is leased by a job and cannot be released yet.".into());
        }
        self.sources.remove(source_id);
        Ok(())
    }

    pub fn release_sources(&mut self, ids: &[String]) -> Result<(), String> {
        if ids.len() > MAX_SOURCES {
            return Err("Too many source IDs in release request.".into());
        }
        // Validate the complete request before closing any handle. The caller
        // holds the catalogue mutex, so no new lease can race this check.
        for id in ids {
            let source = self
                .sources
                .get(id)
                .ok_or("Unknown or released source ID.")?;
            if Arc::strong_count(&source.source) != 1 {
                return Err("Source is leased by a job and cannot be released yet.".into());
            }
        }
        for id in ids {
            self.sources.remove(id);
        }
        Ok(())
    }
}

/// Ordered backend-owned sources. Every source remains leased until this batch
/// is dropped, including after verification fails. No catalogue lock is held.
pub struct SourceBatch {
    leases: Vec<SourceLease>,
}
impl SourceBatch {
    /// Rehash every retained handle against its import digest and return only a
    /// complete report in requested order. Paths, sizes and digests come from
    /// the backend; no pathname is reopened and no publisher trust is asserted.
    ///
    /// Verification is sequential, not an atomic filesystem snapshot. A final
    /// identity/size/mtime pass detects ordinary changes during later hashes,
    /// but external writes and transient mutations cannot be frozen by these
    /// checks. The eventual copy must verify the bytes it consumes and readback.
    #[allow(dead_code)] // Consumed by the forthcoming native preparation job.
    pub fn verify_all(&self) -> Result<Vec<SourceInfo>, String> {
        let infos = self
            .leases
            .iter()
            .map(|lease| lease.with_verified_source(|_, info| Ok(info.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        for lease in &self.leases {
            lease
                .0
                .lock()
                .map_err(|_| "Source lock is unavailable.")?
                .unchanged()?;
        }
        Ok(infos)
    }
}

pub struct SourceLease(Arc<Mutex<RetainedSource>>);
impl SourceLease {
    /// Rehash the retained object, then supply its read-only File at offset zero.
    /// Metadata is checked again after use, even when the callback fails.
    /// The copy consumer must still hash the bytes it reads and verify its output;
    /// mutation checks cannot undo a partial write or prove a transient mutation
    /// did not occur during a callback. This method never reopens a pathname.
    #[allow(dead_code)] // Prepared for media::copy; not exposed as a Tauri command.
    pub fn with_verified_source<T>(
        &self,
        use_source: impl FnOnce(&mut File, &SourceInfo) -> Result<T, String>,
    ) -> Result<T, String> {
        let mut source = self.0.lock().map_err(|_| "Source lock is unavailable.")?;
        source.verify()?;
        let info = source.info.clone();
        let result = use_source(source.handle.as_file_mut(), &info);
        let stability = source.unchanged();
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                stability?;
                Ok(value)
            }
        }
    }
}

fn validate_relative_path(relative: &str) -> Result<(), String> {
    if relative.is_empty()
        || relative.len() > 4096
        || relative.contains(['\\', ':'])
        || relative.chars().any(char::is_control)
        || relative.split('/').count() > 33
        || relative
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(
            "Source path must be a bounded relative path without traversal or control characters."
                .into(),
        );
    }
    Ok(())
}

#[cfg(not(windows))]
fn retain_read_only(file: File) -> Result<File, String> {
    Ok(file)
}

#[cfg(windows)]
fn retain_read_only(file: File) -> Result<File, String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ, ReOpenFile,
        },
    };
    // ReOpenFile binds the already opened object, not the current pathname.
    // Permit rename/delete but deny write sharing. Fail closed on an existing
    // conflicting writer; never fall back to a write-shared handle.
    // SAFETY: file owns a live handle; flags request a synchronous read-only
    // handle and no pointer arguments or output buffers are involved.
    let raw = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_FLAG_SEQUENTIAL_SCAN,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(format!(
            "Cannot retain source without write sharing: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: a successful ReOpenFile returns one owned, valid file handle.
    let retained = unsafe { File::from_raw_handle(raw) };
    let original_identity = Handle::from_file(file).map_err(|e| e.to_string())?;
    let retained_identity = Handle::from_file(retained.try_clone().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    if original_identity != retained_identity {
        return Err("Source identity changed while retaining its handle.".into());
    }
    Ok(retained)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn prepared(root: &std::path::Path, relative: &str, contents: &[u8]) -> PreparedSource {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, contents).unwrap();
        PreparedSource::new(
            isohopper_media::open_image(root, relative).unwrap(),
            relative,
        )
        .unwrap()
    }

    #[test]
    fn nested_sources_keep_separate_opaque_ids_and_read_only_handles() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let infos = catalog
            .insert_batch(vec![
                prepared(root.path(), "Mac/boot.iso", b"abc"),
                prepared(root.path(), "Windows/Install Media/boot.iso", b"xyz"),
                prepared(root.path(), "Linux/日本語.iso", b"linux"),
            ])
            .unwrap();
        assert_eq!(infos[0].relative_path, "Mac/boot.iso");
        assert_eq!(infos[1].relative_path, "Windows/Install Media/boot.iso");
        assert_eq!(infos[2].relative_path, "Linux/日本語.iso");
        assert_ne!(infos[0].source_id, infos[1].source_id);
        assert_eq!(infos[0].bytes, 3);
        assert_eq!(
            infos[0].verification.digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let lease = catalog.lease(&infos[0].source_id).unwrap();
        lease
            .with_verified_source(|file, info| {
                assert_eq!(info.source_id, infos[0].source_id);
                assert!(file.write_all(b"no").is_err());
                let mut contents = Vec::new();
                file.read_to_end(&mut contents).unwrap();
                assert_eq!(contents, b"abc");
                Ok(())
            })
            .unwrap();
        assert_eq!(
            std::fs::read(root.path().join("Mac/boot.iso")).unwrap(),
            b"abc"
        );
    }

    #[test]
    fn batch_lease_rejects_invalid_requests_without_partial_retention() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let infos = catalog
            .insert_batch(vec![
                prepared(root.path(), "first.iso", b"abc"),
                prepared(root.path(), "second.iso", b"xyz"),
            ])
            .unwrap();
        let first = infos[0].source_id.clone();
        let second = infos[1].source_id.clone();
        for ids in [
            vec![],
            vec![first.clone(), second.clone(), "unknown-last".into()],
            vec![first.clone(), second.clone(), first.clone()],
            vec![first.clone(); MAX_SOURCES + 1],
        ] {
            assert!(catalog.lease_batch(&ids).is_err());
            for entry in catalog.sources.values() {
                assert_eq!(Arc::strong_count(&entry.source), 1);
            }
        }
        catalog.release_sources(&[first, second]).unwrap();
        assert_eq!(catalog.remaining_capacity(), MAX_SOURCES);
    }

    #[test]
    fn batch_verifies_backend_metadata_in_requested_nested_path_order() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let infos = catalog
            .insert_batch(vec![
                prepared(root.path(), "Mac/boot.iso", b"abc"),
                prepared(root.path(), "Windows/Install Media/boot.iso", b"xyz"),
                prepared(root.path(), "Linux/日本語.iso", b"linux"),
            ])
            .unwrap();
        let order = [2, 0, 1];
        let ids = order.map(|i| infos[i].source_id.clone());
        let batch = catalog.lease_batch(&ids).unwrap();
        let verified = batch.verify_all().unwrap();
        assert_eq!(verified.len(), order.len());
        for (source, index) in verified.iter().zip(order) {
            assert_eq!(source.source_id, infos[index].source_id);
            assert_eq!(source.relative_path, infos[index].relative_path);
            assert_eq!(source.name, infos[index].name);
            assert_eq!(source.bytes, infos[index].bytes);
            assert_eq!(source.verification, infos[index].verification);
            assert!(!source.verification.publisher_verified);
        }
        assert_eq!(
            verified[1].verification.digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        // Returned metadata is a copy; callers cannot change the next report.
        let mut changed = verified;
        changed[0].relative_path = "injected.iso".into();
        changed[0].verification.digest = "0".repeat(64);
        let repeated = batch.verify_all().unwrap();
        assert_eq!(repeated[0].relative_path, "Linux/日本語.iso");
        assert_eq!(repeated[0].verification, infos[2].verification);
    }

    #[test]
    fn batch_holds_every_source_until_drop_without_holding_catalogue() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let infos = catalog
            .insert_batch(vec![
                prepared(root.path(), "first.iso", b"abc"),
                prepared(root.path(), "second.iso", b"xyz"),
                prepared(root.path(), "unrelated.iso", b"other"),
            ])
            .unwrap();
        let ids = [infos[1].source_id.clone(), infos[0].source_id.clone()];
        let shared = Mutex::new(catalog);
        let batch = shared.lock().unwrap().lease_batch(&ids).unwrap();
        {
            let mut catalog = shared.try_lock().unwrap();
            assert!(catalog.release_sources(&ids).is_err());
            assert!(catalog.release(&ids[0]).is_err());
            assert!(catalog.release(&ids[1]).is_err());
            catalog.release(&infos[2].source_id).unwrap();
            assert_eq!(catalog.list_sources().len(), 2);
        }
        assert_eq!(batch.verify_all().unwrap().len(), 2);
        drop(batch);
        shared.lock().unwrap().release_sources(&ids).unwrap();
        assert!(shared.lock().unwrap().list_sources().is_empty());
    }

    #[test]
    fn batch_acquisition_does_not_wait_for_a_source_cursor_or_hash() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let info = catalog
            .insert_batch(vec![prepared(root.path(), "boot.iso", b"abc")])
            .unwrap()
            .remove(0);
        let source = catalog.lease(&info.source_id).unwrap();
        let cursor = source.0.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let shared = Mutex::new(catalog);
            let batch = shared.lock().unwrap().lease_batch(&[info.source_id]);
            sender.send(batch).unwrap();
        });
        // An accidental hash/cursor lock during acquisition cannot complete
        // while the test owns the source mutex. Release it even on failure.
        let result = receiver.recv_timeout(std::time::Duration::from_secs(5));
        drop(cursor);
        worker.join().unwrap();
        let batch = result
            .expect("batch acquisition waited for source I/O")
            .unwrap();
        // The lease stays usable even after the worker drops the catalogue.
        assert_eq!(batch.verify_all().unwrap()[0].bytes, 3);
    }

    #[test]
    fn batch_verification_never_reopens_a_replaced_path() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let info = catalog
            .insert_batch(vec![prepared(root.path(), "boot.iso", b"abc")])
            .unwrap()
            .remove(0);
        let batch = catalog.lease_batch(&[info.source_id]).unwrap();
        std::fs::rename(root.path().join("boot.iso"), root.path().join("old.iso")).unwrap();
        std::fs::write(root.path().join("boot.iso"), b"replacement").unwrap();
        let verified = batch.verify_all().unwrap();
        assert_eq!(verified[0].relative_path, "boot.iso");
        assert_eq!(verified[0].bytes, 3);
        assert_eq!(verified[0].verification, info.verification);
    }

    #[cfg(unix)]
    #[test]
    fn batch_verification_aborts_on_a_late_source_checksum_change() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let infos = catalog
            .insert_batch(vec![
                prepared(root.path(), "first.iso", b"abc"),
                prepared(root.path(), "last.iso", b"xyz"),
            ])
            .unwrap();
        let ids = infos
            .iter()
            .map(|info| info.source_id.clone())
            .collect::<Vec<_>>();
        let batch = catalog.lease_batch(&ids).unwrap();
        let path = root.path().join("last.iso");
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let mut writer = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        writer.write_all(b"bad").unwrap();
        writer
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let error = batch.verify_all().unwrap_err();
        assert!(error.contains("checksum mismatch"));
        assert!(catalog.release_sources(&ids).is_err());
        drop(batch);
        catalog.release_sources(&ids).unwrap();
    }

    #[test]
    fn pathname_replacement_keeps_the_original_opened_source() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let info = catalog
            .insert_batch(vec![prepared(root.path(), "boot.iso", b"abc")])
            .unwrap()
            .remove(0);
        std::fs::rename(
            root.path().join("boot.iso"),
            root.path().join("original.iso"),
        )
        .unwrap();
        std::fs::write(root.path().join("boot.iso"), b"replacement").unwrap();
        catalog
            .lease(&info.source_id)
            .unwrap()
            .with_verified_source(|file, info| {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents).unwrap();
                assert_eq!(contents, b"abc");
                assert_eq!(info.relative_path, "boot.iso");
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn replacing_the_borrowed_file_handle_is_detected_after_use() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let info = catalog
            .insert_batch(vec![prepared(root.path(), "boot.iso", b"abc")])
            .unwrap()
            .remove(0);
        let alternate = root.path().join("other.iso");
        std::fs::write(&alternate, b"abc").unwrap();
        let original_modified = std::fs::metadata(root.path().join("boot.iso"))
            .unwrap()
            .modified()
            .unwrap();
        std::fs::OpenOptions::new()
            .write(true)
            .open(&alternate)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(original_modified))
            .unwrap();
        let lease = catalog.lease(&info.source_id).unwrap();
        let error = lease
            .with_verified_source(|file, _| {
                *file = File::open(&alternate).unwrap();
                Ok(())
            })
            .unwrap_err();
        assert!(error.contains("identity"));
        assert!(lease.with_verified_source(|_, _| Ok(())).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn same_size_mutation_with_restored_mtime_is_rejected_before_use() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let info = catalog
            .insert_batch(vec![prepared(root.path(), "boot.iso", b"abc")])
            .unwrap()
            .remove(0);
        let path = root.path().join("boot.iso");
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let mut writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all(b"xyz").unwrap();
        writer
            .set_times(std::fs::FileTimes::new().set_modified(modified))
            .unwrap();
        let mut called = false;
        let error = catalog
            .lease(&info.source_id)
            .unwrap()
            .with_verified_source(|_, _| {
                called = true;
                Ok(())
            })
            .unwrap_err();
        assert!(!called);
        assert!(error.contains("checksum mismatch"));
    }

    #[cfg(unix)]
    #[test]
    fn length_change_and_mutation_during_use_fail() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let info = catalog
            .insert_batch(vec![prepared(root.path(), "boot.iso", b"abc")])
            .unwrap()
            .remove(0);
        let path = root.path().join("boot.iso");
        let lease = catalog.lease(&info.source_id).unwrap();
        assert!(
            lease
                .with_verified_source(|_, _| {
                    std::fs::write(&path, b"longer").unwrap();
                    Ok(())
                })
                .is_err()
        );
        let mut called = false;
        assert!(
            lease
                .with_verified_source(|_, _| {
                    called = true;
                    Ok(())
                })
                .is_err()
        );
        assert!(!called);
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_source_denies_new_writers() {
        let root = tempfile::tempdir().unwrap();
        let source = prepared(root.path(), "boot.iso", b"abc");
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(root.path().join("boot.iso"))
                .is_err()
        );
        drop(source);
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .open(root.path().join("boot.iso"))
                .is_ok()
        );
    }

    #[cfg(windows)]
    #[test]
    fn retained_windows_source_refuses_an_existing_writer_without_fallback() {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };

        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("boot.iso");
        std::fs::write(&path, b"abc").unwrap();
        // Allow subsequent opens on this writer so the rejection specifically
        // comes from the retained source's refusal to share existing write access.
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap();
        let opened = isohopper_media::open_image(root.path(), "boot.iso").unwrap();
        let error = match PreparedSource::new(opened, "boot.iso") {
            Ok(_) => panic!("retained a source while a conflicting writer was open"),
            Err(error) => error,
        };
        assert!(error.contains("Cannot retain source without write sharing"));
        drop(writer);

        let source = PreparedSource::new(
            isohopper_media::open_image(root.path(), "boot.iso").unwrap(),
            "boot.iso",
        )
        .unwrap();
        assert_eq!(source.0.info.bytes, 3);
        assert_eq!(
            source.0.info.verification.digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn capacity_failure_is_atomic_and_never_evicts_an_existing_source() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog {
            sources: BTreeMap::new(),
            limit: 2,
        };
        let original = catalog
            .insert_batch(vec![prepared(root.path(), "first.iso", b"first")])
            .unwrap()
            .remove(0);
        assert!(
            catalog
                .insert_batch(vec![
                    prepared(root.path(), "second.iso", b"second"),
                    prepared(root.path(), "third.iso", b"third")
                ])
                .is_err()
        );
        assert_eq!(catalog.remaining_capacity(), 1);
        assert!(catalog.lease(&original.source_id).is_ok());
        assert_eq!(catalog.sources.len(), 1);
    }

    #[test]
    fn release_rejects_active_leases_and_unknown_ids_never_become_paths() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let info = catalog
            .insert_batch(vec![prepared(root.path(), "boot.iso", b"abc")])
            .unwrap()
            .remove(0);
        for id in [
            "boot.iso",
            "../boot.iso",
            &root.path().join("boot.iso").display().to_string(),
        ] {
            assert!(catalog.lease(id).is_err());
        }
        let lease = catalog.lease(&info.source_id).unwrap();
        assert!(catalog.release(&info.source_id).is_err());
        drop(lease);
        catalog.release(&info.source_id).unwrap();
        assert!(catalog.lease(&info.source_id).is_err());
        assert_eq!(catalog.remaining_capacity(), MAX_SOURCES);
    }

    #[test]
    fn batch_release_is_atomic_for_unknown_and_leased_ids() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let infos = catalog
            .insert_batch(vec![
                prepared(root.path(), "first.iso", b"abc"),
                prepared(root.path(), "second.iso", b"xyz"),
            ])
            .unwrap();
        let first = infos[0].source_id.clone();
        let second = infos[1].source_id.clone();
        assert!(
            catalog
                .release_sources(&[first.clone(), "../not-a-source".into()])
                .is_err()
        );
        assert!(catalog.lease(&first).is_ok());
        let lease = catalog.lease(&second).unwrap();
        assert!(
            catalog
                .release_sources(&[first.clone(), second.clone()])
                .is_err()
        );
        assert!(catalog.lease(&first).is_ok());
        drop(lease);
        catalog
            .release_sources(&[first.clone(), second.clone()])
            .unwrap();
        assert!(catalog.lease(&first).is_err());
        assert!(catalog.lease(&second).is_err());
        assert_eq!(catalog.remaining_capacity(), MAX_SOURCES);
        catalog.release_sources(&[]).unwrap();
    }

    #[test]
    fn repeated_import_release_reuses_capacity_and_rejects_oversized_batches() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        for _ in 0..MAX_SOURCES + 1 {
            let image = catalog
                .insert_batch(vec![prepared(root.path(), "boot.iso", b"abc")])
                .unwrap()
                .remove(0);
            let oversized = vec![image.source_id.clone(); MAX_SOURCES + 1];
            assert!(catalog.release_sources(&oversized).is_err());
            assert!(catalog.lease(&image.source_id).is_ok());
            catalog
                .release_sources(&[image.source_id.clone(), image.source_id])
                .unwrap();
            assert_eq!(catalog.remaining_capacity(), MAX_SOURCES);
        }
    }

    #[test]
    fn every_use_rewinds_and_a_failed_consumer_does_not_poison_the_source() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        let info = catalog
            .insert_batch(vec![prepared(root.path(), "boot.iso", b"abc")])
            .unwrap()
            .remove(0);
        let lease = catalog.lease(&info.source_id).unwrap();
        let failure: Result<(), _> = lease.with_verified_source(|file, _| {
            let mut first = [0];
            file.read_exact(&mut first).unwrap();
            assert_eq!(first, *b"a");
            Err("Destination failed".into())
        });
        assert_eq!(failure.unwrap_err(), "Destination failed");
        lease
            .with_verified_source(|file, _| {
                let mut contents = Vec::new();
                file.read_to_end(&mut contents).unwrap();
                assert_eq!(contents, b"abc");
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn invalid_relative_paths_and_empty_sources_never_register() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("file.iso");
        std::fs::write(&path, b"abc").unwrap();
        for relative in [
            "",
            "../file.iso",
            "/tmp/file.iso",
            "C:/file.iso",
            "folder\\file.iso",
            "a//file.iso",
            "a/./file.iso",
            "a/../file.iso",
            "a/\0file.iso",
        ] {
            assert!(PreparedSource::new(File::open(&path).unwrap(), relative).is_err());
        }
        assert!(PreparedSource::new(File::open(&path).unwrap(), &"a".repeat(4097)).is_err());
        std::fs::write(&path, b"").unwrap();
        assert!(PreparedSource::new(File::open(&path).unwrap(), "file.iso").is_err());
    }
    #[test]
    fn source_listing_is_read_only_and_remains_available_while_a_source_is_locked() {
        let root = tempfile::tempdir().unwrap();
        let mut catalog = SourceCatalog::default();
        assert!(catalog.list_sources().is_empty());
        let info = catalog
            .insert_batch(vec![prepared(root.path(), "boot.iso", b"abc")])
            .unwrap()
            .remove(0);
        let lease = catalog.lease(&info.source_id).unwrap();
        let _source_lock = lease.0.lock().unwrap();
        let listing = catalog.list_sources();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].source_id, info.source_id);
        assert_eq!(listing[0].relative_path, "boot.iso");
        assert_eq!(listing[0].verification.digest, info.verification.digest);
        assert_eq!(catalog.remaining_capacity(), MAX_SOURCES - 1);
    }
}
