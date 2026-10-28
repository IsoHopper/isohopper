// SPDX-License-Identifier: GPL-3.0-or-later
//! Local imports keep relative paths and hash through retained regular-file handles.
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::{Mutex, OnceLock},
};
#[path = "source_catalog.rs"]
pub mod source_catalog;
use source_catalog::{PreparedSource, SourceCatalog};
pub type ImportedImage = source_catalog::SourceInfo;

#[derive(Debug, Default, Serialize)]
pub struct ImportedDirectory {
    pub images: Vec<ImportedImage>,
    pub warnings: Vec<String>,
}

static SOURCES: OnceLock<Mutex<SourceCatalog>> = OnceLock::new();
pub fn source_catalog() -> &'static Mutex<SourceCatalog> {
    SOURCES.get_or_init(|| Mutex::new(SourceCatalog::default()))
}

pub fn release_sources(ids: &[String]) -> Result<(), String> {
    let mut catalogue = source_catalog()
        .lock()
        .map_err(|_| "Source catalogue is unavailable.")?;
    catalogue.check_release_sources(ids)?;
    crate::session::forget_images(ids)?;
    catalogue.release_sources(ids)
}

pub fn list_sources() -> Result<Vec<ImportedImage>, String> {
    Ok(source_catalog()
        .lock()
        .map_err(|_| "Source catalogue is unavailable.")?
        .list_sources())
}

fn check_capacity(catalogue: &Mutex<SourceCatalog>, count: usize) -> Result<(), String> {
    let catalogue = catalogue
        .lock()
        .map_err(|_| "Source catalogue is unavailable.")?;
    if count > catalogue.remaining_capacity() {
        return Err(format!(
            "Source catalogue cannot retain {count} more files; {} slots remain. Release unused sources or restart the application.",
            catalogue.remaining_capacity()
        ));
    }
    Ok(())
}
fn register(
    catalogue: &Mutex<SourceCatalog>,
    prepared: Vec<PreparedSource>,
) -> Result<Vec<ImportedImage>, String> {
    catalogue
        .lock()
        .map_err(|_| "Source catalogue is unavailable.")?
        .insert_batch(prepared)
}
fn prepare_file(path: &Path) -> Result<PreparedSource, String> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Image filename is not valid UTF-8")?;
    let parent = path.parent().ok_or("Image has no parent directory")?;
    let file = isohopper_media::open_image(parent, name).map_err(|e| e.to_string())?;
    PreparedSource::new(file, name)
}
#[allow(dead_code)] // Retained single-file API; the native picker uses atomic batches.
pub fn import_file(path: &Path) -> Result<ImportedImage, String> {
    import_files(&[path.to_path_buf()])?
        .pop()
        .ok_or_else(|| "Imported source was not retained.".into())
}
pub fn import_files(paths: &[PathBuf]) -> Result<Vec<ImportedImage>, String> {
    let locations = paths
        .iter()
        .map(|path| {
            Ok(crate::session::ImagePath {
                root: path
                    .parent()
                    .ok_or("Image has no parent directory")?
                    .to_path_buf(),
                relative_path: path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or("Image filename is not valid UTF-8")?
                    .into(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let images = import_files_into(source_catalog(), paths)?;
    remember_imports(&locations, &images)?;
    Ok(images)
}
fn remember_imports(
    paths: &[crate::session::ImagePath],
    images: &[ImportedImage],
) -> Result<(), String> {
    retain_saved_imports(
        source_catalog(),
        images,
        crate::session::remember_images(paths, images),
    )
}

fn retain_saved_imports(
    catalogue: &Mutex<SourceCatalog>,
    images: &[ImportedImage],
    saved: Result<(), String>,
) -> Result<(), String> {
    if let Err(error) = saved {
        let ids: Vec<_> = images.iter().map(|image| image.source_id.clone()).collect();
        catalogue
            .lock()
            .map_err(|_| "Source catalogue is unavailable.")?
            .release_sources(&ids)?;
        return Err(error);
    }
    Ok(())
}
fn import_files_into(
    catalogue: &Mutex<SourceCatalog>,
    paths: &[PathBuf],
) -> Result<Vec<ImportedImage>, String> {
    check_capacity(catalogue, paths.len())?;
    let prepared = paths
        .iter()
        .map(|path| prepare_file(path))
        .collect::<Result<Vec<_>, _>>()?;
    register(catalogue, prepared)
}
pub fn import_directory(root: &Path) -> Result<ImportedDirectory, String> {
    let scan = isohopper_media::scan(root).map_err(|e| e.to_string())?;
    check_capacity(source_catalog(), scan.images.len())?;
    let mut prepared = Vec::with_capacity(scan.images.len());
    let mut locations = Vec::with_capacity(scan.images.len());
    for image in scan.images {
        let file =
            isohopper_media::open_image(root, &image.relative_path).map_err(|e| e.to_string())?;
        prepared.push(PreparedSource::new(file, &image.relative_path)?);
        locations.push(crate::session::ImagePath {
            root: root.to_path_buf(),
            relative_path: image.relative_path,
        });
    }
    // No ID is published until the entire directory batch hashes successfully.
    let images = register(source_catalog(), prepared)?;
    remember_imports(&locations, &images)?;
    Ok(ImportedDirectory {
        images,
        warnings: scan.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    #[test]
    fn failed_persistence_rolls_back_new_imports_without_losing_existing_sources() {
        let root = tempfile::tempdir().unwrap();
        let old = root.path().join("old.iso");
        let new = root.path().join("new.iso");
        std::fs::write(&old, b"abc").unwrap();
        std::fs::write(&new, b"xyz").unwrap();
        let catalogue = Mutex::new(SourceCatalog::default());
        let existing = import_files_into(&catalogue, &[old]).unwrap();
        let added = import_files_into(&catalogue, &[new]).unwrap();
        assert!(retain_saved_imports(&catalogue, &added, Err("save failed".into())).is_err());
        let remaining = catalogue.lock().unwrap().list_sources();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].source_id, existing[0].source_id);
    }
    #[test]
    fn failed_multi_file_import_does_not_leak_unreturned_sources() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("good.iso");
        let second = root.path().join("missing.iso");
        std::fs::write(&first, b"abc").unwrap();
        let catalogue = Mutex::new(SourceCatalog::default());
        assert!(import_files_into(&catalogue, &[first, second]).is_err());
        assert_eq!(
            catalogue.lock().unwrap().remaining_capacity(),
            source_catalog::MAX_SOURCES
        );
    }
    #[test]
    fn nested_import_preserves_paths_and_hashes_actual_bytes() {
        let root = tempfile::tempdir().unwrap();
        for folder in ["Mac", "Windows", "Linux live"] {
            std::fs::create_dir(root.path().join(folder)).unwrap();
            std::fs::write(root.path().join(folder).join("boot.iso"), b"abc").unwrap();
        }
        let imported = import_directory(root.path()).unwrap();
        assert_eq!(imported.images.len(), 3);
        assert_eq!(
            imported
                .images
                .iter()
                .map(|i| i.relative_path.as_str())
                .collect::<Vec<_>>(),
            ["Linux live/boot.iso", "Mac/boot.iso", "Windows/boot.iso"]
        );
        for image in imported.images {
            assert_eq!(image.bytes, 3);
            assert_eq!(
                image.verification.digest,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            );
            assert!(!image.verification.publisher_verified);
        }
    }
    #[test]
    #[ignore = "opt-in 600 MiB native streaming test"]
    fn native_import_exceeds_browser_preview_limit() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("large.img");
        File::create(&path)
            .unwrap()
            .set_len(600 * 1024 * 1024)
            .unwrap();
        let imported = import_file(&path).unwrap();
        assert_eq!(imported.bytes, 629145600);
        assert_eq!(
            imported.verification.digest,
            "987523e7780392e283b404990c4e84e580bc75c451138b0c86c4f81c296eeebe"
        );
    }
    #[test]
    fn imported_file_uses_streamed_size() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("test.img");
        std::fs::write(&path, b"abc").unwrap();
        let imported = import_file(&path).unwrap();
        assert_eq!(imported.relative_path, "test.img");
        assert_eq!(imported.bytes, imported.verification.bytes);
    }
    #[test]
    fn imported_source_has_an_opaque_backend_id_without_an_absolute_path() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("private-source.iso");
        std::fs::write(&path, b"abc").unwrap();
        let imported = serde_json::to_value(import_file(&path).unwrap()).unwrap();
        let id = imported.get("source_id").and_then(|value| value.as_str());
        assert!(id.is_some_and(|value| value.starts_with("src_") && value.len() == 68));
        assert!(
            !imported
                .to_string()
                .contains(&root.path().display().to_string())
        );
    }
}
