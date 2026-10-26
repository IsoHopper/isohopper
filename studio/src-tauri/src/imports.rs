// SPDX-License-Identifier: GPL-3.0-or-later
//! Local imports keep relative paths and hash through retained regular-file handles.
use serde::Serialize;
use std::{fs::File, path::Path};

#[derive(Debug, Serialize)]
pub struct ImportedImage {
    pub name: String,
    pub relative_path: String,
    pub bytes: u64,
    pub verification: isohopper_config::verify::Verification,
}
#[derive(Debug, Default, Serialize)]
pub struct ImportedDirectory {
    pub images: Vec<ImportedImage>,
    pub warnings: Vec<String>,
}

fn hash_opened(mut file: File, relative: &str) -> Result<ImportedImage, String> {
    let before = file.metadata().map_err(|e| e.to_string())?;
    let verification = isohopper_config::verify::opened_file(&mut file, "sha256", None)
        .map_err(|e| e.to_string())?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if before.len() != verification.bytes
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err(format!("File changed while hashing: {relative}"));
    }
    Ok(ImportedImage {
        name: relative.rsplit('/').next().unwrap_or(relative).into(),
        relative_path: relative.into(),
        bytes: verification.bytes,
        verification,
    })
}
pub fn import_file(path: &Path) -> Result<ImportedImage, String> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("Image filename is not valid UTF-8")?;
    let parent = path.parent().ok_or("Image has no parent directory")?;
    let file = isohopper_media::open_image(parent, name).map_err(|e| e.to_string())?;
    hash_opened(file, name)
}
pub fn import_directory(root: &Path) -> Result<ImportedDirectory, String> {
    let scan = isohopper_media::scan(root).map_err(|e| e.to_string())?;
    let mut result = ImportedDirectory {
        images: Vec::new(),
        warnings: scan.warnings,
    };
    for image in scan.images {
        let file =
            isohopper_media::open_image(root, &image.relative_path).map_err(|e| e.to_string())?;
        result.images.push(hash_opened(file, &image.relative_path)?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
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
}
