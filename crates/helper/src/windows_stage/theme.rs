// SPDX-License-Identifier: GPL-3.0-or-later
//! Fixed application-owned data files. These do not alter the pinned engine.
use super::{StageError, StageInput};
use cap_std::fs::Dir;
use isohopper_media::copy::{CopyEntry, Progress, copy_one};
use sha2::{Digest, Sha256};
use std::{
    fs::File,
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
};

struct Asset {
    temporary: &'static str,
    path: &'static str,
    bytes: &'static [u8],
}
macro_rules! asset {
    ($name:literal, $path:literal) => {
        Asset {
            temporary: concat!("theme-", $name),
            path: $path,
            bytes: include_bytes!(concat!("../../../../boot/ventoy-theme/", $name)),
        }
    };
}
const ASSETS: &[Asset] = &[
    asset!("ventoy.json", "ventoy/ventoy.json"),
    asset!("theme.txt", "ventoy/isohopper/theme.txt"),
    asset!("logo.png", "ventoy/isohopper/logo.png"),
    asset!("background.png", "ventoy/isohopper/background.png"),
    asset!("select_c.png", "ventoy/isohopper/select_c.png"),
    asset!("select_n.png", "ventoy/isohopper/select_n.png"),
    asset!("select_s.png", "ventoy/isohopper/select_s.png"),
    asset!("select_e.png", "ventoy/isohopper/select_e.png"),
    asset!("select_w.png", "ventoy/isohopper/select_w.png"),
    asset!("select_ne.png", "ventoy/isohopper/select_ne.png"),
    asset!("select_nw.png", "ventoy/isohopper/select_nw.png"),
    asset!("select_se.png", "ventoy/isohopper/select_se.png"),
    asset!("select_sw.png", "ventoy/isohopper/select_sw.png"),
];

pub(super) fn entries() -> Vec<CopyEntry> {
    ASSETS
        .iter()
        .map(|asset| CopyEntry {
            relative_path: asset.path.into(),
            bytes: asset.bytes.len() as u64,
            sha256: Sha256::digest(asset.bytes).into(),
        })
        .collect()
}

pub(super) fn sources(
    mut create: impl FnMut(&'static str) -> Result<File, StageError>,
    cancel: &AtomicBool,
) -> Result<Vec<StageInput>, StageError> {
    let mut sources = Vec::with_capacity(ASSETS.len());
    for (asset, entry) in ASSETS.iter().zip(entries()) {
        if cancel.load(Ordering::Relaxed) {
            return Err(StageError::Invalid("theme staging cancelled"));
        }
        // The caller creates an exclusive file in its retained protected job
        // directory and owns cleanup, including on a partial failure.
        let mut file = create(asset.temporary)?;
        let meta = file.metadata().map_err(|source| StageError::Io {
            operation: "theme source metadata",
            source,
        })?;
        if !meta.is_file() || meta.len() != 0 {
            return Err(StageError::Invalid(
                "theme source must be a fresh empty file",
            ));
        }
        file.write_all(asset.bytes)
            .and_then(|()| file.sync_all())
            .map_err(|source| StageError::Io {
                operation: "materialize fixed theme source",
                source,
            })?;
        sources.push(StageInput { file, entry });
    }
    Ok(sources)
}

pub(super) fn copy_to(
    root: &Dir,
    sources: &mut [StageInput],
    cancel: &AtomicBool,
    mut progress: impl FnMut(Progress),
) -> Result<(), StageError> {
    if sources.len() != ASSETS.len() {
        return Err(StageError::Invalid("fixed theme source count differs"));
    }
    for (source, expected) in sources.iter_mut().zip(entries()) {
        // Use the compiled manifest, never a path supplied by an IPC source.
        copy_one(root, &mut source.file, &expected, cancel, &mut progress).map_err(|e| {
            StageError::Io {
                operation: "copy fixed theme asset",
                source: std::io::Error::other(e),
            }
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, sync::atomic::Ordering};

    fn prepare(temp: &std::path::Path, cancel: &AtomicBool) -> Result<Vec<StageInput>, StageError> {
        sources(
            |name| {
                File::options()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .open(temp.join(name))
                    .map_err(|source| StageError::Io {
                        operation: "test source",
                        source,
                    })
            },
            cancel,
        )
    }

    #[test]
    fn copied_theme_configuration_resolves_to_verified_files() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut inputs = prepare(source.path(), &cancel).unwrap();
        let root = Dir::open_ambient_dir(destination.path(), cap_std::ambient_authority()).unwrap();
        copy_to(&root, &mut inputs, &cancel, |_| {}).unwrap();
        let config: serde_json::Value =
            serde_json::from_slice(&root.read("ventoy/ventoy.json").unwrap()).unwrap();
        let path = config["theme"]["file"]
            .as_str()
            .unwrap()
            .strip_prefix('/')
            .unwrap();
        assert!(!root.read(path).unwrap().is_empty());
        for expected in entries() {
            let bytes = root.read(&expected.relative_path).unwrap();
            assert_eq!(bytes.len() as u64, expected.bytes);
            assert_eq!(<[u8; 32]>::from(Sha256::digest(&bytes)), expected.sha256);
        }
    }

    #[test]
    fn theme_copy_never_replaces_an_existing_configuration() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        fs::create_dir(destination.path().join("ventoy")).unwrap();
        fs::write(
            destination.path().join("ventoy/ventoy.json"),
            b"keep existing",
        )
        .unwrap();
        let cancel = AtomicBool::new(false);
        let mut inputs = prepare(source.path(), &cancel).unwrap();
        let root = Dir::open_ambient_dir(destination.path(), cap_std::ambient_authority()).unwrap();
        assert!(copy_to(&root, &mut inputs, &cancel, |_| {}).is_err());
        assert_eq!(root.read("ventoy/ventoy.json").unwrap(), b"keep existing");
    }

    #[test]
    fn changed_theme_source_is_rejected_before_destination_creation() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(false);
        let mut inputs = prepare(source.path(), &cancel).unwrap();
        use std::io::{Seek, SeekFrom, Write};
        inputs[0].file.seek(SeekFrom::Start(0)).unwrap();
        inputs[0].file.write_all(b"!").unwrap();
        let root = Dir::open_ambient_dir(destination.path(), cap_std::ambient_authority()).unwrap();
        assert!(copy_to(&root, &mut inputs, &cancel, |_| {}).is_err());
        assert_eq!(root.entries().unwrap().count(), 0);
    }

    #[test]
    fn theme_staging_does_not_truncate_an_existing_source() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("existing");
        fs::write(&path, b"keep existing").unwrap();
        assert!(
            sources(
                |_| Ok(File::options().read(true).write(true).open(&path).unwrap()),
                &AtomicBool::new(false)
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), b"keep existing");
    }

    #[test]
    fn cancelled_theme_staging_creates_nothing() {
        let source = tempfile::tempdir().unwrap();
        let cancel = AtomicBool::new(true);
        assert!(prepare(source.path(), &cancel).is_err());
        assert_eq!(fs::read_dir(source.path()).unwrap().count(), 0);
        cancel.store(false, Ordering::Relaxed);
        let mut inputs = prepare(source.path(), &cancel).unwrap();
        let destination = tempfile::tempdir().unwrap();
        let root = Dir::open_ambient_dir(destination.path(), cap_std::ambient_authority()).unwrap();
        cancel.store(true, Ordering::Relaxed);
        assert!(copy_to(&root, &mut inputs, &cancel, |_| {}).is_err());
        assert_eq!(root.entries().unwrap().count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn theme_copy_does_not_follow_destination_symlinks() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), destination.path().join("ventoy")).unwrap();
        let cancel = AtomicBool::new(false);
        let mut inputs = prepare(source.path(), &cancel).unwrap();
        let root = Dir::open_ambient_dir(destination.path(), cap_std::ambient_authority()).unwrap();
        assert!(copy_to(&root, &mut inputs, &cancel, |_| {}).is_err());
        assert_eq!(fs::read_dir(outside.path()).unwrap().count(), 0);
    }
}
