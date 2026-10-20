// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{MediaError, invalid, relative_path};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions},
};
use serde::Serialize;
use std::{
    io::{Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

#[cfg(test)]
thread_local! {
    // Deterministic race injection after entry classification, before its open.
    static BEFORE_IMAGE_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

#[derive(Debug, Clone, Serialize)]
pub struct ImageEntry {
    pub relative_path: String,
    pub size: u64,
    pub extension: String,
    pub iso_volume_label: Option<String>,
    pub inspection_status: String,
    pub boot_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub boot_inspection: Option<crate::iso::BootInspection>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub root: PathBuf,
    pub images: Vec<ImageEntry>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct ScanLimits {
    pub max_depth: usize,
    pub max_entries: usize,
}
impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_entries: 10_000,
        }
    }
}

pub fn scan(directory: impl AsRef<Path>) -> Result<ScanReport, MediaError> {
    scan_with_limits(directory, ScanLimits::default())
}

/// Open an image through retained directory handles without following symlinks.
/// Spaces and nested paths are supported. The returned read-only handle remains
/// on the opened file if a path is subsequently renamed or replaced.
/// This opens the current file; it does not attest an earlier scan's identity.
pub fn open_image(
    directory: impl AsRef<Path>,
    relative: &str,
) -> Result<std::fs::File, MediaError> {
    relative_path(relative)?;
    let components: Vec<_> = relative.split('/').collect();
    if components.len() > 33 {
        return Err(invalid("image path exceeds directory depth limit"));
    }
    let filename = components
        .last()
        .ok_or_else(|| invalid("missing image filename"))?;
    let extension = Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(
        extension.as_str(),
        "iso" | "img" | "wim" | "vhd" | "vhdx" | "efi"
    ) {
        return Err(invalid("unsupported image extension"));
    }
    let (_, mut directory) = open_root(directory.as_ref())?;
    for component in &components[..components.len() - 1] {
        directory = directory.open_dir_nofollow(component)?;
    }
    Ok(open_regular(&directory, Path::new(filename))?.into_std())
}

fn open_root(directory: &Path) -> Result<(PathBuf, Dir), MediaError> {
    let root = std::path::absolute(directory)?;
    let dir = match (root.parent(), root.file_name()) {
        (Some(parent), Some(name)) => {
            Dir::open_ambient_dir(parent, ambient_authority())?.open_dir_nofollow(name)?
        }
        _ => Dir::open_ambient_dir(&root, ambient_authority())?,
    };
    Ok((root, dir))
}

fn open_regular(directory: &Dir, filename: &Path) -> Result<cap_std::fs::File, MediaError> {
    if !directory.symlink_metadata(filename)?.is_file() {
        return Err(invalid(
            "image must be a regular file, not a symlink or special file",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
    }
    let file = directory.open_with(filename, &options)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("image changed to a non-regular file while opening"));
    }
    Ok(file)
}

/// Inspect files without following symlinks. Limits include non-image entries so
/// an irrelevant-file or directory flood cannot bypass the work bound.
pub fn scan_with_limits(
    directory: impl AsRef<Path>,
    limits: ScanLimits,
) -> Result<ScanReport, MediaError> {
    if limits.max_depth > 32 || limits.max_entries == 0 || limits.max_entries > 100_000 {
        return Err(invalid(
            "scan limits must be depth 0..32 and entries 1..100000",
        ));
    }
    let (root, dir) = open_root(directory.as_ref())?;
    let mut report = ScanReport {
        root,
        images: Vec::new(),
        warnings: Vec::new(),
    };
    walk(&dir, Path::new(""), 0, &mut 0, limits, &mut report)?;
    report
        .images
        .sort_by(|a, b| a.relative_path.cmp(&b.relative_path));
    report.warnings.sort();
    Ok(report)
}

fn walk(
    dir: &Dir,
    prefix: &Path,
    depth: usize,
    count: &mut usize,
    limits: ScanLimits,
    report: &mut ScanReport,
) -> Result<(), MediaError> {
    for entry in dir.entries()? {
        *count += 1;
        if *count > limits.max_entries {
            return Err(invalid("directory entry count exceeds scan limit"));
        }
        let entry = entry?;
        let name = entry.file_name();
        let path = prefix.join(&name);
        let Some(relative) = path.to_str() else {
            report.warnings.push("skipped a non-UTF-8 filename".into());
            continue;
        };
        // Windows separators are normalized for portable catalogue and recipe paths.
        let relative = relative.replace(std::path::MAIN_SEPARATOR, "/");
        if relative_path(&relative).is_err() {
            report
                .warnings
                .push(format!("skipped unsafe image path {relative:?}"));
            continue;
        }
        let metadata = dir.symlink_metadata(&name)?;
        if metadata.file_type().is_symlink() {
            report
                .warnings
                .push(format!("skipped symlink {relative:?}"));
            continue;
        }
        if metadata.is_dir() {
            if depth >= limits.max_depth {
                return Err(invalid("directory depth exceeds scan limit"));
            }
            let child = dir.open_dir_nofollow(&name)?;
            walk(&child, &path, depth + 1, count, limits, report)?;
            continue;
        }
        if !metadata.is_file() {
            report
                .warnings
                .push(format!("skipped non-regular file {relative:?}"));
            continue;
        }
        let Some(extension) = path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
        else {
            continue;
        };
        if !matches!(
            extension.as_str(),
            "iso" | "img" | "wim" | "vhd" | "vhdx" | "efi"
        ) {
            continue;
        }
        #[cfg(test)]
        BEFORE_IMAGE_OPEN.with(|hook| {
            if let Some(action) = hook.borrow_mut().take() {
                action();
            }
        });
        let mut file = open_regular(dir, Path::new(&name))?;
        let opened = file.metadata()?;
        let mut label = None;
        let mut status = "unknown";
        let mut boot_inspection = None;
        if extension == "iso" {
            label = iso_label(&mut file, opened.len())?;
            boot_inspection = Some(crate::iso::inspect(&mut file, opened.len())?);
            status = if label.is_some() {
                "iso9660-header"
            } else {
                "invalid-iso9660-header"
            };
        }
        let after = file.metadata()?;
        if opened.len() != after.len() || opened.modified().ok() != after.modified().ok() {
            return Err(invalid("image changed while reading its header"));
        }
        report.images.push(ImageEntry {
            relative_path: relative,
            size: opened.len(),
            extension,
            iso_volume_label: label,
            inspection_status: status.into(),
            boot_status: "not-boot-tested".into(),
            boot_inspection,
        });
    }
    Ok(())
}

// ISO 9660 descriptors occupy 2048-byte sectors beginning at sector 16.
// Inspect at most 32 descriptors (64 KiB); no offsets supplied by the image are followed.
fn iso_label(file: &mut (impl Read + Seek), length: u64) -> Result<Option<String>, MediaError> {
    const SECTOR: usize = 2048;
    let mut descriptor = [0u8; SECTOR];
    for sector in 16..48 {
        if (sector + 1) * SECTOR as u64 > length {
            return Ok(None);
        }
        file.seek(SeekFrom::Start(sector * SECTOR as u64))?;
        file.read_exact(&mut descriptor)?;
        if &descriptor[1..6] != b"CD001" || descriptor[6] != 1 {
            return Ok(None);
        }
        match descriptor[0] {
            0 | 2 | 3 => continue,
            1 => {
                let blocks = u32::from_le_bytes(descriptor[80..84].try_into().unwrap());
                let blocks_be = u32::from_be_bytes(descriptor[84..88].try_into().unwrap());
                let block_size = u16::from_le_bytes(descriptor[128..130].try_into().unwrap());
                let block_size_be = u16::from_be_bytes(descriptor[130..132].try_into().unwrap());
                if blocks != blocks_be
                    || blocks < 17
                    || u64::from(blocks) * SECTOR as u64 > length
                    || block_size != 2048
                    || block_size_be != 2048
                    || descriptor[881] != 1
                    || descriptor[156] < 34
                    || descriptor[181] & 2 == 0
                {
                    return Ok(None);
                }
                let bytes = &descriptor[40..72];
                if !bytes.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
                    return Ok(None);
                }
                let label = std::str::from_utf8(bytes)
                    .map_err(|_| invalid("invalid ISO label"))?
                    .trim_end();
                return Ok(Some(label.into()));
            }
            _ => return Ok(None),
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::{BEFORE_IMAGE_OPEN, iso_label, scan};
    use std::io::{self, Cursor, Read, Seek, SeekFrom};

    #[test]
    fn replacement_between_classification_and_open_uses_one_file_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("image.iso");
        std::fs::write(&path, [0; 512]).unwrap();
        let replacement = tempfile::tempdir().unwrap();
        let replacement_path = replacement.path().join("complete.iso");
        let mut data = vec![0; 24 * 2048];
        let pvd = &mut data[16 * 2048..17 * 2048];
        pvd[0] = 1;
        pvd[1..6].copy_from_slice(b"CD001");
        pvd[6] = 1;
        pvd[40..72].fill(b' ');
        pvd[40..48].copy_from_slice(b"COMPLETE");
        pvd[80..84].copy_from_slice(&24u32.to_le_bytes());
        pvd[84..88].copy_from_slice(&24u32.to_be_bytes());
        pvd[128..130].copy_from_slice(&2048u16.to_le_bytes());
        pvd[130..132].copy_from_slice(&2048u16.to_be_bytes());
        pvd[156] = 34;
        pvd[181] = 2;
        pvd[881] = 1;
        std::fs::write(&replacement_path, &data).unwrap();
        BEFORE_IMAGE_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::rename(replacement_path, path).unwrap();
            }));
        });
        let report = scan(root.path()).unwrap();
        assert_eq!(report.images.len(), 1);
        assert_eq!(
            report.images[0].iso_volume_label.as_deref(),
            Some("COMPLETE")
        );
        assert_eq!(report.images[0].size, data.len() as u64);
    }

    #[test]
    fn raw_image_size_also_comes_from_the_retained_handle() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("image.img");
        std::fs::write(&path, b"old").unwrap();
        BEFORE_IMAGE_OPEN.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::write(path, b"replacement").unwrap();
            }));
        });
        let report = scan(root.path()).unwrap();
        assert_eq!(report.images[0].size, 11);
        assert_eq!(report.images[0].inspection_status, "unknown");
    }

    struct Counted {
        input: Cursor<Vec<u8>>,
        read: usize,
        furthest: u64,
    }
    impl Read for Counted {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let count = self.input.read(bytes)?;
            self.read += count;
            Ok(count)
        }
    }
    impl Seek for Counted {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            let offset = self.input.seek(position)?;
            self.furthest = self.furthest.max(offset);
            Ok(offset)
        }
    }

    #[test]
    fn descriptor_flood_never_reads_past_the_fixed_budget() {
        let mut data = vec![0; 128 * 2048];
        for descriptor in data[16 * 2048..].chunks_mut(2048) {
            descriptor[1..6].copy_from_slice(b"CD001");
            descriptor[6] = 1;
        }
        let mut reader = Counted {
            input: Cursor::new(data),
            read: 0,
            furthest: 0,
        };
        assert_eq!(iso_label(&mut reader, u64::MAX).unwrap(), None);
        assert_eq!(reader.read, 32 * 2048);
        assert_eq!(reader.furthest, 47 * 2048);
    }
}
