// SPDX-License-Identifier: GPL-3.0-or-later
#![cfg(windows)]

use cap_std::{ambient_authority, fs::Dir};
use isohopper_media::copy::{CopyEntry, copy_one};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
    path::Path,
    sync::atomic::AtomicBool,
};
use windows_sys::Win32::{
    Foundation::GENERIC_WRITE,
    Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
    System::{
        IO::DeviceIoControl, Ioctl::FSCTL_SET_REPARSE_POINT,
        SystemServices::IO_REPARSE_TAG_MOUNT_POINT,
    },
};

const CONTENT: &[u8] = b"owned copy fixture";

fn entry(name: &str) -> CopyEntry {
    CopyEntry {
        relative_path: name.into(),
        bytes: CONTENT.len() as u64,
        sha256: Sha256::digest(CONTENT).into(),
    }
}

#[test]
fn windows_copy_reuses_existing_parent_and_creates_nested_unicode_directories() {
    let mut source = tempfile::tempfile().unwrap();
    std::io::Write::write_all(&mut source, CONTENT).unwrap();
    let output = tempfile::tempdir().unwrap();
    fs::create_dir(output.path().join("Existing")).unwrap();
    fs::write(output.path().join("Existing/keep"), b"unchanged").unwrap();
    let root = Dir::open_ambient_dir(output.path(), ambient_authority()).unwrap();
    for name in ["Existing/日本語/one.iso", "Existing/日本語/two.img"] {
        let report = copy_one(
            &root,
            &mut source,
            &entry(name),
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        assert_eq!(report.sha256, entry(name).sha256);
        assert_eq!(fs::read(output.path().join(name)).unwrap(), CONTENT);
    }
    assert_eq!(
        fs::read(output.path().join("Existing/keep")).unwrap(),
        b"unchanged"
    );
}

#[test]
fn windows_copy_refuses_a_regular_file_as_parent_without_changing_it() {
    let output = tempfile::tempdir().unwrap();
    fs::write(output.path().join("source"), CONTENT).unwrap();
    fs::write(output.path().join("blocked"), b"valuable").unwrap();
    let root = Dir::open_ambient_dir(output.path(), ambient_authority()).unwrap();
    let failure = copy_one(
        &root,
        &mut File::open(output.path().join("source")).unwrap(),
        &entry("blocked/image.iso"),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap_err();
    assert!(!failure.destination_incomplete);
    assert_eq!(failure.bytes_written, 0);
    assert_eq!(
        fs::read(output.path().join("blocked")).unwrap(),
        b"valuable"
    );
}

// Create an NTFS junction entirely within two owned temporary directories.
// Unlike a symbolic link this fixture does not need a symlink privilege.
fn junction(path: &Path, target: &Path) {
    fs::create_dir(path).unwrap();
    let target = fs::canonicalize(target).unwrap();
    let spelling: Vec<u16> = target.as_os_str().encode_wide().collect();
    assert!(spelling.starts_with(&[92, 92, 63, 92])); // canonical \\?\ prefix
    let mut substitute = vec![92, 63, 63, 92]; // mount point's \??\ prefix
    substitute.extend_from_slice(&spelling[4..]);
    let print = &spelling[4..];
    let substitute_bytes = u16::try_from(substitute.len() * 2).unwrap();
    let print_bytes = u16::try_from(print.len() * 2).unwrap();
    let data_len = 8 + substitute_bytes + 2 + print_bytes + 2;
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&IO_REPARSE_TAG_MOUNT_POINT.to_le_bytes());
    for word in [
        data_len,
        0,
        0,
        substitute_bytes,
        substitute_bytes + 2,
        print_bytes,
    ] {
        buffer.extend_from_slice(&word.to_le_bytes());
    }
    for word in substitute
        .into_iter()
        .chain([0])
        .chain(print.iter().copied())
        .chain([0])
    {
        buffer.extend_from_slice(&word.to_le_bytes());
    }
    let handle = OpenOptions::new()
        .access_mode(GENERIC_WRITE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .unwrap();
    let mut returned = 0;
    // SAFETY: retained synchronous directory handle, bounded complete mount-point
    // buffer, live output count. Only this new owned fixture is changed.
    assert_ne!(
        unsafe {
            DeviceIoControl(
                handle.as_raw_handle(),
                FSCTL_SET_REPARSE_POINT,
                buffer.as_ptr().cast(),
                buffer.len().try_into().unwrap(),
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        },
        0,
        "{}",
        std::io::Error::last_os_error()
    );
}

#[test]
fn windows_copy_rejects_junction_parent_without_writing_outside_root() {
    let output = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    fs::write(output.path().join("source"), CONTENT).unwrap();
    fs::write(elsewhere.path().join("keep"), b"outside").unwrap();
    junction(&output.path().join("redirect"), elsewhere.path());
    assert_eq!(
        fs::read(output.path().join("redirect/keep")).unwrap(),
        b"outside"
    );
    let root = Dir::open_ambient_dir(output.path(), ambient_authority()).unwrap();
    let failure = copy_one(
        &root,
        &mut File::open(output.path().join("source")).unwrap(),
        &entry("redirect/new/image.iso"),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap_err();
    assert!(!failure.destination_incomplete);
    assert_eq!(failure.bytes_written, 0);
    assert_eq!(fs::read(elsewhere.path().join("keep")).unwrap(), b"outside");
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 1);
}
