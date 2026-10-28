// SPDX-License-Identifier: GPL-3.0-or-later
use cap_std::{ambient_authority, fs::Dir};
use isohopper_media::copy::{CopyEntry, Phase, copy_one, validate_manifest};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    sync::atomic::{AtomicBool, Ordering},
};

fn entry(path: &str, bytes: &[u8]) -> CopyEntry {
    CopyEntry {
        relative_path: path.into(),
        bytes: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}

#[test]
fn nested_images_preserve_bytes_paths_and_report_verified_progress() {
    let input = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(output.path(), ambient_authority()).unwrap();
    for name in [
        "Mac/MacOS.img",
        "Windows/Win11.iso",
        "Linux live/日本語.iso",
    ] {
        let data = vec![0x5a; 2 * 1024 * 1024 + 71];
        fs::write(input.path().join("source"), &data).unwrap();
        let mut source = File::open(input.path().join("source")).unwrap();
        let mut phases = Vec::new();
        let report = copy_one(
            &root,
            &mut source,
            &entry(name, &data),
            &AtomicBool::new(false),
            |p| {
                assert!(p.completed_bytes <= p.total_bytes);
                if phases.last() != Some(&p.phase) {
                    phases.push(p.phase);
                }
            },
        )
        .unwrap();
        assert_eq!(fs::read(output.path().join(name)).unwrap(), data);
        assert_eq!(report.bytes_written, data.len() as u64);
        assert_eq!(report.bytes_verified, data.len() as u64);
        assert_eq!(report.sha256, Sha256::digest(&data).as_slice());
        assert_eq!(
            phases,
            [
                Phase::CheckingSource,
                Phase::Writing,
                Phase::Flushing,
                Phase::Verifying,
                Phase::Complete
            ]
        );
    }
}

#[test]
fn manifest_rejects_unsafe_names_collisions_prefix_conflicts_and_capacity_overflow() {
    for name in [
        "../x.iso",
        "/x.iso",
        "a\\x.iso",
        "a:x.iso",
        "a//b.iso",
        "CON.iso",
        "CON .iso",
        "COM0.iso",
        "LPT0.iso",
        "a/NUL",
        "a/COM1.iso",
        "a/LPT³.iso",
        "a./b.iso",
        "a /b.iso",
        "a?/b.iso",
        "a*/b.iso",
        "a\u{7f}/b.iso",
    ] {
        assert!(
            validate_manifest(&[entry(name, b"abc")], 4096, 4096).is_err(),
            "{name:?}"
        );
    }
    for names in [
        ["Windows/boot.iso", "windows/BOOT.iso"],
        ["a.iso", "a.iso/b.img"],
        ["a.iso/b.img", "a.iso"],
    ] {
        assert!(validate_manifest(&names.map(|p| entry(p, b"abc")), 8192, 4096).is_err());
    }
    assert_eq!(
        validate_manifest(
            &[entry("Mac/x.img", b"abc"), entry("Win/y.iso", b"abc")],
            8192,
            4096
        )
        .unwrap(),
        8192
    );
    assert!(
        validate_manifest(
            &[entry("x.iso", b"abc"), entry("y.iso", b"abc")],
            8191,
            4096
        )
        .is_err()
    );
    assert!(validate_manifest(&[entry("x.iso", b"abc")], u64::MAX, 0).is_err());
}

#[test]
fn invalid_sources_and_pre_cancel_never_create_destination() {
    let input = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(output.path(), ambient_authority()).unwrap();
    fs::write(input.path().join("source"), b"changed").unwrap();
    for cancelled in [false, true] {
        let mut source = File::open(input.path().join("source")).unwrap();
        let failure = copy_one(
            &root,
            &mut source,
            &entry("sub/x.iso", b"initial"),
            &AtomicBool::new(cancelled),
            |_| {},
        )
        .unwrap_err();
        assert!(!failure.destination_incomplete);
        assert_eq!(failure.bytes_written, 0);
        assert_eq!(fs::read_dir(output.path()).unwrap().count(), 0);
    }
}

#[test]
fn existing_destination_is_never_overwritten() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(tmp.path(), ambient_authority()).unwrap();
    fs::write(tmp.path().join("source"), b"new").unwrap();
    fs::write(tmp.path().join("x.iso"), b"valuable").unwrap();
    let error = copy_one(
        &root,
        &mut File::open(tmp.path().join("source")).unwrap(),
        &entry("x.iso", b"new"),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap_err();
    assert!(!error.destination_incomplete);
    assert_eq!(fs::read(tmp.path().join("x.iso")).unwrap(), b"valuable");
}

#[test]
fn cancellation_after_mutation_marks_partial_file_and_never_completes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(tmp.path(), ambient_authority()).unwrap();
    let data = vec![3; 3 * 1024 * 1024];
    fs::write(tmp.path().join("source"), &data).unwrap();
    let cancel = AtomicBool::new(false);
    let error = copy_one(
        &root,
        &mut File::open(tmp.path().join("source")).unwrap(),
        &entry("x.iso", &data),
        &cancel,
        |p| {
            assert_ne!(p.phase, Phase::Complete);
            if p.phase == Phase::Writing && p.completed_bytes > 0 {
                cancel.store(true, Ordering::Relaxed);
            }
        },
    )
    .unwrap_err();
    assert!(error.destination_incomplete);
    assert!(error.bytes_written > 0 && error.bytes_written < data.len() as u64);
}

#[cfg(unix)]
#[test]
fn symlink_destination_parent_cannot_escape_root() {
    let input = tempfile::tempdir().unwrap();
    let output = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    fs::write(input.path().join("source"), b"abc").unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), output.path().join("redirect")).unwrap();
    let root = Dir::open_ambient_dir(output.path(), ambient_authority()).unwrap();
    let failure = copy_one(
        &root,
        &mut File::open(input.path().join("source")).unwrap(),
        &entry("redirect/x.iso", b"abc"),
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap_err();
    assert!(!failure.destination_incomplete);
    assert_eq!(fs::read_dir(elsewhere.path()).unwrap().count(), 0);
}

#[test]
fn changed_source_during_copy_cannot_report_success() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(tmp.path(), ambient_authority()).unwrap();
    let path = tmp.path().join("source");
    fs::write(&path, b"abc").unwrap();
    let failure = copy_one(
        &root,
        &mut File::open(&path).unwrap(),
        &entry("x.iso", b"abc"),
        &AtomicBool::new(false),
        |p| {
            if p.phase == Phase::Writing && p.completed_bytes == 0 {
                fs::write(&path, b"xyz").unwrap();
            }
            assert_ne!(p.phase, Phase::Complete);
        },
    )
    .unwrap_err();
    assert!(failure.destination_incomplete);
}

#[test]
fn readback_detects_corruption_after_flush() {
    let tmp = tempfile::tempdir().unwrap();
    let root = Dir::open_ambient_dir(tmp.path(), ambient_authority()).unwrap();
    fs::write(tmp.path().join("source"), b"abc").unwrap();
    let failure = copy_one(
        &root,
        &mut File::open(tmp.path().join("source")).unwrap(),
        &entry("x.iso", b"abc"),
        &AtomicBool::new(false),
        |p| {
            if p.phase == Phase::Verifying && p.completed_bytes == 0 {
                fs::write(tmp.path().join("x.iso"), b"bad").unwrap();
            }
            assert_ne!(p.phase, Phase::Complete);
        },
    )
    .unwrap_err();
    assert!(failure.destination_incomplete);
    assert_eq!(failure.bytes_written, 3);
}

#[cfg(unix)]
#[test]
fn replacing_destination_or_parent_during_copy_cannot_report_success() {
    for replace_parent in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let root = Dir::open_ambient_dir(tmp.path(), ambient_authority()).unwrap();
        fs::write(tmp.path().join("source"), b"abc").unwrap();
        let failure = copy_one(
            &root,
            &mut File::open(tmp.path().join("source")).unwrap(),
            &entry("sub/x.iso", b"abc"),
            &AtomicBool::new(false),
            |p| {
                if p.phase == Phase::Writing && p.completed_bytes == 0 {
                    if replace_parent {
                        fs::rename(tmp.path().join("sub"), tmp.path().join("moved")).unwrap();
                        fs::create_dir(tmp.path().join("sub")).unwrap();
                    } else {
                        fs::rename(tmp.path().join("sub/x.iso"), tmp.path().join("old.iso"))
                            .unwrap();
                    }
                    fs::write(tmp.path().join("sub/x.iso"), b"bad").unwrap();
                }
            },
        )
        .unwrap_err();
        assert!(failure.destination_incomplete);
        assert_eq!(fs::read(tmp.path().join("sub/x.iso")).unwrap(), b"bad");
    }
}
