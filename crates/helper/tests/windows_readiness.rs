// SPDX-License-Identifier: GPL-3.0-or-later
#[path = "../src/writer/windows_readiness.rs"]
mod readiness;

#[cfg(windows)]
#[allow(dead_code)]
#[path = "support/windows_vhd.rs"]
mod vhd_support;

#[cfg(windows)]
#[test]
#[ignore = "queries only its own new 256 MiB temporary VHDX; requires Windows administrator storage privileges"]
fn windows_vhd_readiness_refuses_read_only_attachment() -> Result<(), Box<dyn std::error::Error>> {
    use isohopper_helper::writer::windows::check_write_readiness;
    use std::{fs::OpenOptions, io, os::windows::fs::OpenOptionsExt};
    use vhd_support::{ManageVolumePrivilege, TemporaryVhd, assert_readback_binding};
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    let _privilege = ManageVolumePrivilege::enable()?;
    // The VHD owner detaches before its directory is removed on every exit.
    let directory = tempfile::tempdir()?;
    let mut vhd = TemporaryVhd::create(directory.path().join("readiness.vhdx"))?;
    for read_only in [false, true, false] {
        vhd.attach(read_only)?;
        let (path, number) = vhd.physical_path()?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)?;
        assert_readback_binding(&file, number)?;
        // SAFETY: this is the live disk handle for our own VHD, opened above
        // synchronously without FILE_FLAG_OVERLAPPED. The query is read-only.
        let result = unsafe { check_write_readiness(&file) };
        if read_only {
            let error = result.expect_err("read-only VHD attachment was reported writable");
            assert_eq!(
                error.kind(),
                io::ErrorKind::PermissionDenied,
                "read-only attachment must be an explicit refusal, not unknown: {error}"
            );
            assert!(
                ["disk is read-only", "disk is write protected"]
                    .contains(&error.to_string().as_str()),
                "read-only attachment must report its flag or write protection, not access denial: {error}"
            );
        } else {
            result.map_err(|error| format!("normal VHD readiness query failed: {error}"))?;
        }
        drop(file);
        vhd.detach()?;
    }
    println!(
        "Readiness integration passed: ordinary VHD attachments accepted; read-only attachment explicitly refused; no media or disk attributes changed; no USB hardware exercised"
    );
    Ok(())
}
