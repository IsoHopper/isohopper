// SPDX-License-Identifier: GPL-3.0-or-later
//! This fixture alone changes its process privilege, before taking each stamp.
//! Production creation only observes it. Run this ignored test independently.
use super::*;
use windows_sys::Win32::{
    Foundation::GetLastError,
    Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
        TOKEN_PRIVILEGES, TOKEN_STATISTICS, TokenStatistics,
    },
};

struct Privilege {
    token: OwnedHandle,
    previous: TOKEN_PRIVILEGES,
}
impl Privilege {
    fn set(enabled: bool) -> Self {
        let mut raw = ptr::null_mut();
        // SAFETY: current process; the fixture retains and restores its token.
        assert_ne!(
            unsafe {
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                    &mut raw,
                )
            },
            0
        );
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let name: Vec<_> = "SeManageVolumePrivilege"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut luid = LUID::default();
        assert_ne!(
            unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) },
            0
        );
        let desired = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: if enabled { SE_PRIVILEGE_ENABLED } else { 0 },
            }],
        };
        let mut previous = TOKEN_PRIVILEGES::default();
        let mut size = 0;
        // SAFETY: fixed one-entry buffers, TOKEN_ADJUST_PRIVILEGES handle.
        assert_ne!(
            unsafe {
                AdjustTokenPrivileges(
                    token.as_raw_handle(),
                    0,
                    &desired,
                    size_of::<TOKEN_PRIVILEGES>() as u32,
                    &mut previous,
                    &mut size,
                )
            },
            0
        );
        let status = unsafe { GetLastError() };
        assert_eq!(
            status, 0,
            "fixture requires a token with SeManageVolumePrivilege"
        );
        Self { token, previous }
    }
}
impl Drop for Privilege {
    fn drop(&mut self) {
        // SAFETY: original one-entry state supplied by AdjustTokenPrivileges.
        unsafe {
            AdjustTokenPrivileges(
                self.token.as_raw_handle(),
                0,
                &self.previous,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            );
        }
    }
}

fn modified_id() -> (u32, i32) {
    let mut raw = ptr::null_mut();
    assert_ne!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) },
        0
    );
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut value = TOKEN_STATISTICS::default();
    let mut returned = 0;
    // SAFETY: SDK-sized writable output, live query-only process token.
    assert_ne!(
        unsafe {
            GetTokenInformation(
                token.as_raw_handle(),
                TokenStatistics,
                (&mut value as *mut TOKEN_STATISTICS).cast(),
                size_of::<TOKEN_STATISTICS>() as u32,
                &mut returned,
            )
        },
        0
    );
    assert_eq!(returned as usize, size_of::<TOKEN_STATISTICS>());
    (value.ModifiedId.LowPart, value.ModifiedId.HighPart)
}

fn fixture(path: &Path, handle: &File) -> Root {
    Root::Fixture {
        path: path.to_owned(),
        handle: handle.try_clone().unwrap(),
    }
}

#[test]
#[ignore = "requires elevated Windows; creates only a new private disposable VHDX"]
fn native_owned_stage_disk_has_private_lifetime_without_token_changes() {
    let outer = tempfile::tempdir().unwrap();
    let path = outer.path().join("private-stage-fixture");
    let descriptor = Descriptor::private().unwrap();
    let root = create_private_directory(&path, &descriptor).unwrap();
    let geometry = Geometry {
        size_bytes: 256 * 1024 * 1024,
        logical_sector_size: 512,
        physical_sector_size: 4096,
    };

    // Never adopt an existing directory, even one bearing the right ACL.
    let marker = path.join("marker");
    std::fs::write(&marker, b"keep").unwrap();
    assert!(create_private_directory(&path, &descriptor).is_err());
    assert_eq!(std::fs::read(&marker).unwrap(), b"keep");
    std::fs::remove_file(marker).unwrap();

    let disabled = Privilege::set(false);
    let before = modified_id();
    let refused = OwnedStageDisk::create_under(fixture(&path, &root), geometry.clone());
    assert!(matches!(refused, Err(StageError::Privilege)));
    assert_eq!(before, modified_id(), "refusal must not enable privileges");
    assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);

    // Explicit bootstrap precedes the token identity used for the operation.
    let enabled = Privilege::set(true);
    let before = modified_id();
    let mut disk = OwnedStageDisk::create_under(fixture(&path, &root), geometry.clone()).unwrap();
    let directory = disk.directory.clone();
    assert_eq!(before, modified_id(), "creation changed token identity");
    assert!(directory.join(BACKING_NAME).is_file());
    disk.attach(false).unwrap();
    assert!(disk.attached);
    assert!(disk.attach(false).is_err());
    disk.detach().unwrap();
    disk.attach(true).unwrap();
    assert_eq!(before, modified_id(), "attachment changed token identity");
    disk.close().unwrap();
    assert!(!directory.exists());
    assert_eq!(before, modified_id(), "cleanup changed token identity");

    // Destruction also owns detach. No separately retained raw handle escapes.
    let mut dropped =
        OwnedStageDisk::create_under(fixture(&path, &root), geometry.clone()).unwrap();
    let directory = dropped.directory.clone();
    dropped.attach(false).unwrap();
    drop(dropped);
    assert!(!directory.exists());

    // Unknown contents are never recursively removed or silently adopted.
    let blocked = OwnedStageDisk::create_under(fixture(&path, &root), geometry).unwrap();
    let directory = blocked.directory.clone();
    let extra = directory.join("unexpected");
    std::fs::write(&extra, b"preserve").unwrap();
    assert!(blocked.close().is_err());
    assert_eq!(std::fs::read(&extra).unwrap(), b"preserve");
    assert!(!directory.join(BACKING_NAME).exists());
    std::fs::remove_file(extra).unwrap();
    std::fs::remove_dir(directory).unwrap();
    assert_eq!(before, modified_id());

    drop(enabled);
    drop(disabled);
    drop(root);
    std::fs::remove_dir(path).unwrap();
    println!("OWNED_STAGE_LIFETIME_OK token_unchanged=true owned_only=true");
}
