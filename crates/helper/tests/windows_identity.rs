// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::windows_identity::{IdentityError, IdentityOrigin, parse_identity};

const GUID: [u8; 16] = [
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 1, 2, 3, 4, 5, 6, 7, 8,
];

fn descriptor(flags: u32) -> Vec<u8> {
    let mut bytes = vec![0; 40];
    for (offset, value) in [(0, 40u32), (4, 40), (8, flags), (12, 7), (16, 12)] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes[20..36].copy_from_slice(&GUID);
    bytes
}

fn set(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn hardware_derived_origins_preserve_native_guid_and_device_number() {
    for (flags, origin) in [
        (0, IdentityOrigin::VendorProductSerial),
        (4, IdentityOrigin::Page83),
    ] {
        let identity = parse_identity(&descriptor(flags)).unwrap();
        assert_eq!(identity.device_number(), 12);
        assert_eq!(identity.device_guid(), &GUID);
        assert_eq!(identity.origin(), origin);
    }
    let mut bytes = descriptor(4);
    set(&mut bytes, 16, 0);
    assert_eq!(parse_identity(&bytes).unwrap().device_number(), 0);
}

#[test]
fn random_no_hardware_and_conflicting_identities_are_never_accepted() {
    for flags in [1, 2, 3, 5, 6, 7] {
        assert!(
            matches!(parse_identity(&descriptor(flags)), Err(IdentityError::RandomGuid { flags: actual }) if actual == flags)
        );
    }
}

#[test]
fn unknown_flags_and_versions_are_not_interpreted_as_known_layouts() {
    for flags in [8, 12, 1 << 31, u32::MAX] {
        assert!(matches!(
            parse_identity(&descriptor(flags)),
            Err(IdentityError::UnsupportedDescriptor(_))
        ));
    }
    for version in [0, 1, 39, 41, u32::MAX] {
        let mut bytes = descriptor(4);
        set(&mut bytes, 0, version);
        assert!(matches!(
            parse_identity(&bytes),
            Err(IdentityError::UnsupportedDescriptor(_))
        ));
    }
}

#[test]
fn only_exact_complete_descriptor_sizes_are_accepted() {
    let bytes = descriptor(4);
    for length in 0..40 {
        assert!(parse_identity(&bytes[..length]).is_err());
    }
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(parse_identity(&extended).is_err());
    for size in [0, 1, 39, 41, u32::MAX] {
        let mut bytes = bytes.clone();
        set(&mut bytes, 4, size);
        assert!(parse_identity(&bytes).is_err());
    }
}

#[test]
fn partitions_non_disks_mpio_paths_and_zero_guids_are_rejected() {
    for device_type in [0, 2, 8, u32::MAX] {
        let mut bytes = descriptor(4);
        set(&mut bytes, 12, device_type);
        assert!(matches!(
            parse_identity(&bytes),
            Err(IdentityError::NotDisk)
        ));
    }
    for partition in [1, 2, u32::MAX] {
        let mut bytes = descriptor(4);
        set(&mut bytes, 36, partition);
        assert!(matches!(
            parse_identity(&bytes),
            Err(IdentityError::NotWholeDisk)
        ));
    }
    let mut bytes = descriptor(4);
    set(&mut bytes, 16, u32::MAX);
    assert!(matches!(
        parse_identity(&bytes),
        Err(IdentityError::MpioPath)
    ));
    let mut bytes = descriptor(4);
    bytes[20..36].fill(0);
    assert!(matches!(
        parse_identity(&bytes),
        Err(IdentityError::MissingGuid)
    ));
}

#[test]
fn equality_checks_guid_number_and_origin_without_uuid_endianness_guessing() {
    let expected = parse_identity(&descriptor(4)).unwrap();
    assert_eq!(parse_identity(&descriptor(4)).unwrap(), expected);
    let mut bytes = descriptor(4);
    bytes[20..24].reverse();
    assert_ne!(parse_identity(&bytes).unwrap(), expected);
    let mut bytes = descriptor(4);
    set(&mut bytes, 16, 13);
    assert_ne!(parse_identity(&bytes).unwrap(), expected);
    assert_ne!(parse_identity(&descriptor(0)).unwrap(), expected);
}

#[cfg(windows)]
#[allow(dead_code)]
#[path = "support/windows_vhd.rs"]
mod vhd_support;

#[cfg(windows)]
#[test]
#[ignore = "read-only identity queries on an owned disposable VHDX; requires Windows administrator storage privileges"]
fn windows_vhd_identity_queries_agree_or_report_unsupported()
-> Result<(), Box<dyn std::error::Error>> {
    use isohopper_helper::windows_identity::query_identity;
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    use vhd_support::{ManageVolumePrivilege, TemporaryVhd, assert_readback_binding};
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    let _privilege = ManageVolumePrivilege::enable()?;
    let directory = tempfile::tempdir()?;
    let mut vhd = TemporaryVhd::create(directory.path().join("identity.vhdx"))?;
    vhd.attach(true)?;
    let (path, number) = vhd.physical_path()?;
    let first = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)?;
    let second = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)?;
    assert_readback_binding(&first, number)?;
    assert_readback_binding(&second, number)?;
    // SAFETY: both retained VHD disk handles were opened synchronously above,
    // without FILE_FLAG_OVERLAPPED; these calls only query device metadata.
    let (first_result, second_result) =
        unsafe { (query_identity(&first), query_identity(&second)) };
    match (first_result, second_result) {
        (Ok(first), Ok(second)) => {
            assert_eq!(first.device_number(), number);
            assert_eq!(first, second);
            println!(
                "Owned read-only VHD identity agrees across retained handles; no physical device tested"
            );
        }
        (
            Err(IdentityError::RandomGuid { flags: first }),
            Err(IdentityError::RandomGuid { flags: second }),
        ) => {
            assert_eq!(first, second);
            println!(
                "Owned VHD reports a random GUID (flags {first}); identity binding remains unsupported, not accepted"
            );
        }
        (Err(IdentityError::MissingGuid), Err(IdentityError::MissingGuid)) => {
            println!(
                "Owned VHD has no device GUID; identity binding remains unsupported, not accepted"
            );
        }
        (Err(IdentityError::Query(first)), Err(IdentityError::Query(second)))
            if matches!(first.raw_os_error(), Some(1 | 50))
                && first.raw_os_error() == second.raw_os_error() =>
        {
            println!(
                "Owned VHD driver does not implement the identity query (Win32 {:?}); binding remains unsupported",
                first.raw_os_error()
            );
        }
        results => {
            return Err(
                format!("unexpected or inconsistent identity query results: {results:?}").into(),
            );
        }
    }
    drop(first);
    drop(second);
    vhd.detach()?;
    Ok(())
}
