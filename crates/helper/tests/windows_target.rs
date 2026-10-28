// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::{
    windows_identity::parse_identity,
    windows_lock::{PartitionCoverage, TargetCoverage},
    windows_target::{HandleObservation, assess},
    writer::{DeviceSnapshot, Geometry},
};
use isohopper_inventory::windows::{
    WindowsDiskRecord, WindowsEvidence, WindowsEvidenceCompleteness, WindowsPartitionRecord,
};

const PATH: &str =
    r"\\?\scsi#disk&ven_fixture&prod_disk#unit#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
const BASIC_DATA: [u8; 16] = [
    0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
];

fn fixture() -> (
    HandleObservation,
    TargetCoverage,
    WindowsEvidence,
    Vec<String>,
) {
    let mut descriptor = [0; 40];
    for (offset, value) in [(0, 40u32), (4, 40), (8, 4), (12, 7), (16, 9)] {
        descriptor[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    descriptor[20..36].fill(1);
    let handle = HandleObservation {
        identity: parse_identity(&descriptor).unwrap(),
        device: DeviceSnapshot {
            device_number: 9,
            serial: "fixture-serial".into(),
            device_id: None,
            bus_type: 7,
            geometry: Geometry {
                size_bytes: 1024 * 1024 * 1024,
                logical_sector_size: 512,
                physical_sector_size: 4096,
            },
        },
    };
    let coverage = TargetCoverage {
        device: handle.device.clone(),
        partition_style: 1,
        layout_identity: [2; 16],
        partitions: vec![PartitionCoverage {
            partition_number: 1,
            start_offset: 1024 * 1024,
            length_bytes: 128 * 1024 * 1024,
            partition_type: BASIC_DATA,
            partition_identity: [3; 16],
            volume_guid: Some(r"\\?\Volume{11111111-1111-1111-1111-111111111111}\".into()),
            volume_required: true,
        }],
    };
    let evidence = WindowsEvidence {
        source: "fixture".into(),
        disks: vec![WindowsDiskRecord {
            number: 9,
            path: Some(PATH.into()),
            unique_id: Some("  provider identity stays opaque  ".into()),
            unique_id_format: Some(8),
            serial_number: Some("fixture-serial".into()),
            friendly_name: Some("fixture".into()),
            size: Some(handle.device.geometry.size_bytes),
            logical_sector_size: Some(512),
            physical_sector_size: Some(4096),
            bus_type: Some(7),
            is_boot: Some(false),
            is_system: Some(false),
            is_read_only: Some(false),
            is_offline: Some(false),
            is_clustered: Some(false),
            number_of_partitions: Some(1),
        }],
        partitions: vec![WindowsPartitionRecord {
            disk_number: 9,
            partition_number: 1,
            offset: Some(1024 * 1024),
            size: Some(128 * 1024 * 1024),
            is_boot: Some(false),
            is_system: Some(false),
            is_read_only: Some(false),
            is_offline: Some(false),
            gpt_type: Some("{EBD0A0A2-B9E5-4433-87C0-68B6B72699C7}".into()),
            mbr_type: None,
        }],
        completeness: WindowsEvidenceCompleteness {
            partition_query_complete: true,
            partition_membership_consistent: true,
            identity_fields_present: true,
            geometry_fields_present: true,
            status_fields_present: true,
            identity_values_unique: true,
            command_clean: true,
        },
        issues: vec![],
    };
    (handle, coverage, evidence, vec![PATH.into()])
}

#[test]
fn correlates_exact_handles_geometry_topology_and_opaque_provider_values() {
    let (handle, coverage, evidence, interfaces) = fixture();
    let result = assess(&handle, &coverage, &handle, &evidence, &interfaces).unwrap();
    assert_eq!(result.handle, handle);
    assert_eq!(result.coverage, coverage);
    assert_eq!(result.disk, evidence.disks[0]);
    assert_eq!(result.partitions, evidence.partitions);
    assert_eq!(
        result.disk.unique_id.as_deref(),
        Some("  provider identity stays opaque  ")
    );
}

#[test]
fn provider_safety_flags_preserve_positive_negative_and_unknown_without_authorizing() {
    let (handle, coverage, mut evidence, interfaces) = fixture();
    evidence.disks[0].is_boot = Some(true);
    evidence.disks[0].is_system = None;
    evidence.disks[0].is_offline = Some(true);
    evidence.disks[0].is_read_only = None;
    evidence.disks[0].is_clustered = Some(true);
    evidence.partitions[0].is_system = Some(true);
    evidence.partitions[0].is_read_only = None;
    evidence.completeness.status_fields_present = false;
    evidence.disks[0].unique_id_format = Some(65535);
    let result = assess(&handle, &coverage, &handle, &evidence, &interfaces).unwrap();
    assert_eq!(result.disk.is_boot, Some(true));
    assert_eq!(result.disk.is_system, None);
    assert_eq!(result.disk.is_read_only, None);
    assert_eq!(result.disk.is_clustered, Some(true));
    assert_eq!(result.partitions[0].is_system, Some(true));
    assert_eq!(result.partitions[0].is_read_only, None);
    assert_eq!(result.disk.unique_id_format, Some(65535));
}

#[test]
fn native_identity_and_snapshot_mismatches_are_not_repaired_by_provider_strings() {
    let (handle, coverage, evidence, interfaces) = fixture();
    for changed in [
        {
            let mut v = handle.clone();
            v.device.serial.push('x');
            v
        },
        {
            let mut v = handle.clone();
            v.device.device_number += 1;
            v
        },
        {
            let mut v = handle.clone();
            v.device.bus_type = 15;
            v
        },
        {
            let mut v = handle.clone();
            v.device.geometry.size_bytes *= 2;
            v
        },
        {
            let mut v = handle.clone();
            v.device.geometry.logical_sector_size = 4096;
            v
        },
        {
            let mut v = handle.clone();
            v.device.geometry.physical_sector_size = 512;
            v
        },
    ] {
        assert!(assess(&handle, &coverage, &changed, &evidence, &interfaces).is_err());
    }
    let mut raw = [0; 40];
    for (offset, value) in [(0, 40u32), (4, 40), (8, 4), (12, 7), (16, 9)] {
        raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    raw[20..36].fill(2);
    let changed = HandleObservation {
        identity: parse_identity(&raw).unwrap(),
        ..handle.clone()
    };
    assert!(assess(&handle, &coverage, &changed, &evidence, &interfaces).is_err());
    let mut stale_coverage = coverage.clone();
    stale_coverage.device.serial.push('x');
    assert!(assess(&handle, &stale_coverage, &handle, &evidence, &interfaces).is_err());
}

#[test]
fn provider_geometry_bus_and_partition_changes_refuse_binding() {
    let (handle, coverage, evidence, interfaces) = fixture();
    let mutations: &[fn(&mut WindowsEvidence)] = &[
        |e| e.disks[0].size = None,
        |e| e.disks[0].size = Some(512),
        |e| e.disks[0].logical_sector_size = Some(4096),
        |e| e.disks[0].physical_sector_size = None,
        |e| e.disks[0].bus_type = Some(15),
        |e| e.disks[0].serial_number = Some("different-serial".into()),
        |e| e.disks[0].number_of_partitions = None,
        |e| e.disks[0].number_of_partitions = Some(0),
        |e| e.partitions[0].offset = None,
        |e| e.partitions[0].offset = Some(2 * 1024 * 1024),
        |e| e.partitions[0].size = Some(512),
        |e| e.partitions[0].partition_number = 2,
        |e| e.partitions[0].gpt_type = None,
        |e| e.partitions[0].gpt_type = Some("ebd0a0a2b9e5443387c068b6b72699c7".into()),
        |e| e.partitions[0].gpt_type = Some("c12a7328-f81f-11d2-ba4b-00a0c93ec93b".into()),
        |e| e.partitions[0].mbr_type = Some(7),
        |e| e.partitions.clear(),
        |e| e.partitions.push(e.partitions[0].clone()),
        |e| e.disks.push(e.disks[0].clone()),
    ];
    for (i, mutate) in mutations.iter().enumerate() {
        let mut changed = evidence.clone();
        mutate(&mut changed);
        assert!(
            assess(&handle, &coverage, &handle, &changed, &interfaces).is_err(),
            "mutation {i}"
        );
    }
}

#[test]
fn present_interface_membership_required_before_path_can_be_used() {
    let (handle, coverage, evidence, interfaces) = fixture();
    for path in [
        r"C:\example.iso",
        r"\\server\share\disk",
        r"\\.\pipe\disk",
        r"\\.\PhysicalDrive9",
        r"\\?\GLOBALROOT\Device\Harddisk9\DR9",
        "",
        "missing",
        "bad\0path",
        "bad\npath",
    ] {
        let mut changed = evidence.clone();
        changed.disks[0].path = Some(path.into());
        assert!(assess(&handle, &coverage, &handle, &changed, &interfaces).is_err());
    }
    assert!(assess(&handle, &coverage, &handle, &evidence, &[]).is_err());
    assert!(
        assess(
            &handle,
            &coverage,
            &handle,
            &evidence,
            &[PATH.into(), PATH.into()]
        )
        .is_err()
    );
}

#[test]
fn ascii_case_selection_preserves_exact_os_path_and_native_identity_check() {
    let (handle, coverage, evidence, _) = fixture();
    let os_path = PATH.to_ascii_uppercase();
    let result = assess(
        &handle,
        &coverage,
        &handle,
        &evidence,
        std::slice::from_ref(&os_path),
    )
    .unwrap();
    assert_eq!(result.interface_path, os_path);
    assert_eq!(result.disk.path, evidence.disks[0].path);
    let mut changed = handle.clone();
    changed.device.serial.push('x');
    assert!(assess(&handle, &coverage, &changed, &evidence, &[os_path]).is_err());
}

#[test]
fn ambiguous_case_equivalents_and_other_path_rewrites_are_rejected() {
    let (handle, coverage, evidence, _) = fixture();
    assert!(
        assess(
            &handle,
            &coverage,
            &handle,
            &evidence,
            &[PATH.into(), PATH.to_ascii_uppercase()]
        )
        .is_err()
    );
    for rewritten in [
        format!("{PATH}\\"),
        PATH.replacen("?", ".", 1),
        format!(" {PATH}"),
    ] {
        assert!(assess(&handle, &coverage, &handle, &evidence, &[rewritten]).is_err());
    }
    let mut unicode = evidence;
    unicode.disks[0].path = Some("interface-ä".into());
    assert!(
        assess(
            &handle,
            &coverage,
            &handle,
            &unicode,
            &["INTERFACE-Ä".into()]
        )
        .is_err()
    );
}

#[test]
fn incomplete_or_ambiguous_provider_enumeration_never_binds() {
    let (handle, coverage, evidence, interfaces) = fixture();
    for mutate in [
        (|e: &mut WindowsEvidence| e.completeness.command_clean = false)
            as fn(&mut WindowsEvidence),
        |e| e.completeness.partition_query_complete = false,
        |e| e.completeness.partition_membership_consistent = false,
        |e| e.completeness.identity_values_unique = false,
        |e| e.disks.clear(),
    ] {
        let mut changed = evidence.clone();
        mutate(&mut changed);
        assert!(assess(&handle, &coverage, &handle, &changed, &interfaces).is_err());
    }
}

#[test]
fn raw_blank_and_mbr_topologies_match_without_inventing_gpt_types() {
    let (handle, mut coverage, mut evidence, interfaces) = fixture();
    coverage.partition_style = 0;
    coverage.partitions[0].partition_type = [0; 16];
    coverage.partitions[0].partition_type[0] = 12;
    evidence.partitions[0].gpt_type = None;
    evidence.partitions[0].mbr_type = Some(12);
    assert!(assess(&handle, &coverage, &handle, &evidence, &interfaces).is_ok());
    evidence.partitions[0].mbr_type = Some(7);
    assert!(assess(&handle, &coverage, &handle, &evidence, &interfaces).is_err());
    coverage.partition_style = 2;
    coverage.partitions.clear();
    evidence.partitions.clear();
    evidence.disks[0].number_of_partitions = Some(0);
    assert!(assess(&handle, &coverage, &handle, &evidence, &interfaces).is_ok());
}

#[cfg(windows)]
#[allow(dead_code)]
#[path = "support/windows_vhd.rs"]
mod vhd_support;

#[cfg(windows)]
#[test]
#[ignore = "read-only target/provider correlation on a newly created disposable VHDX; requires Windows administrator storage privileges"]
fn windows_vhd_provider_path_binds_to_retained_target() -> Result<(), Box<dyn std::error::Error>> {
    use isohopper_helper::{
        windows_identity::{IdentityError, query_identity},
        windows_target::{BoundTarget, TargetError},
    };
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    use vhd_support::{ManageVolumePrivilege, TemporaryVhd, assert_readback_binding};
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

    let _privilege = ManageVolumePrivilege::enable()?;
    let directory = tempfile::tempdir()?;
    let mut vhd = TemporaryVhd::create(directory.path().join("target-binding.vhdx"))?;
    vhd.attach(false)?;
    // The existing test fixture exposes a snapshot through its raw-device
    // constructor. No read/write operation is performed on that temporary
    // owner; every handle passed to the new binding is opened read-only.
    let snapshot_owner = vhd.open_raw_device()?;
    let expected = snapshot_owner.initial_snapshot().clone();
    drop(snapshot_owner);
    let (path, number) = vhd.physical_path()?;
    let target = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&path)?;
    assert_readback_binding(&target, number)?;
    let ordinary_path = directory.path().join("ordinary-file.img");
    let ordinary_contents = b"owned non-device fixture";
    std::fs::write(&ordinary_path, ordinary_contents)?;
    // Neither an ordinary file nor this VHD's valid PhysicalDrive alias is a
    // CM disk-interface selection. Refusal must precede file/device inspection.
    for candidate in [
        ordinary_path
            .to_str()
            .ok_or("fixture path is not Unicode")?,
        path.to_str().ok_or("VHD path is not Unicode")?,
    ] {
        assert!(matches!(
            BoundTarget::open_present_interface(candidate),
            Err(TargetError::Invalid(
                "provider path has no matching present disk interface"
            ))
        ));
    }
    assert_eq!(std::fs::read(ordinary_path)?, ordinary_contents);
    // SAFETY: this owned VHD's handle is live, read-only and synchronous.
    let identity = unsafe { query_identity(&target) };
    // Record only typed issue categories and numeric disk/partition keys. This
    // is a separate read-only observation, not the binding's exact snapshot.
    let diagnostic = isohopper_inventory::windows::collect_evidence()?;
    eprintln!(
        "Provider observation before target binding: completeness={:?}; issue_count={}; first_issues={:?}",
        diagnostic.completeness,
        diagnostic.issues.len(),
        &diagnostic.issues[..diagnostic.issues.len().min(16)]
    );
    // SAFETY: the target was opened with read access only, without OVERLAPPED;
    // the expected snapshot came from this same still-attached disposable VHD.
    let result = unsafe { BoundTarget::from_owned_handle(target.into(), &expected) };
    match (identity, result) {
        (Ok(identity), Ok(mut bound)) => {
            assert_eq!(bound.observation().handle.identity, identity);
            assert_eq!(bound.observation().handle.device, expected);
            assert_eq!(bound.observation().disk.number, number);
            let observation = bound.observation();
            let provider_path = observation.disk.path.as_deref().expect("provider path");
            assert!(provider_path.eq_ignore_ascii_case(&observation.interface_path));
            println!(
                "Owned VHD interface selection: match={}",
                if provider_path == observation.interface_path {
                    "exact"
                } else {
                    "ascii_case_only"
                }
            );
            assert!(bound.observation().partitions.is_empty());
            let first = bound.observation().clone();
            assert_eq!(bound.revalidate()?, &first);
            // Obtain a second owner using only the observed interface selector,
            // without passing it a handle, snapshot, serial or device number.
            // Different ASCII case must still preserve the actual CM spelling.
            let mut acquired =
                BoundTarget::open_present_interface(&first.interface_path.to_ascii_uppercase())?;
            assert_eq!(acquired.observation(), &first);
            assert_eq!(acquired.revalidate()?, &first);
            assert_eq!(bound.revalidate()?, &first);
            drop(acquired);
            println!(
                "Owned blank VHD provider path, retained native identity and empty partition topology agree across a fresh collection; no physical write or safety approval"
            );
            println!(
                "Owned VHD read-only interface acquisition agrees with retained target; ordinary-file and PhysicalDrive selectors refused"
            );
            drop(bound);
        }
        (
            Err(IdentityError::RandomGuid { flags: expected }),
            Err(TargetError::Identity(IdentityError::RandomGuid { flags: actual })),
        ) => {
            assert_eq!(expected, actual);
            println!(
                "UNSUPPORTED: owned VHD identity is random (flags {actual}); provider binding was refused, not passed"
            );
        }
        (
            Err(IdentityError::MissingGuid),
            Err(TargetError::Identity(IdentityError::MissingGuid)),
        ) => {
            println!(
                "UNSUPPORTED: owned VHD has no native device GUID; provider binding was refused, not passed"
            );
        }
        (
            Err(IdentityError::Query(expected)),
            Err(TargetError::Identity(IdentityError::Query(actual))),
        ) if matches!(expected.raw_os_error(), Some(1 | 50))
            && expected.raw_os_error() == actual.raw_os_error() =>
        {
            println!(
                "UNSUPPORTED: owned VHD driver lacks the device identity query; provider binding was refused, not passed"
            );
        }
        (Ok(_), Err(error)) => return Err(error.into()),
        (Err(error), _) => return Err(error.into()),
    }
    vhd.detach()?;
    Ok(())
}
