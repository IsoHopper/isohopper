// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::windows_encryption_check::{AssessmentScope, EncryptionReport, ProviderObservation};
use crate::windows_lock::TargetCoverage;
use crate::writer::Geometry;
use isohopper_inventory::windows_encryption::ProviderStatus;
use isohopper_inventory::windows_pools::StoragePool;

fn fixture() -> (DeviceSnapshot, WindowsDiskRecord, PoolObservation) {
    let device = DeviceSnapshot {
        device_number: 9,
        serial: "usb-serial".into(),
        device_id: None,
        bus_type: 7,
        geometry: Geometry {
            size_bytes: 8 * 1024 * 1024 * 1024,
            logical_sector_size: 512,
            physical_sector_size: 4096,
        },
    };
    let disk = WindowsDiskRecord {
        number: 9,
        path: Some("native-bound-interface".into()),
        unique_id: Some("  Opaque ID  ".into()),
        unique_id_format: Some(8),
        serial_number: Some(device.serial.clone()),
        friendly_name: None,
        size: Some(device.geometry.size_bytes),
        logical_sector_size: Some(512),
        physical_sector_size: Some(4096),
        bus_type: Some(7),
        is_boot: Some(false),
        is_system: Some(false),
        is_read_only: Some(false),
        is_offline: Some(false),
        is_clustered: Some(false),
        number_of_partitions: Some(0),
    };
    let pools = PoolObservation {
        source: "test-provider".into(),
        physical_disks: vec![PhysicalDiskPools {
            object_id: "physical-object".into(),
            unique_id: "  Opaque ID  ".into(),
            unique_id_format: Some(8),
            device_id: Some("unrelated-provider-id".into()),
            serial_number: Some(device.serial.clone()),
            bus_type: Some(7),
            size_bytes: disk.size,
            can_pool: Some(false),
            is_partial: Some(false),
            primordial_pools: vec![StoragePool {
                object_id: "primordial-object".into(),
                unique_id: "primordial-id".into(),
                friendly_name: None,
            }],
            nonprimordial_pools: vec![],
        }],
    };
    (device, disk, pools)
}

#[test]
fn exact_standalone_match_ignores_device_id_and_can_pool() {
    let (_, disk, mut pools) = fixture();
    assert_eq!(
        require_standalone_pool(&disk, &pools).unwrap().object_id,
        "physical-object"
    );
    pools.physical_disks[0].device_id = None;
    pools.physical_disks[0].can_pool = None;
    assert!(require_standalone_pool(&disk, &pools).is_ok());
}

#[test]
fn pool_identity_is_not_trimmed_case_folded_or_replaced_with_device_number() {
    let (_, disk, pools) = fixture();
    for id in ["Opaque ID", "  opaque id  ", "9", ""] {
        let mut p = pools.clone();
        p.physical_disks[0].unique_id = id.into();
        p.physical_disks[0].device_id = Some("9".into());
        assert!(require_standalone_pool(&disk, &p).is_err(), "{id:?}");
    }
    for format in [None, Some(0), Some(3)] {
        let mut p = pools.clone();
        p.physical_disks[0].unique_id_format = format;
        assert!(require_standalone_pool(&disk, &p).is_err());
    }
}

#[test]
fn pool_identity_format_must_be_explicitly_supported_even_when_both_records_agree() {
    let (_, mut disk, mut pools) = fixture();
    for format in [1, 2, 3, 8] {
        disk.unique_id_format = Some(format);
        pools.physical_disks[0].unique_id_format = Some(format);
        assert!(require_standalone_pool(&disk, &pools).is_ok());
    }
    for format in [0, 4, 5, 6, 7, 9, u16::MAX] {
        disk.unique_id_format = Some(format);
        pools.physical_disks[0].unique_id_format = Some(format);
        assert!(
            require_standalone_pool(&disk, &pools).is_err(),
            "unexpected acceptance of format {format}"
        );
    }
}

#[test]
fn missing_ambiguous_partial_or_concrete_pool_evidence_refuses() {
    let (_, disk, pools) = fixture();
    let mut variants = vec![];
    let mut p = pools.clone();
    p.physical_disks.clear();
    variants.push(p);
    let mut p = pools.clone();
    p.physical_disks.push(p.physical_disks[0].clone());
    variants.push(p);
    let mut p = pools.clone();
    p.physical_disks[0].primordial_pools.clear();
    variants.push(p);
    for partial in [None, Some(true)] {
        let mut p = pools.clone();
        p.physical_disks[0].is_partial = partial;
        variants.push(p);
    }
    let mut p = pools.clone();
    p.physical_disks[0].nonprimordial_pools = p.physical_disks[0].primordial_pools.clone();
    variants.push(p);
    for p in variants {
        assert!(require_standalone_pool(&disk, &p).is_err());
    }
}

#[test]
fn pool_membership_refusals_identify_the_failed_field_without_provider_values() {
    let (_, disk, pools) = fixture();
    for (partial, primordial, concrete, reason) in [
        (
            Some(true),
            true,
            false,
            "physical storage reports partial use",
        ),
        (
            None,
            true,
            false,
            "physical storage partial-use status is unknown",
        ),
        (
            Some(false),
            false,
            false,
            "physical storage has no primordial pool association",
        ),
        (
            Some(false),
            true,
            true,
            "physical storage has concrete pool membership",
        ),
    ] {
        let mut observed = pools.clone();
        let record = &mut observed.physical_disks[0];
        record.is_partial = partial;
        if concrete {
            record.nonprimordial_pools = record.primordial_pools.clone();
        }
        if !primordial {
            record.primordial_pools.clear();
        }
        let error = require_standalone_pool(&disk, &observed).unwrap_err();
        // Exact fixed output excludes every provider-controlled identity,
        // serial, friendly name and path, including on the native error path.
        assert_eq!(error.to_string(), format!("preparation refused: {reason}"));
        assert!(matches!(error, PreparationError::Refused(value) if value == reason));
    }
}

#[test]
fn pool_size_bus_and_serial_must_agree_and_be_known() {
    let (_, disk, pools) = fixture();
    let mut variants = vec![];
    for size in [None, Some(0), Some(1024)] {
        let mut p = pools.clone();
        p.physical_disks[0].size_bytes = size;
        variants.push(p);
    }
    for bus in [None, Some(17)] {
        let mut p = pools.clone();
        p.physical_disks[0].bus_type = bus;
        variants.push(p);
    }
    for serial in [None, Some("other".into()), Some("".into())] {
        let mut p = pools.clone();
        p.physical_disks[0].serial_number = serial;
        variants.push(p);
    }
    for p in variants {
        assert!(require_standalone_pool(&disk, &p).is_err());
    }
}

#[test]
fn supported_usb_target_requires_every_negative_provider_flag() {
    let (device, disk, _) = fixture();
    assert!(require_target_policy(&device, &disk, &[]).is_ok());
    for value in [None, Some(true)] {
        for field in 0..5 {
            let mut d = disk.clone();
            match field {
                0 => d.is_boot = value,
                1 => d.is_system = value,
                2 => d.is_read_only = value,
                3 => d.is_offline = value,
                _ => d.is_clustered = value,
            }
            assert!(require_target_policy(&device, &d, &[]).is_err());
        }
    }
}

#[test]
fn unsupported_bus_or_sector_geometry_cannot_reach_writer() {
    let (device, disk, _) = fixture();
    for bus in [0, 3, 8, 11, 13, 15, 16, 17] {
        let mut d = device.clone();
        d.bus_type = bus;
        assert!(require_target_policy(&d, &disk, &[]).is_err());
    }
    let mut d = device.clone();
    d.geometry.logical_sector_size = 4096;
    assert!(require_target_policy(&d, &disk, &[]).is_err());
    let mut d = device;
    d.geometry.physical_sector_size = 65536;
    assert!(require_target_policy(&d, &disk, &[]).is_err());
}

#[test]
fn target_preparation_requires_a_nonempty_native_matched_serial() {
    let (mut device, mut disk, _) = fixture();
    disk.serial_number = None;
    assert!(require_target_policy(&device, &disk, &[]).is_err());
    disk.serial_number = Some("other".into());
    assert!(require_target_policy(&device, &disk, &[]).is_err());
    device.serial = " ".into();
    disk.serial_number = Some(" ".into());
    assert!(require_target_policy(&device, &disk, &[]).is_err());
}

#[test]
fn partition_status_cannot_be_unknown_or_protected() {
    let (device, disk, _) = fixture();
    let part = WindowsPartitionRecord {
        disk_number: 9,
        partition_number: 1,
        offset: Some(1048576),
        size: Some(1048576),
        is_boot: Some(false),
        is_system: Some(false),
        is_read_only: Some(false),
        is_offline: Some(false),
        gpt_type: None,
        mbr_type: Some(7),
    };
    assert!(require_target_policy(&device, &disk, std::slice::from_ref(&part)).is_ok());
    for value in [None, Some(true)] {
        for field in 0..4 {
            let mut p = part.clone();
            match field {
                0 => p.is_boot = value,
                1 => p.is_system = value,
                2 => p.is_read_only = value,
                _ => p.is_offline = value,
            }
            assert!(require_target_policy(&device, &disk, &[p]).is_err());
        }
    }
}

#[test]
fn raw_disk_needs_complete_empty_encryption_coverage() {
    let (device, _, _) = fixture();
    let mut report = EncryptionReport {
        coverage: TargetCoverage {
            device,
            partition_style: 2,
            layout_identity: [0; 16],
            partitions: vec![],
        },
        provider: ProviderObservation::Reported(ProviderStatus::Available),
        scope: AssessmentScope::NoVolumesAssessed,
        partitions: vec![],
    };
    assert!(require_clear_encryption(&report).is_ok());
    report.provider = ProviderObservation::Reported(ProviderStatus::MissingNamespace);
    assert!(require_clear_encryption(&report).is_err());
    report.provider = ProviderObservation::Reported(ProviderStatus::Available);
    report.scope = AssessmentScope::VolumesAssessed { count: 1 };
    assert!(require_clear_encryption(&report).is_err());
}

#[test]
fn every_mapped_volume_needs_one_coherent_clear_encryption_finding() {
    use crate::windows_encryption_check::{Finding, PartitionReport};
    use crate::windows_lock::PartitionCoverage;
    let (device, _, _) = fixture();
    let partition = PartitionCoverage {
        partition_number: 1,
        start_offset: 1048576,
        length_bytes: 1048576,
        partition_type: [1; 16],
        partition_identity: [2; 16],
        volume_guid: Some("volume".into()),
        volume_required: true,
    };
    let mut report = EncryptionReport {
        coverage: TargetCoverage {
            device,
            partition_style: 1,
            layout_identity: [3; 16],
            partitions: vec![partition.clone()],
        },
        provider: ProviderObservation::Reported(ProviderStatus::Available),
        scope: AssessmentScope::VolumesAssessed { count: 1 },
        partitions: vec![PartitionReport {
            partition,
            observation: None,
            findings: vec![Finding::ProviderReportsNoBitLockerEncryption],
        }],
    };
    assert!(require_clear_encryption(&report).is_ok());
    for findings in [
        vec![],
        vec![Finding::TargetVolumeNotReported],
        vec![
            Finding::ProviderReportsNoBitLockerEncryption,
            Finding::HardwareEncryptionReported,
        ],
    ] {
        report.partitions[0].findings = findings;
        assert!(require_clear_encryption(&report).is_err());
    }
    report.partitions.clear();
    assert!(require_clear_encryption(&report).is_err());
}
