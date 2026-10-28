// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::{
    windows_encryption_check::{
        self as check, AssessmentScope, Finding, Inconsistency, Method, ProviderObservation,
        ReservedPartition,
    },
    windows_lock::{PartitionCoverage, TargetCoverage},
    writer::{DeviceSnapshot, Geometry},
};
use isohopper_inventory::windows_encryption::{
    ConversionStatus, EncryptionInventory, EncryptionMethod, LockStatus, MethodObservation,
    ProtectionStatus, ProviderStatus, VolumeEncryption,
};

fn guid(n: u32) -> String {
    format!(r"\\?\Volume{{abcdef01-0000-0000-0000-{n:012x}}}\")
}
fn coverage() -> TargetCoverage {
    TargetCoverage {
        device: DeviceSnapshot {
            device_number: 7,
            serial: "TEST-TARGET".into(),
            device_id: None,
            bus_type: 7,
            geometry: Geometry {
                size_bytes: 64 * 1024 * 1024,
                logical_sector_size: 512,
                physical_sector_size: 4096,
            },
        },
        partition_style: 1,
        layout_identity: [1; 16],
        partitions: (1..=2)
            .map(|n| PartitionCoverage {
                partition_number: n,
                start_offset: u64::from(n) * 1024 * 1024,
                length_bytes: 1024 * 1024,
                partition_type: [1; 16],
                partition_identity: [n as u8; 16],
                volume_guid: Some(guid(n)),
                volume_required: true,
            })
            .collect(),
    }
}
fn successful<T>(value: T) -> MethodObservation<T> {
    MethodObservation {
        return_code: Some(0),
        value: Some(value),
    }
}
fn clear(n: u32) -> VolumeEncryption {
    VolumeEncryption {
        device_id: guid(n),
        conversion: successful(ConversionStatus::FullyDecrypted),
        encryption_percentage: Some(0),
        protection: successful(ProtectionStatus::Off),
        lock: successful(LockStatus::Unlocked),
        encryption_method: successful(EncryptionMethod::None),
    }
}
fn inventory(volumes: Vec<VolumeEncryption>) -> EncryptionInventory {
    EncryptionInventory {
        provider: ProviderStatus::Available,
        volumes,
    }
}

#[test]
fn exact_guid_join_preserves_raw_records_and_never_borrows_a_foreign_clear_result() {
    let target = coverage();
    let mut first = clear(1);
    first.device_id = first.device_id.replace("abcdef", "ABCDEF");
    let report = check::assess(&target, &inventory(vec![clear(9), first.clone()])).unwrap();
    assert_eq!(report.coverage, target);
    assert_eq!(report.scope, AssessmentScope::VolumesAssessed { count: 2 });
    assert_eq!(report.partitions[0].observation, Some(first));
    assert_eq!(
        report.partitions[0].findings,
        vec![Finding::ProviderReportsNoBitLockerEncryption]
    );
    assert_eq!(report.partitions[1].observation, None);
    assert_eq!(
        report.partitions[1].findings,
        vec![Finding::TargetVolumeNotReported]
    );
}

#[test]
fn only_the_complete_coherent_success_tuple_reports_no_bitlocker_encryption() {
    let base = clear(1);
    let changes: [fn(&mut VolumeEncryption); 9] = [
        |v| v.conversion.return_code = None,
        |v| v.conversion.value = None,
        |v| v.encryption_percentage = None,
        |v| v.encryption_percentage = Some(1),
        |v| v.protection.return_code = Some(5),
        |v| v.protection.value = Some(ProtectionStatus::Unknown),
        |v| v.lock.value = Some(LockStatus::Locked),
        |v| v.encryption_method.return_code = None,
        |v| v.encryption_method.value = Some(EncryptionMethod::Hardware),
    ];
    for change in changes {
        let mut value = base.clone();
        change(&mut value);
        let report = check::assess(&coverage(), &inventory(vec![value])).unwrap();
        assert!(
            !report.partitions[0]
                .findings
                .contains(&Finding::ProviderReportsNoBitLockerEncryption)
        );
        assert!(!report.partitions[0].findings.is_empty());
    }
}

#[test]
fn failed_methods_keep_their_codes_but_cannot_supply_clear_or_encrypted_values() {
    let mut value = clear(1);
    value.conversion.return_code = Some(2_150_694_912);
    value.conversion.value = Some(ConversionStatus::FullyEncrypted);
    value.encryption_percentage = Some(100);
    value.encryption_method.return_code = None;
    value.encryption_method.value = Some(EncryptionMethod::Hardware);
    value.protection.value = None;
    let report = check::assess(&coverage(), &inventory(vec![value.clone()])).unwrap();
    let item = &report.partitions[0];
    assert_eq!(item.observation, Some(value));
    assert!(item.findings.contains(&Finding::MethodFailed {
        method: Method::Conversion,
        return_code: 2_150_694_912
    }));
    assert!(
        item.findings
            .contains(&Finding::ReturnCodeMissing(Method::EncryptionMethod))
    );
    assert!(
        item.findings
            .contains(&Finding::MethodValueMissing(Method::Protection))
    );
    assert!(!item.findings.contains(&Finding::HardwareEncryptionReported));
    assert!(
        !item
            .findings
            .contains(&Finding::ProtectionOffWithEncryption)
    );
}

#[test]
fn suspended_hardware_and_unknown_algorithm_remain_explicit_encryption_observations() {
    for (method, extra) in [
        (
            EncryptionMethod::XtsAes256,
            Finding::EncryptionMethodReported(EncryptionMethod::XtsAes256),
        ),
        (
            EncryptionMethod::Hardware,
            Finding::HardwareEncryptionReported,
        ),
        (
            EncryptionMethod::Unknown,
            Finding::EncryptionAlgorithmUnknown,
        ),
    ] {
        let mut value = clear(1);
        value.conversion = successful(ConversionStatus::FullyEncrypted);
        value.encryption_percentage = Some(100);
        value.encryption_method = successful(method);
        let report = check::assess(&coverage(), &inventory(vec![value])).unwrap();
        assert!(
            report.partitions[0]
                .findings
                .contains(&Finding::ProtectionOffWithEncryption)
        );
        assert!(report.partitions[0].findings.contains(&extra));
        assert!(
            !report.partitions[0]
                .findings
                .contains(&Finding::ProviderReportsNoBitLockerEncryption)
        );
    }
    let mut hardware = clear(1);
    hardware.encryption_method = successful(EncryptionMethod::Hardware);
    let report = check::assess(&coverage(), &inventory(vec![hardware])).unwrap();
    assert!(
        report.partitions[0]
            .findings
            .contains(&Finding::HardwareEncryptionReported)
    );
    assert!(
        !report.partitions[0]
            .findings
            .contains(&Finding::Inconsistent(
                Inconsistency::DecryptedWithSoftwareEncryption
            ))
    );
}

#[test]
fn partial_or_paused_conversion_is_never_cleared_by_rounded_percentage() {
    for conversion in [
        ConversionStatus::EncryptionInProgress,
        ConversionStatus::DecryptionInProgress,
        ConversionStatus::EncryptionPaused,
        ConversionStatus::DecryptionPaused,
    ] {
        for percentage in [0, 100] {
            let mut value = clear(1);
            value.conversion = successful(conversion);
            value.encryption_percentage = Some(percentage);
            value.encryption_method = successful(EncryptionMethod::Aes256);
            let report = check::assess(&coverage(), &inventory(vec![value])).unwrap();
            assert!(
                report.partitions[0]
                    .findings
                    .contains(&Finding::ConversionReportsEncryption(conversion))
            );
            assert!(
                !report.partitions[0]
                    .findings
                    .contains(&Finding::ProviderReportsNoBitLockerEncryption)
            );
        }
    }
}

#[test]
fn contradictory_successful_results_are_explicit_not_a_clear_verdict() {
    for (change, expected) in [
        (0, Inconsistency::DecryptedWithSoftwareEncryption),
        (1, Inconsistency::DecryptedWithNonzeroPercentage),
        (2, Inconsistency::EncryptedWithNoEncryptionMethod),
        (3, Inconsistency::NoEncryptionMethodWithProtectionOn),
        (4, Inconsistency::NoEncryptionMethodWithLockedVolume),
    ] {
        let mut value = clear(1);
        match change {
            0 => value.encryption_method = successful(EncryptionMethod::Aes256),
            1 => value.encryption_percentage = Some(4),
            2 => value.conversion = successful(ConversionStatus::FullyEncrypted),
            3 => value.protection = successful(ProtectionStatus::On),
            4 => value.lock = successful(LockStatus::Locked),
            _ => unreachable!(),
        }
        let report = check::assess(&coverage(), &inventory(vec![value])).unwrap();
        assert!(
            report.partitions[0]
                .findings
                .contains(&Finding::Inconsistent(expected))
        );
        assert!(
            !report.partitions[0]
                .findings
                .contains(&Finding::ProviderReportsNoBitLockerEncryption)
        );
    }
}

#[test]
fn unavailable_provider_and_empty_inventory_remain_unknown_for_each_target() {
    for status in [
        ProviderStatus::MissingNamespace,
        ProviderStatus::MissingClass,
    ] {
        let report = check::assess(
            &coverage(),
            &EncryptionInventory {
                provider: status,
                volumes: vec![],
            },
        )
        .unwrap();
        assert_eq!(report.provider, ProviderObservation::Reported(status));
        for partition in report.partitions {
            assert_eq!(
                partition.findings,
                vec![Finding::ProviderUnavailable(status)]
            );
        }
    }
    let report = check::assess(&coverage(), &inventory(vec![])).unwrap();
    assert!(
        report
            .partitions
            .iter()
            .all(|p| p.findings == vec![Finding::TargetVolumeNotReported])
    );
}

#[test]
fn blank_and_explicit_reserved_partitions_are_not_blanket_clear_results() {
    let mut target = coverage();
    target.partition_style = 2;
    target.partitions.clear();
    let report = check::assess(&target, &inventory(vec![])).unwrap();
    assert_eq!(report.scope, AssessmentScope::NoVolumesAssessed);
    assert!(report.partitions.is_empty());
    for (kind, bytes) in [
        (
            ReservedPartition::BiosBoot,
            [
                0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6f, 0x6e, 0x74, 0x4e, 0x65, 0x65, 0x64, 0x45,
                0x46, 0x49,
            ],
        ),
        (
            ReservedPartition::MicrosoftReserved,
            [
                0x16, 0xe3, 0xc9, 0xe3, 0x5c, 0x0b, 0xb8, 0x4d, 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02,
                0x15, 0xae,
            ],
        ),
    ] {
        let mut target = coverage();
        target.partitions.truncate(1);
        target.partitions[0].partition_type = bytes;
        target.partitions[0].volume_required = false;
        target.partitions[0].volume_guid = None;
        let report = check::assess(&target, &inventory(vec![])).unwrap();
        assert_eq!(report.scope, AssessmentScope::NoVolumesAssessed);
        assert_eq!(
            report.partitions[0].findings,
            vec![Finding::NotApplicable(kind)]
        );
        target.partitions[0].volume_guid = Some(guid(1));
        let report = check::assess(&target, &inventory(vec![])).unwrap();
        assert_eq!(
            report.partitions[0].findings,
            vec![Finding::TargetVolumeNotReported]
        );
    }
}

#[test]
fn public_coverage_requires_unique_valid_guid_ranges_and_consistent_partition_roles() {
    for change in 0..11 {
        let mut target = coverage();
        match change {
            0 => target.partitions[1].volume_guid = target.partitions[0].volume_guid.clone(),
            1 => target.partitions[0].volume_guid = Some(r"C:\".into()),
            2 => target.partitions[0].volume_guid = None,
            3 => target.partitions[0].volume_required = false,
            4 => target.partitions[1].partition_number = 1,
            5 => target.partitions[1].start_offset = target.partitions[0].start_offset,
            6 => target.partitions[0].length_bytes = u64::MAX,
            7 => target.partitions[0].start_offset += 1,
            8 => target.partition_style = 2,
            9 => target.partition_style = 3,
            10 => target.device.serial.clear(),
            _ => unreachable!(),
        }
        assert!(
            check::assess(&target, &inventory(vec![clear(1), clear(2)])).is_err(),
            "change {change}"
        );
    }
}

#[test]
fn duplicate_or_malformed_inventory_cannot_make_an_ambiguous_guid_join() {
    let mut duplicate = clear(1);
    duplicate.device_id = duplicate.device_id.replace("abcdef", "ABCDEF");
    assert!(check::assess(&coverage(), &inventory(vec![clear(1), duplicate])).is_err());
    let mut bad = clear(1);
    bad.device_id.push_str("extra");
    assert!(check::assess(&coverage(), &inventory(vec![bad])).is_err());
    let mut bad = clear(1);
    bad.encryption_percentage = Some(101);
    assert!(check::assess(&coverage(), &inventory(vec![bad])).is_err());
    assert!(
        check::assess(
            &coverage(),
            &EncryptionInventory {
                provider: ProviderStatus::MissingClass,
                volumes: vec![clear(1)]
            }
        )
        .is_err()
    );
}

#[test]
fn public_input_limits_accept_complete_bounded_sets_and_reject_overflow() {
    let mut target = coverage();
    target.device.geometry.size_bytes = 256 * 1024 * 1024;
    target.partitions = (1..=128)
        .map(|n| {
            let mut partition = target.partitions[0].clone();
            partition.partition_number = n;
            partition.start_offset = u64::from(n) * 1024 * 1024;
            partition.partition_identity = [n as u8; 16];
            partition.volume_guid = Some(guid(n));
            partition
        })
        .collect();
    let mut observed = inventory((1..=256).map(clear).collect());
    let report = check::assess(&target, &observed).unwrap();
    assert_eq!(
        report.scope,
        AssessmentScope::VolumesAssessed { count: 128 }
    );
    assert!(
        report
            .partitions
            .iter()
            .all(|p| p.findings == [Finding::ProviderReportsNoBitLockerEncryption])
    );
    observed.volumes.push(clear(257));
    assert!(check::assess(&target, &observed).is_err());
    observed.volumes.pop();
    target.partitions.push(target.partitions[0].clone());
    assert!(check::assess(&target, &observed).is_err());
}
