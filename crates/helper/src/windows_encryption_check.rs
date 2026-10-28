// SPDX-License-Identifier: GPL-3.0-or-later
//! BitLocker diagnostics for exact target-volume coverage. No result is a
//! write authorization, a stable encryption lease, or a general encryption scan.
//! Protection off can mean suspended keys; hardware encryption can report fully
//! decrypted conversion. See Microsoft Win32_EncryptableVolume method contracts:
//! https://learn.microsoft.com/windows/win32/secprov/win32-encryptablevolume

use crate::windows_lock::{LockError, PartitionCoverage, TargetCoverage};
use isohopper_inventory::windows_encryption::{
    ConversionStatus, EncryptionInventory, EncryptionMethod, LockStatus, MethodObservation,
    ProtectionStatus, ProviderStatus, VolumeEncryption,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Conversion,
    Protection,
    Lock,
    EncryptionMethod,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedPartition {
    BiosBoot,
    MicrosoftReserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CollectorFailure {
    UnsupportedPlatform,
    InvalidResponse,
    CommandFailed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderObservation {
    Reported(ProviderStatus),
    QueryFailed(CollectorFailure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssessmentScope {
    NoVolumesAssessed,
    VolumesAssessed { count: usize },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Inconsistency {
    DecryptedWithSoftwareEncryption,
    DecryptedWithNonzeroPercentage,
    EncryptedWithNoEncryptionMethod,
    FullyEncryptedWithIncompletePercentage,
    NoEncryptionMethodWithProtectionOn,
    NoEncryptionMethodWithLockedVolume,
    DecryptedWithProtectionOn,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Finding {
    /// All four methods succeeded with the exact coherent clear tuple. This
    /// describes the provider at observation time, never general disk safety.
    ProviderReportsNoBitLockerEncryption,
    NotApplicable(ReservedPartition),
    ProviderUnavailable(ProviderStatus),
    ProviderQueryFailed(CollectorFailure),
    TargetVolumeNotReported,
    ReturnCodeMissing(Method),
    MethodFailed {
        method: Method,
        return_code: u32,
    },
    MethodValueMissing(Method),
    EncryptionPercentageMissing,
    ProtectionStatusUnknown,
    ConversionReportsEncryption(ConversionStatus),
    EncryptionMethodReported(EncryptionMethod),
    HardwareEncryptionReported,
    /// The provider's UINT32_MAX method means encryption with unknown algorithm.
    EncryptionAlgorithmUnknown,
    /// Encryption remains reported with protection off; suspension is one
    /// possible reason, not a fact inferred solely from ProtectionStatus.
    ProtectionOffWithEncryption,
    /// Hardware providers can report this even for an unlocked band.
    VolumeReportedLocked,
    Inconsistent(Inconsistency),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionReport {
    pub partition: PartitionCoverage,
    /// Original observation, including every method return code and status.
    /// Undefined values on failed methods are retained here but not interpreted.
    pub observation: Option<VolumeEncryption>,
    pub findings: Vec<Finding>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptionReport {
    pub coverage: TargetCoverage,
    pub provider: ProviderObservation,
    pub scope: AssessmentScope,
    pub partitions: Vec<PartitionReport>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum AssessmentError {
    #[error("invalid target coverage: {0}")]
    InvalidCoverage(&'static str),
    #[error("invalid BitLocker inventory: {0}")]
    InvalidInventory(&'static str),
}

#[derive(Debug, thiserror::Error)]
pub enum ObservationError {
    #[error(transparent)]
    Coverage(#[from] LockError),
    #[error("target coverage changed across the BitLocker query")]
    CoverageChanged,
    #[error(transparent)]
    Assessment(#[from] AssessmentError),
}

pub fn assess(
    coverage: &TargetCoverage,
    inventory: &EncryptionInventory,
) -> Result<EncryptionReport, AssessmentError> {
    let names = validate_coverage(coverage)?;
    if inventory.volumes.len() > 256
        || (inventory.provider != ProviderStatus::Available && !inventory.volumes.is_empty())
    {
        return Err(AssessmentError::InvalidInventory(
            "invalid provider or volume count",
        ));
    }
    let mut records = BTreeMap::new();
    for volume in &inventory.volumes {
        let name = canonical_guid(&volume.device_id)
            .ok_or(AssessmentError::InvalidInventory("invalid volume GUID"))?;
        if records.insert(name, volume).is_some() {
            return Err(AssessmentError::InvalidInventory("duplicate volume GUID"));
        }
        if volume.conversion.return_code == Some(0)
            && volume
                .encryption_percentage
                .is_some_and(|value| value > 100)
        {
            return Err(AssessmentError::InvalidInventory(
                "invalid encryption percentage",
            ));
        }
    }
    let partitions = coverage
        .partitions
        .iter()
        .zip(&names)
        .map(|(partition, name)| {
            let observation = name.as_ref().and_then(|name| records.get(name)).copied();
            let findings = if name.is_none() {
                vec![Finding::NotApplicable(
                    reserved(partition.partition_type).expect("validated reserved partition"),
                )]
            } else if inventory.provider != ProviderStatus::Available {
                vec![Finding::ProviderUnavailable(inventory.provider)]
            } else if let Some(value) = observation {
                findings(value)
            } else {
                vec![Finding::TargetVolumeNotReported]
            };
            PartitionReport {
                partition: partition.clone(),
                observation: observation.cloned(),
                findings,
            }
        })
        .collect();
    let count = names.iter().flatten().count();
    Ok(EncryptionReport {
        coverage: coverage.clone(),
        provider: ProviderObservation::Reported(inventory.provider),
        scope: if count == 0 {
            AssessmentScope::NoVolumesAssessed
        } else {
            AssessmentScope::VolumesAssessed { count }
        },
        partitions,
    })
}

fn canonical_guid(value: &str) -> Option<String> {
    let guid = value.strip_prefix(r"\\?\Volume{")?.strip_suffix("}\\")?;
    if guid.len() != 36
        || !guid.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return None;
    }
    Some(format!(r"\\?\Volume{{{}}}\", guid.to_ascii_lowercase()))
}

fn reserved(kind: [u8; 16]) -> Option<ReservedPartition> {
    match kind {
        [
            0x48,
            0x61,
            0x68,
            0x21,
            0x49,
            0x64,
            0x6f,
            0x6e,
            0x74,
            0x4e,
            0x65,
            0x65,
            0x64,
            0x45,
            0x46,
            0x49,
        ] => Some(ReservedPartition::BiosBoot),
        [
            0x16,
            0xe3,
            0xc9,
            0xe3,
            0x5c,
            0x0b,
            0xb8,
            0x4d,
            0x81,
            0x7d,
            0xf9,
            0x2d,
            0xf0,
            0x02,
            0x15,
            0xae,
        ] => Some(ReservedPartition::MicrosoftReserved),
        _ => None,
    }
}

fn validate_coverage(coverage: &TargetCoverage) -> Result<Vec<Option<String>>, AssessmentError> {
    let invalid = AssessmentError::InvalidCoverage;
    coverage
        .device
        .validate_identity()
        .map_err(|_| invalid("missing or invalid device identity"))?;
    coverage
        .device
        .geometry
        .validate()
        .map_err(|_| invalid("invalid device geometry"))?;
    if coverage.partition_style > 2
        || coverage.partitions.len() > 128
        || (coverage.partition_style == 2 && !coverage.partitions.is_empty())
    {
        return Err(invalid("invalid partition style or count"));
    }
    let mut numbers = BTreeSet::new();
    let mut guids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut ranges = Vec::new();
    let mut names = Vec::new();
    let geometry = &coverage.device.geometry;
    for partition in &coverage.partitions {
        if partition.partition_number == 0 || !numbers.insert(partition.partition_number) {
            return Err(invalid("invalid or duplicate partition number"));
        }
        if partition.start_offset == 0
            || partition.length_bytes == 0
            || !partition
                .start_offset
                .is_multiple_of(u64::from(geometry.logical_sector_size))
            || !partition
                .length_bytes
                .is_multiple_of(u64::from(geometry.logical_sector_size))
            || partition.start_offset > geometry.size_bytes
            || partition.length_bytes > geometry.size_bytes - partition.start_offset
        {
            return Err(invalid("invalid partition range"));
        }
        if partition.partition_type == [0; 16]
            || (coverage.partition_style == 0
                && partition.partition_type[1..].iter().any(|byte| *byte != 0))
        {
            return Err(invalid("invalid partition type"));
        }
        if coverage.partition_style == 1
            && (partition.partition_identity == [0; 16]
                || !identities.insert(partition.partition_identity))
        {
            return Err(invalid("invalid or duplicate GPT partition identity"));
        }
        let is_reserved =
            coverage.partition_style == 1 && reserved(partition.partition_type).is_some();
        if partition.volume_required == is_reserved
            || (partition.volume_guid.is_none() && !is_reserved)
        {
            return Err(invalid("partition volume requirement is inconsistent"));
        }
        let name = partition
            .volume_guid
            .as_deref()
            .map(|value| {
                let name = canonical_guid(value).ok_or(invalid("invalid volume GUID"))?;
                if !guids.insert(name.clone()) {
                    return Err(invalid("duplicate target volume GUID"));
                }
                Ok(name)
            })
            .transpose()?;
        names.push(name);
        ranges.push((
            partition.start_offset,
            partition.start_offset + partition.length_bytes,
        ));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(invalid("overlapping target partitions"));
    }
    Ok(names)
}

fn value<T: Copy>(
    observation: &MethodObservation<T>,
    method: Method,
    output: &mut Vec<Finding>,
) -> Option<T> {
    match observation.return_code {
        None => output.push(Finding::ReturnCodeMissing(method)),
        Some(0) => match observation.value {
            Some(value) => return Some(value),
            None => output.push(Finding::MethodValueMissing(method)),
        },
        Some(return_code) => output.push(Finding::MethodFailed {
            method,
            return_code,
        }),
    }
    None
}

fn findings(volume: &VolumeEncryption) -> Vec<Finding> {
    let mut result = Vec::new();
    let conversion = value(&volume.conversion, Method::Conversion, &mut result);
    let protection = value(&volume.protection, Method::Protection, &mut result);
    let lock = value(&volume.lock, Method::Lock, &mut result);
    let method = value(
        &volume.encryption_method,
        Method::EncryptionMethod,
        &mut result,
    );
    let percentage = conversion.and(volume.encryption_percentage);
    if conversion.is_some() && percentage.is_none() {
        result.push(Finding::EncryptionPercentageMissing);
    }
    if protection == Some(ProtectionStatus::Unknown) {
        result.push(Finding::ProtectionStatusUnknown);
    }
    if let Some(status) = conversion.filter(|status| *status != ConversionStatus::FullyDecrypted) {
        result.push(Finding::ConversionReportsEncryption(status));
    }
    if let Some(method) = method.filter(|method| *method != EncryptionMethod::None) {
        result.push(Finding::EncryptionMethodReported(method));
        match method {
            EncryptionMethod::Hardware => result.push(Finding::HardwareEncryptionReported),
            EncryptionMethod::Unknown => result.push(Finding::EncryptionAlgorithmUnknown),
            _ => {}
        }
    }
    let encryption_reported = conversion
        .is_some_and(|status| status != ConversionStatus::FullyDecrypted)
        || method.is_some_and(|method| method != EncryptionMethod::None);
    if encryption_reported && protection == Some(ProtectionStatus::Off) {
        result.push(Finding::ProtectionOffWithEncryption);
    }
    if lock == Some(LockStatus::Locked) {
        result.push(Finding::VolumeReportedLocked);
    }

    let mut inconsistent = |condition, reason| {
        if condition {
            result.push(Finding::Inconsistent(reason));
        }
    };
    let decrypted = conversion == Some(ConversionStatus::FullyDecrypted);
    let software_method = method.is_some_and(|method| {
        !matches!(
            method,
            EncryptionMethod::None | EncryptionMethod::Hardware | EncryptionMethod::Unknown
        )
    });
    inconsistent(
        decrypted && software_method,
        Inconsistency::DecryptedWithSoftwareEncryption,
    );
    // Hardware conversion describes band locking rather than software sector
    // encryption. Do not impose software percentage consistency on that state.
    let software_or_none = software_method || method == Some(EncryptionMethod::None);
    inconsistent(
        decrypted && software_or_none && percentage.is_some_and(|value| value != 0),
        Inconsistency::DecryptedWithNonzeroPercentage,
    );
    inconsistent(
        conversion.is_some_and(|status| status != ConversionStatus::FullyDecrypted)
            && method == Some(EncryptionMethod::None),
        Inconsistency::EncryptedWithNoEncryptionMethod,
    );
    inconsistent(
        conversion == Some(ConversionStatus::FullyEncrypted)
            && software_or_none
            && percentage.is_some_and(|value| value != 100),
        Inconsistency::FullyEncryptedWithIncompletePercentage,
    );
    inconsistent(
        method == Some(EncryptionMethod::None) && protection == Some(ProtectionStatus::On),
        Inconsistency::NoEncryptionMethodWithProtectionOn,
    );
    inconsistent(
        method == Some(EncryptionMethod::None) && lock == Some(LockStatus::Locked),
        Inconsistency::NoEncryptionMethodWithLockedVolume,
    );
    inconsistent(
        decrypted && protection == Some(ProtectionStatus::On),
        Inconsistency::DecryptedWithProtectionOn,
    );

    if decrypted
        && percentage == Some(0)
        && method == Some(EncryptionMethod::None)
        && protection == Some(ProtectionStatus::Off)
        && lock == Some(LockStatus::Unlocked)
    {
        result.push(Finding::ProviderReportsNoBitLockerEncryption);
    }
    result
}

/// Collect bounded BitLocker evidence between two revalidations of the same
/// retained device/volume coverage. Collection failures remain unknown reports;
/// coverage changes are errors. This cannot freeze encryption state and does
/// not replace the independent checks required before physical preparation.
#[cfg(windows)]
pub fn observe_for_probe(
    probe: &mut crate::windows_lock::TargetVolumeProbe,
) -> Result<EncryptionReport, ObservationError> {
    observe_with(
        || probe.revalidate().cloned(),
        isohopper_inventory::windows_encryption::collect,
    )
}

#[cfg(any(windows, test))]
fn observe_with(
    mut revalidate: impl FnMut() -> Result<TargetCoverage, LockError>,
    collect: impl FnOnce() -> Result<EncryptionInventory, isohopper_inventory::InventoryError>,
) -> Result<EncryptionReport, ObservationError> {
    let before = revalidate()?;
    let observation = collect();
    let after = revalidate()?;
    if before != after {
        return Err(ObservationError::CoverageChanged);
    }
    match observation {
        Ok(observation) => Ok(assess(&before, &observation)?),
        Err(error) => {
            use isohopper_inventory::InventoryError;
            let reason = match error {
                InventoryError::Unsupported(_) => CollectorFailure::UnsupportedPlatform,
                InventoryError::Invalid(_) => CollectorFailure::InvalidResponse,
                InventoryError::Command(_) => CollectorFailure::CommandFailed,
            };
            let mut report = assess(
                &before,
                &EncryptionInventory {
                    provider: ProviderStatus::Available,
                    volumes: vec![],
                },
            )?;
            report.provider = ProviderObservation::QueryFailed(reason);
            for partition in &mut report.partitions {
                if partition.partition.volume_guid.is_some() {
                    partition.findings = vec![Finding::ProviderQueryFailed(reason)];
                }
            }
            Ok(report)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::{DeviceSnapshot, Geometry};
    use isohopper_inventory::InventoryError;
    use std::cell::{Cell, RefCell};

    fn target() -> TargetCoverage {
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
            partitions: vec![PartitionCoverage {
                partition_number: 1,
                start_offset: 1024 * 1024,
                length_bytes: 1024 * 1024,
                partition_type: [1; 16],
                partition_identity: [2; 16],
                volume_guid: Some(r"\\?\Volume{00000000-0000-0000-0000-000000000001}\".into()),
                volume_required: true,
            }],
        }
    }

    #[test]
    fn collector_failure_is_bracketed_and_returned_as_unknown_without_raw_error_text() {
        let events = RefCell::new(Vec::new());
        let result = observe_with(
            || {
                events.borrow_mut().push("revalidate");
                Ok(target())
            },
            || {
                events.borrow_mut().push("collect");
                Err(InventoryError::Command("private diagnostic".into()))
            },
        )
        .unwrap();
        assert_eq!(*events.borrow(), ["revalidate", "collect", "revalidate"]);
        assert_eq!(
            result.provider,
            ProviderObservation::QueryFailed(CollectorFailure::CommandFailed)
        );
        assert_eq!(
            result.partitions[0].findings,
            [Finding::ProviderQueryFailed(
                CollectorFailure::CommandFailed
            )]
        );
        assert!(result.partitions[0].observation.is_none());
        assert!(!format!("{result:?}").contains("private diagnostic"));
    }

    #[test]
    fn changed_coverage_cannot_receive_a_report_from_the_previous_target() {
        let calls = Cell::new(0);
        let result = observe_with(
            || {
                let mut coverage = target();
                if calls.get() != 0 {
                    coverage.layout_identity[0] ^= 1;
                }
                calls.set(calls.get() + 1);
                Ok(coverage)
            },
            || {
                Ok(EncryptionInventory {
                    provider: ProviderStatus::Available,
                    volumes: vec![],
                })
            },
        );
        assert!(matches!(result, Err(ObservationError::CoverageChanged)));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn failed_post_collection_revalidation_takes_precedence_over_collector_failure() {
        let calls = Cell::new(0);
        let result = observe_with(
            || {
                calls.set(calls.get() + 1);
                if calls.get() == 1 {
                    Ok(target())
                } else {
                    Err(LockError::VolumeChanged)
                }
            },
            || Err(InventoryError::Command("query failed".into())),
        );
        assert!(matches!(
            result,
            Err(ObservationError::Coverage(LockError::VolumeChanged))
        ));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn failed_initial_revalidation_never_queries_the_provider() {
        let result = observe_with(
            || Err(LockError::DeviceChanged),
            || panic!("provider must not be queried for changed target"),
        );
        assert!(matches!(
            result,
            Err(ObservationError::Coverage(LockError::DeviceChanged))
        ));
    }
}
