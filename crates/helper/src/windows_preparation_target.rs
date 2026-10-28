// SPDX-License-Identifier: GPL-3.0-or-later
//! Preparation policy and retained Windows target ownership. Pure policy inputs
//! are observations, not authority; the native owner obtains them independently.
#[cfg(any(windows, test))]
use crate::writer::DeviceSnapshot;
#[cfg(any(windows, test))]
use isohopper_inventory::windows::WindowsPartitionRecord;
use isohopper_inventory::{
    windows::WindowsDiskRecord,
    windows_pools::{PhysicalDiskPools, PoolObservation},
};

#[derive(Debug, thiserror::Error)]
pub enum PreparationError {
    #[error("preparation refused: {0}")]
    Refused(&'static str),
    #[error(transparent)]
    Target(#[from] crate::windows_target::TargetError),
    #[error(transparent)]
    Protected(#[from] crate::windows_protected::ProtectedError),
    #[error(transparent)]
    Inventory(#[from] isohopper_inventory::InventoryError),
    #[error(transparent)]
    Lock(#[from] crate::windows_lock::ObservedLockError),
}

/// Correlate a native-bound MSFT_Disk record with complete pool observations.
/// This does not collect evidence and must not be used on caller-supplied data
/// as a write authorization. DeviceId is deliberately never a disk number.
pub fn require_standalone_pool<'a>(
    disk: &WindowsDiskRecord,
    pools: &'a PoolObservation,
) -> Result<&'a PhysicalDiskPools, PreparationError> {
    let refused = PreparationError::Refused;
    let id = disk
        .unique_id
        .as_deref()
        .filter(|id| !id.trim().is_empty())
        .ok_or(refused("missing opaque storage identity"))?;
    let format = disk
        .unique_id_format
        .ok_or(refused("missing storage identity format"))?;
    // Both storage classes define these VPD identifier formats. Vendor-specific
    // format 0 and unrecognized values cannot establish this correlation.
    if !matches!(format, 1 | 2 | 3 | 8) {
        return Err(refused("unsupported storage identity format"));
    }
    let mut matches = pools
        .physical_disks
        .iter()
        .filter(|record| record.unique_id == id);
    let record = matches
        .next()
        .ok_or(refused("disk has no exact physical storage match"))?;
    if matches.next().is_some() || record.unique_id_format != Some(format) {
        return Err(refused("ambiguous physical storage identity"));
    }
    let serial = disk
        .serial_number
        .as_deref()
        .filter(|serial| !serial.trim().is_empty())
        .ok_or(refused("physical storage serial is unknown"))?;
    if disk.size.is_none_or(|size| size == 0)
        || disk.bus_type.is_none()
        || record.size_bytes != disk.size
        || record.bus_type != disk.bus_type
        || record.serial_number.as_deref() != Some(serial)
    {
        return Err(refused("physical storage metadata does not match"));
    }
    match record.is_partial {
        Some(false) => (),
        Some(true) => return Err(refused("physical storage reports partial use")),
        None => return Err(refused("physical storage partial-use status is unknown")),
    }
    if record.primordial_pools.is_empty() {
        return Err(refused(
            "physical storage has no primordial pool association",
        ));
    }
    if !record.nonprimordial_pools.is_empty() {
        return Err(refused("physical storage has concrete pool membership"));
    }
    Ok(record)
}

#[cfg(any(windows, test))]
fn require_target_policy(
    device: &DeviceSnapshot,
    disk: &WindowsDiskRecord,
    partitions: &[WindowsPartitionRecord],
) -> Result<(), PreparationError> {
    let refused = PreparationError::Refused;
    device
        .geometry
        .validate()
        .map_err(|_| refused("unsupported geometry"))?;
    device
        .validate_identity()
        .map_err(|_| refused("missing durable device identity"))?;
    if device.serial.trim().is_empty() || disk.serial_number.as_deref() != Some(&device.serial) {
        return Err(refused(
            "preparation requires a native and provider-matched serial",
        ));
    }
    if ![7, 12].contains(&device.bus_type) {
        return Err(refused("only USB and SD preparation is supported"));
    }
    if device.geometry.logical_sector_size != 512
        || ![512, 4096].contains(&device.geometry.physical_sector_size)
    {
        return Err(refused("boot engine requires 512-byte logical sectors"));
    }
    if [
        disk.is_boot,
        disk.is_system,
        disk.is_read_only,
        disk.is_offline,
        disk.is_clustered,
    ]
    .iter()
    .any(|flag| *flag != Some(false))
    {
        return Err(refused(
            "disk is protected, unavailable, or has unknown status",
        ));
    }
    if partitions.iter().any(|partition| {
        [
            partition.is_boot,
            partition.is_system,
            partition.is_read_only,
            partition.is_offline,
        ]
        .iter()
        .any(|flag| *flag != Some(false))
    }) {
        return Err(refused(
            "partition is protected, unavailable, or has unknown status",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;

#[cfg(any(windows, test))]
fn require_clear_encryption(
    report: &crate::windows_encryption_check::EncryptionReport,
) -> Result<(), PreparationError> {
    use crate::windows_encryption_check::{AssessmentScope, Finding, ProviderObservation};
    use isohopper_inventory::windows_encryption::ProviderStatus;
    let refused =
        || PreparationError::Refused("BitLocker state is encrypted, incomplete, or unknown");
    if report.provider != ProviderObservation::Reported(ProviderStatus::Available)
        || report.partitions.len() != report.coverage.partitions.len()
    {
        return Err(refused());
    }
    let mut volumes = 0;
    for (result, partition) in report.partitions.iter().zip(&report.coverage.partitions) {
        if &result.partition != partition {
            return Err(refused());
        }
        match result.findings.as_slice() {
            [Finding::ProviderReportsNoBitLockerEncryption] if partition.volume_guid.is_some() => {
                volumes += 1
            }
            [Finding::NotApplicable(_)]
                if partition.volume_guid.is_none() && !partition.volume_required => {}
            _ => return Err(refused()),
        }
    }
    let expected = if volumes == 0 {
        AssessmentScope::NoVolumesAssessed
    } else {
        AssessmentScope::VolumesAssessed { count: volumes }
    };
    if report.scope != expected {
        return Err(refused());
    }
    Ok(())
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{PreparationDevice, PreparationTarget};
