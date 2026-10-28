// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only correlation of Windows provider records with retained disk handles.
//! A successful binding identifies observations; it is not a safety verdict,
//! target authorization, a volume lock, or permission to write. Provider status
//! fields retain true, false and unknown separately. Pool membership, pagefiles,
//! protected storage, encryption and authenticated elevation remain separate.

use crate::{windows_identity::DiskIdentity, windows_lock::TargetCoverage, writer::DeviceSnapshot};
use isohopper_inventory::windows::{WindowsDiskRecord, WindowsEvidence, WindowsPartitionRecord};
use std::collections::BTreeSet;

const MAX_INTERFACES: usize = 256;
const MAX_PATH_UNITS: usize = 4096;
#[cfg(any(windows, test))]
const MAX_INTERFACE_UNITS: usize = MAX_INTERFACES * (MAX_PATH_UNITS + 1) + 1;

/// Facts queried from one retained handle. Public construction supplies data,
/// not evidence that any operating-system query actually took place.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HandleObservation {
    pub identity: DiskIdentity,
    pub device: DeviceSnapshot,
}

/// Correlated observations, never an approval token. Use the native owner to
/// collect/revalidate these facts; `assess` also accepts synthetic test data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetObservation {
    pub handle: HandleObservation,
    pub coverage: TargetCoverage,
    pub disk: WindowsDiskRecord,
    pub partitions: Vec<WindowsPartitionRecord>,
}

#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    #[error("incomplete or unsupported Windows target evidence: {0}")]
    Invalid(&'static str),
    #[error("Windows target observations disagree: {0}")]
    Mismatch(&'static str),
    #[error("Windows target query failed during {stage}: {source}")]
    Io {
        stage: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("Windows configuration manager returned {0}")]
    ConfigurationManager(u32),
    #[error(transparent)]
    Identity(#[from] crate::windows_identity::IdentityError),
    #[error(transparent)]
    Coverage(#[from] crate::windows_lock::LockError),
    #[error(transparent)]
    Inventory(#[from] isohopper_inventory::InventoryError),
}

/// Pure comparison for provider/handle observations. It performs no I/O and
/// does not establish their provenance. Exact present disk-interface membership
/// is required; no disk-number path construction or identifier normalization is
/// used. Unknown provider safety flags remain unknown in the returned record.
pub fn assess(
    target: &HandleObservation,
    coverage: &TargetCoverage,
    provider: &HandleObservation,
    evidence: &WindowsEvidence,
    present_disk_interfaces: &[String],
) -> Result<TargetObservation, TargetError> {
    target
        .device
        .geometry
        .validate()
        .map_err(|_| TargetError::Invalid("target geometry"))?;
    target
        .device
        .validate_identity()
        .map_err(|_| TargetError::Invalid("target identity"))?;
    if target.identity.device_number() != target.device.device_number
        || target.device != coverage.device
        || provider != target
    {
        return Err(TargetError::Mismatch(
            "retained handle identity or geometry",
        ));
    }
    let disk = candidate(evidence, target.device.device_number)?;
    let path = disk
        .path
        .as_deref()
        .ok_or(TargetError::Invalid("provider disk path"))?;
    require_interface(path, present_disk_interfaces)?;
    let geometry = &target.device.geometry;
    if disk.size != Some(geometry.size_bytes)
        || disk.logical_sector_size != Some(u64::from(geometry.logical_sector_size))
        || disk.physical_sector_size != Some(u64::from(geometry.physical_sector_size))
        || disk.bus_type.map(u32::from) != Some(target.device.bus_type)
        || disk
            .serial_number
            .as_deref()
            .is_some_and(|value| value != target.device.serial)
    {
        return Err(TargetError::Mismatch(
            "provider geometry, bus type or reported serial",
        ));
    }
    let mut partitions: Vec<_> = evidence
        .partitions
        .iter()
        .filter(|part| part.disk_number == disk.number)
        .cloned()
        .collect();
    if coverage.partition_style > 2
        || coverage.partitions.len() > 128
        || disk.number_of_partitions != Some(coverage.partitions.len() as u32)
        || partitions.len() != coverage.partitions.len()
        || (coverage.partition_style == 2 && !partitions.is_empty())
    {
        return Err(TargetError::Mismatch("partition count or style"));
    }
    partitions.sort_by_key(|part| part.partition_number);
    let mut native_parts: Vec<_> = coverage.partitions.iter().collect();
    native_parts.sort_by_key(|part| part.partition_number);
    let mut numbers = BTreeSet::new();
    let mut ranges = Vec::new();
    for (part, native) in partitions.iter().zip(native_parts) {
        let end = native
            .start_offset
            .checked_add(native.length_bytes)
            .ok_or(TargetError::Invalid("partition range overflow"))?;
        let sector = u64::from(geometry.logical_sector_size);
        if native.partition_number == 0
            || !numbers.insert(native.partition_number)
            || native.start_offset == 0
            || native.length_bytes == 0
            || end > geometry.size_bytes
            || !native.start_offset.is_multiple_of(sector)
            || !native.length_bytes.is_multiple_of(sector)
        {
            return Err(TargetError::Invalid("native partition topology"));
        }
        ranges.push((native.start_offset, end));
        if part.partition_number != native.partition_number
            || part.offset != Some(native.start_offset)
            || part.size != Some(native.length_bytes)
        {
            return Err(TargetError::Mismatch("partition number or extent"));
        }
        let kind = match coverage.partition_style {
            0 if part.gpt_type.is_none() => {
                let value = part
                    .mbr_type
                    .filter(|&value| value > 0 && value <= 255)
                    .ok_or(TargetError::Invalid("MBR partition type"))?;
                let mut kind = [0; 16];
                kind[0] = value as u8;
                kind
            }
            1 if part.mbr_type.is_none_or(|value| value == 0) => parse_guid(
                part.gpt_type
                    .as_deref()
                    .ok_or(TargetError::Invalid("GPT partition type"))?,
            )?,
            _ => return Err(TargetError::Invalid("inconsistent partition type")),
        };
        if kind != native.partition_type {
            return Err(TargetError::Mismatch("partition type"));
        }
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(TargetError::Invalid("overlapping native partitions"));
    }
    Ok(TargetObservation {
        handle: target.clone(),
        coverage: coverage.clone(),
        disk: disk.clone(),
        partitions,
    })
}

fn candidate(evidence: &WindowsEvidence, number: u32) -> Result<&WindowsDiskRecord, TargetError> {
    let complete = &evidence.completeness;
    if evidence.disks.len() > 256
        || evidence.partitions.len() > 4096
        || !complete.command_clean
        || !complete.partition_query_complete
        || !complete.partition_membership_consistent
        || !complete.identity_values_unique
        || !evidence.issues.is_empty()
    {
        return Err(TargetError::Invalid(
            "incomplete or ambiguous provider response",
        ));
    }
    let mut matching = evidence.disks.iter().filter(|disk| disk.number == number);
    let disk = matching
        .next()
        .ok_or(TargetError::Invalid("target absent from provider"))?;
    if matching.next().is_some() {
        return Err(TargetError::Invalid("duplicate provider target"));
    }
    Ok(disk)
}

fn valid_interface_text(path: &str) -> bool {
    !path.is_empty()
        && path.encode_utf16().count() <= MAX_PATH_UNITS
        && !path.chars().any(char::is_control)
}

fn require_interface(path: &str, interfaces: &[String]) -> Result<(), TargetError> {
    if !valid_interface_text(path) || interfaces.len() > MAX_INTERFACES {
        return Err(TargetError::Invalid("disk interface path or count"));
    }
    let mut distinct = BTreeSet::new();
    for value in interfaces {
        if !valid_interface_text(value) || !distinct.insert(value.as_str()) {
            return Err(TargetError::Invalid(
                "invalid or duplicate present disk interface",
            ));
        }
    }
    if !distinct.contains(path) {
        return Err(TargetError::Invalid(
            "provider path is not an exact present disk interface",
        ));
    }
    Ok(())
}

// GPT GUID text has a documented structure. Device-interface paths and VPD
// identifiers do not use this parser and are never normalized for a join.
fn parse_guid(value: &str) -> Result<[u8; 16], TargetError> {
    let text = value
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(value);
    if text.len() != 36
        || !text.bytes().enumerate().all(|(i, byte)| {
            if [8, 13, 18, 23].contains(&i) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(TargetError::Invalid("malformed GPT type GUID"));
    }
    let mut bytes = [0; 16];
    hex::decode_to_slice(text.replace('-', ""), &mut bytes)
        .map_err(|_| TargetError::Invalid("malformed GPT type GUID"))?;
    bytes[..4].reverse();
    bytes[4..6].reverse();
    bytes[6..8].reverse();
    Ok(bytes)
}

#[cfg(any(windows, test))]
fn parse_interfaces(units: &[u16]) -> Result<Vec<String>, TargetError> {
    if units.is_empty() || units.len() > MAX_INTERFACE_UNITS {
        return Err(TargetError::Invalid("interface list size"));
    }
    let mut result = Vec::new();
    let mut remaining = units;
    loop {
        let end = remaining
            .iter()
            .position(|&unit| unit == 0)
            .ok_or(TargetError::Invalid("unterminated interface list"))?;
        if end == 0 {
            if remaining.iter().any(|&unit| unit != 0) {
                return Err(TargetError::Invalid("data after interface list terminator"));
            }
            return Ok(result);
        }
        if end > MAX_PATH_UNITS || result.len() == MAX_INTERFACES {
            return Err(TargetError::Invalid("interface list bounds"));
        }
        let path = String::from_utf16(&remaining[..end])
            .map_err(|_| TargetError::Invalid("invalid interface UTF-16"))?;
        if !valid_interface_text(&path) || result.contains(&path) {
            return Err(TargetError::Invalid(
                "invalid or duplicate present disk interface",
            ));
        }
        result.push(path);
        remaining = &remaining[end + 1..];
    }
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::BoundTarget;

#[cfg(any(windows, test))]
mod state;
