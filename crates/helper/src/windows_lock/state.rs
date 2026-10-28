// SPDX-License-Identifier: GPL-3.0-or-later
use super::LockError;
use crate::writer::{DeviceSnapshot, Geometry};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const MAX_VOLUMES: usize = 1024;
pub(super) const MAX_EXTENTS: usize = 64;
pub(super) const MAX_PARTITIONS: usize = 128;
pub(super) const LDM_DATA: [u8; 16] = [
    0xa0, 0x60, 0x9b, 0xaf, 0x31, 0x14, 0x62, 0x4f, 0xbc, 0x68, 0x33, 0x11, 0x71, 0x4a, 0x69, 0xad,
];
pub(super) const LDM_METADATA: [u8; 16] = [
    0xaa, 0xc8, 0x08, 0x58, 0x8f, 0x7e, 0xe0, 0x42, 0x85, 0xd2, 0xe1, 0xe9, 0x04, 0x34, 0xcf, 0xb3,
];
// Exact GPT types whose payload is not a filesystem: GRUB BIOS Boot
// (21686148-6449-6e6f-744e-656564454649) and Microsoft Reserved
// (e3c9e316-0b5c-4db8-817d-f92df00215ae). These need no volume GUID;
// a matching volume, if Windows does expose one, must still be locked.
const BIOS_BOOT: [u8; 16] = [
    0x48, 0x61, 0x68, 0x21, 0x49, 0x64, 0x6f, 0x6e, 0x74, 0x4e, 0x65, 0x65, 0x64, 0x45, 0x46, 0x49,
];
const MICROSOFT_RESERVED: [u8; 16] = [
    0x16, 0xe3, 0xc9, 0xe3, 0x5c, 0x0b, 0xb8, 0x4d, 0x81, 0x7d, 0xf9, 0x2d, 0xf0, 0x02, 0x15, 0xae,
];

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct VolumeName(pub(super) String);
impl VolumeName {
    pub(super) fn parse(text: &str) -> Result<Self, LockError> {
        let guid = text
            .strip_prefix(r"\\?\Volume{")
            .and_then(|s| s.strip_suffix("}\\"))
            .ok_or(LockError::MissingEvidence("invalid volume GUID path"))?;
        if guid.len() != 36
            || !guid.bytes().enumerate().all(|(i, b)| {
                if [8, 13, 18, 23].contains(&i) {
                    b == b'-'
                } else {
                    b.is_ascii_hexdigit()
                }
            })
        {
            return Err(LockError::MissingEvidence("invalid volume GUID"));
        }
        Ok(Self(format!(
            r"\\?\Volume{{{}}}\",
            guid.to_ascii_lowercase()
        )))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Extent {
    pub(super) disk: u32,
    pub(super) start: u64,
    pub(super) length: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Partition {
    pub(super) number: u32,
    pub(super) start: u64,
    pub(super) length: u64,
    pub(super) kind: [u8; 16],
    pub(super) identity: [u8; 16],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DiskLayout {
    pub(super) style: u32,
    pub(super) identity: [u8; 16],
    pub(super) partitions: Vec<Partition>,
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

pub(super) fn parse_extents(bytes: &[u8]) -> Result<Vec<Extent>, LockError> {
    if bytes.len() < 8 {
        return Err(LockError::MissingEvidence("truncated extent header"));
    }
    let count = u32_at(bytes, 0) as usize;
    if count == 0 || count > MAX_EXTENTS || bytes.len() != 8 + count * 24 {
        return Err(LockError::MissingEvidence("invalid extent count or length"));
    }
    let mut result = Vec::with_capacity(count);
    for entry in bytes[8..].as_chunks::<24>().0 {
        let start = u64_at(entry, 8);
        let length = u64_at(entry, 16);
        if start > i64::MAX as u64
            || length == 0
            || length > i64::MAX as u64
            || start
                .checked_add(length)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(LockError::MissingEvidence("invalid signed extent range"));
        }
        result.push(Extent {
            disk: u32_at(entry, 0),
            start,
            length,
        });
    }
    Ok(result)
}

pub(super) fn parse_layout(bytes: &[u8], geometry: &Geometry) -> Result<DiskLayout, LockError> {
    geometry
        .validate()
        .map_err(|_| LockError::MissingEvidence("invalid device geometry"))?;
    if bytes.len() < 48 {
        return Err(LockError::MissingEvidence("truncated drive layout"));
    }
    let style = u32_at(bytes, 0);
    let count = u32_at(bytes, 4) as usize;
    if count > MAX_PARTITIONS || bytes.len() != 48 + count * 144 {
        return Err(LockError::MissingEvidence(
            "invalid partition count or length",
        ));
    }
    if style > 2 || (style == 2 && count != 0) {
        return Err(LockError::UnsupportedLayout);
    }
    let mut identity = [0; 16];
    let identity_length = if style == 1 { 16 } else { 4 };
    identity[..identity_length].copy_from_slice(&bytes[8..8 + identity_length]);
    let mut partitions = Vec::new();
    let mut numbers = BTreeSet::new();
    for entry in bytes[48..].as_chunks::<144>().0 {
        if u32_at(entry, 0) != style {
            return Err(LockError::UnsupportedLayout);
        }
        let mut kind = [0; 16];
        let mut partition_id = [0; 16];
        if style == 0 {
            kind[0] = entry[32];
            partition_id.copy_from_slice(&entry[40..56]);
            // Extended containers need independent validation of the complete
            // logical-partition topology. Silently dropping them could turn
            // incomplete discovery into an apparently empty, unlocked disk.
            if [0x05, 0x0f, 0x42, 0x85, 0x86, 0x87].contains(&kind[0]) {
                return Err(LockError::UnsupportedLayout);
            }
            if kind[0] == 0 {
                if u64_at(entry, 8) != 0 || u64_at(entry, 16) != 0 {
                    return Err(LockError::UnsupportedLayout);
                }
                continue;
            }
        } else {
            kind.copy_from_slice(&entry[32..48]);
            partition_id.copy_from_slice(&entry[48..64]);
            if [LDM_DATA, LDM_METADATA].contains(&kind) {
                return Err(LockError::UnsupportedLayout);
            }
            if kind == [0; 16] {
                continue;
            }
        }
        let start = u64_at(entry, 8);
        let length = u64_at(entry, 16);
        let number = u32_at(entry, 24);
        let sector = u64::from(geometry.logical_sector_size);
        if number == 0
            || !numbers.insert(number)
            || start == 0
            || length == 0
            || !start.is_multiple_of(sector)
            || !length.is_multiple_of(sector)
            || start > geometry.size_bytes
            || length > geometry.size_bytes - start
        {
            return Err(LockError::UnsupportedLayout);
        }
        partitions.push(Partition {
            number,
            start,
            length,
            kind,
            identity: partition_id,
        });
    }
    partitions.sort_by_key(|partition| partition.start);
    if partitions
        .windows(2)
        .any(|pair| pair[0].start + pair[0].length > pair[1].start)
    {
        return Err(LockError::UnsupportedLayout);
    }
    Ok(DiskLayout {
        style,
        identity,
        partitions,
    })
}

pub(super) trait Volume {
    /// None requires positive evidence of a non-disk device (currently CD-ROM).
    fn extents(&mut self) -> Result<Option<Vec<Extent>>, LockError>;
    fn lock(&mut self) -> Result<(), LockError>;
    fn dismount(&mut self) -> Result<(), LockError>;
}
pub(super) trait Backend {
    type Volume: Volume;
    fn snapshot(&mut self) -> Result<DeviceSnapshot, LockError>;
    fn layout(&mut self) -> Result<DiskLayout, LockError>;
    fn enumerate(&mut self) -> Result<Vec<VolumeName>, LockError>;
    fn open(&mut self, name: &VolumeName, write: bool) -> Result<Self::Volume, LockError>;
}

pub(super) struct Held<V: Volume> {
    pub(super) name: VolumeName,
    pub(super) volume: V,
}
type Survey = BTreeMap<VolumeName, Option<Vec<Extent>>>;
fn survey<B: Backend>(backend: &mut B, held: &mut [Held<B::Volume>]) -> Result<Survey, LockError> {
    let names = backend.enumerate()?;
    if names.len() > MAX_VOLUMES {
        return Err(LockError::MissingEvidence("volume count limit"));
    }
    let mut result = BTreeMap::new();
    for name in names {
        if result.contains_key(&name) {
            return Err(LockError::MissingEvidence("duplicate volume GUID"));
        }
        let extents = match held.iter_mut().find(|lock| lock.name == name) {
            Some(lock) => lock.volume.extents()?,
            None => backend.open(&name, false)?.extents()?,
        };
        result.insert(name, extents);
    }
    Ok(result)
}

pub(super) fn acquire<B: Backend>(
    backend: &mut B,
    expected: &DeviceSnapshot,
) -> Result<Vec<Held<B::Volume>>, LockError> {
    if backend.snapshot()? != *expected {
        return Err(LockError::DeviceChanged);
    }
    let layout = backend.layout()?;
    let before = survey(backend, &mut [])?;
    let mut names = Vec::new();
    let mut ranges = BTreeSet::new();
    for (name, extents) in &before {
        let Some(extents) = extents else {
            continue;
        };
        if !extents
            .iter()
            .any(|extent| extent.disk == expected.device_number)
        {
            continue;
        }
        if extents.len() != 1 {
            return Err(LockError::UnsupportedLayout);
        }
        let extent = &extents[0];
        if !layout
            .partitions
            .iter()
            .any(|partition| partition.start == extent.start && partition.length == extent.length)
            || !ranges.insert((extent.start, extent.length))
        {
            return Err(LockError::UnsupportedLayout);
        }
        names.push(name.clone());
    }
    // Discovery is complete only if every filesystem-bearing partition has
    // one classified volume with the exact retained layout range. Hidden,
    // unformatted and unknown types are not evidence of safe absence.
    if layout.partitions.iter().any(|partition| {
        let reserved =
            layout.style == 1 && [BIOS_BOOT, MICROSOFT_RESERVED].contains(&partition.kind);
        !reserved && !ranges.contains(&(partition.start, partition.length))
    }) {
        return Err(LockError::MissingEvidence(
            "target partition has no classified volume",
        ));
    }
    if backend.snapshot()? != *expected {
        return Err(LockError::DeviceChanged);
    }
    let mut held = Vec::new();
    // Open and validate every target before taking any lock or dismounting.
    // Each Volume owns its lock and releases it when dropped, including all
    // early returns and unwinding after partial acquisition.
    for name in names {
        let mut volume = backend.open(&name, true)?;
        if volume.extents()? != before[&name] {
            return Err(LockError::VolumeChanged);
        }
        held.push(Held { name, volume });
    }
    for item in &mut held {
        item.volume.lock()?;
    }
    if backend.snapshot()? != *expected {
        return Err(LockError::DeviceChanged);
    }
    if backend.layout()? != layout {
        return Err(LockError::VolumeChanged);
    }
    for item in &mut held {
        if item.volume.extents()? != before[&item.name] {
            return Err(LockError::VolumeChanged);
        }
    }
    // No explicit dismount occurs until every lock and revalidation succeeds.
    for item in &mut held {
        item.volume.dismount()?;
    }
    if survey(backend, &mut held)? != before || backend.layout()? != layout {
        return Err(LockError::VolumeChanged);
    }
    if backend.snapshot()? != *expected {
        return Err(LockError::DeviceChanged);
    }
    Ok(held)
}

#[cfg(test)]
mod tests;
