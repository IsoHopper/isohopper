// SPDX-License-Identifier: GPL-3.0-or-later
//! Checked partition geometry. This module performs no I/O.
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MIB: u64 = 1 << 20;
pub const ENTRY_COUNT: u32 = 128;
pub const ENTRY_SIZE: u32 = 128;
pub const DATA_TYPE_GUID: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
pub const EFI_TYPE_GUID: &str = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
pub const BIOS_TYPE_GUID: &str = "21686148-6449-6e6f-744e-656564454649";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Partition {
    pub number: u32,
    pub name: String,
    pub type_guid: String,
    pub start_lba: u64,
    pub end_lba: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Layout {
    pub size_bytes: u64,
    pub logical_sector_size: u64,
    pub total_sectors: u64,
    pub first_usable_lba: u64,
    pub last_usable_lba: u64,
    pub legacy: bool,
    pub partitions: Vec<Partition>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LayoutError {
    #[error("logical sector size must be 512 or 4096 bytes")]
    InvalidSector,
    #[error("legacy BIOS layout is unsupported on 4Kn")]
    Legacy4Kn,
    #[error("image size must fit a signed file offset and contain whole logical sectors")]
    InvalidSize,
    #[error("image is too small for GPT, boot slots, and at least 1 MiB of data")]
    TooSmall,
    #[error("layout differs from the supported plan")]
    NonCanonical,
}

pub fn plan(
    size_bytes: u64,
    logical_sector_size: u64,
    legacy: bool,
) -> Result<Layout, LayoutError> {
    if ![512, 4096].contains(&logical_sector_size) {
        return Err(LayoutError::InvalidSector);
    }
    if legacy && logical_sector_size == 4096 {
        return Err(LayoutError::Legacy4Kn);
    }
    if size_bytes == 0
        || size_bytes > i64::MAX as u64
        || !size_bytes.is_multiple_of(logical_sector_size)
    {
        return Err(LayoutError::InvalidSize);
    }
    let total_sectors = size_bytes / logical_sector_size;
    let entries = u64::from(ENTRY_COUNT) * u64::from(ENTRY_SIZE) / logical_sector_size;
    if total_sectors < 2 * entries + 4 {
        return Err(LayoutError::TooSmall);
    }
    let first_usable_lba = 2 + entries;
    let last_usable_lba = total_sectors - entries - 2;
    let alignment = MIB / logical_sector_size;
    let start = first_usable_lba.div_ceil(alignment) * alignment;
    let end = (last_usable_lba + 1) / alignment * alignment;
    let boot = (if logical_sector_size == 4096 { 512 } else { 64 }) * MIB / logical_sector_size;
    let reserved = 2 * boot + if legacy { alignment } else { 0 };
    if end < start || end - start < reserved + alignment {
        return Err(LayoutError::TooSmall);
    }
    let a = end - reserved;
    let b = a + boot;
    let partition = |number, name: &str, type_guid: &str, start_lba, end_lba| Partition {
        number,
        name: name.into(),
        type_guid: type_guid.into(),
        start_lba,
        end_lba,
    };
    let mut partitions = vec![
        partition(1, "ISOHOPPER", DATA_TYPE_GUID, start, a - 1),
        partition(2, "ISOHOPPER-A", EFI_TYPE_GUID, a, b - 1),
        partition(3, "ISOHOPPER-B", EFI_TYPE_GUID, b, b + boot - 1),
    ];
    if legacy {
        partitions.push(partition(4, "BIOS-BOOT", BIOS_TYPE_GUID, b + boot, end - 1));
    }
    Ok(Layout {
        size_bytes,
        logical_sector_size,
        total_sectors,
        first_usable_lba,
        last_usable_lba,
        legacy,
        partitions,
    })
}

/// Accept only canonical geometry. Public fields cannot bypass writer bounds.
pub fn validate(value: &Layout) -> Result<(), LayoutError> {
    if *value == plan(value.size_bytes, value.logical_sector_size, value.legacy)? {
        Ok(())
    } else {
        Err(LayoutError::NonCanonical)
    }
}
