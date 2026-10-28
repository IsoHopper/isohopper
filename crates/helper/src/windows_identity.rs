// SPDX-License-Identifier: GPL-3.0-or-later
//! Hardware-derived Windows device identity observations from retained handles.
//! Equality is useful evidence for correlating two live disk handles, not proof
//! of target authorization, complete storage safety, or trustworthy hardware.
//! Requery before relying on a prior observation. Device numbers are not durable
//! identities across boots. A GUID is not a disk path, pool ID, or GPT disk GUID.
//!
//! Layout, GUID provenance, and flags:
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_device_number_ex>
//! The query is supported starting with Windows 10:
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ni-ntddstor-ioctl_storage_get_device_number_ex>
use serde::Serialize;
use std::io;

const DESCRIPTOR_BYTES: usize = 40;
const FILE_DEVICE_DISK: u32 = 7;
const RANDOM_CONFLICT: u32 = 1;
const RANDOM_NO_HARDWARE_ID: u32 = 2;
const PAGE_83: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityOrigin {
    /// Windows derives the GUID from vendor/product/serial information.
    VendorProductSerial,
    /// Windows derives the GUID from SCSI page 83 identity information.
    Page83,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiskIdentity {
    device_number: u32,
    /// Native GUID memory order; not a VPD identifier or GPT disk GUID.
    device_guid: [u8; 16],
    origin: IdentityOrigin,
}

impl DiskIdentity {
    pub fn device_number(&self) -> u32 {
        self.device_number
    }
    pub fn device_guid(&self) -> &[u8; 16] {
        &self.device_guid
    }
    pub fn origin(&self) -> IdentityOrigin {
        self.origin
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("invalid Windows device identity descriptor: {0}")]
    InvalidDescriptor(&'static str),
    #[error("unsupported Windows device identity descriptor: {0}")]
    UnsupportedDescriptor(&'static str),
    #[error(
        "device GUID is random because hardware identity is absent or conflicting (flags {flags})"
    )]
    RandomGuid { flags: u32 },
    #[error("device has no GUID")]
    MissingGuid,
    #[error("identity does not describe a disk device")]
    NotDisk,
    #[error("identity does not describe a whole disk")]
    NotWholeDisk,
    #[error("MPIO physical-path identity is unsupported")]
    MpioPath,
    #[error("Windows device identity query failed: {0}")]
    Query(#[source] io::Error),
}

/// Parse the current STORAGE_DEVICE_NUMBER_EX wire layout. This validates
/// bytes only; callers must separately establish their origin and freshness.
/// This intentionally supports only whole disks with PartitionNumber zero.
/// The documented -1 case for nonpartitionable devices is not accepted.
pub fn parse_identity(bytes: &[u8]) -> Result<DiskIdentity, IdentityError> {
    if bytes.len() != DESCRIPTOR_BYTES {
        return Err(IdentityError::InvalidDescriptor("returned byte count"));
    }
    let word = |offset| {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    };
    if word(0) != DESCRIPTOR_BYTES as u32 {
        return Err(IdentityError::UnsupportedDescriptor("structure version"));
    }
    if word(4) != DESCRIPTOR_BYTES as u32 {
        return Err(IdentityError::InvalidDescriptor("structure size"));
    }
    let flags = word(8);
    if flags & !(RANDOM_CONFLICT | RANDOM_NO_HARDWARE_ID | PAGE_83) != 0 {
        return Err(IdentityError::UnsupportedDescriptor("unknown flags"));
    }
    if flags & (RANDOM_CONFLICT | RANDOM_NO_HARDWARE_ID) != 0 {
        return Err(IdentityError::RandomGuid { flags });
    }
    if word(12) != FILE_DEVICE_DISK {
        return Err(IdentityError::NotDisk);
    }
    let device_number = word(16);
    if device_number == u32::MAX {
        return Err(IdentityError::MpioPath);
    }
    if word(36) != 0 {
        return Err(IdentityError::NotWholeDisk);
    }
    let mut device_guid = [0; 16];
    device_guid.copy_from_slice(&bytes[20..36]);
    if device_guid == [0; 16] {
        return Err(IdentityError::MissingGuid);
    }
    Ok(DiskIdentity {
        device_number,
        device_guid,
        origin: if flags & PAGE_83 != 0 {
            IdentityOrigin::Page83
        } else {
            IdentityOrigin::VendorProductSerial
        },
    })
}

/// Observe a caller-retained disk handle without opening paths or changing
/// device state. The file stays borrowed and must remain open for revalidation.
/// An OS error is preserved; unsupported queries never become missing-but-safe
/// identities. A successful result does not authorize writes or establish pool
/// membership, system exclusion, device lock state, or physical rather than
/// virtual storage.
///
/// # Safety
/// `file` must use synchronous I/O: it must not have FILE_FLAG_OVERLAPPED. This
/// function passes a null OVERLAPPED and uses a stack buffer which is valid only
/// until the synchronous DeviceIoControl call returns.
#[cfg(windows)]
pub unsafe fn query_identity(file: &std::fs::File) -> Result<DiskIdentity, IdentityError> {
    use std::{
        mem::{offset_of, size_of},
        os::windows::io::AsRawHandle,
        ptr,
    };
    use windows_sys::Win32::System::{
        IO::DeviceIoControl,
        Ioctl::{IOCTL_STORAGE_GET_DEVICE_NUMBER_EX, STORAGE_DEVICE_NUMBER_EX},
    };

    // Match the SDK's C layout explicitly instead of casting an unaligned byte
    // buffer or silently reinterpreting a future platform-specific structure.
    const {
        assert!(size_of::<STORAGE_DEVICE_NUMBER_EX>() == DESCRIPTOR_BYTES);
        assert!(offset_of!(STORAGE_DEVICE_NUMBER_EX, Version) == 0);
        assert!(offset_of!(STORAGE_DEVICE_NUMBER_EX, Size) == 4);
        assert!(offset_of!(STORAGE_DEVICE_NUMBER_EX, Flags) == 8);
        assert!(offset_of!(STORAGE_DEVICE_NUMBER_EX, DeviceType) == 12);
        assert!(offset_of!(STORAGE_DEVICE_NUMBER_EX, DeviceNumber) == 16);
        assert!(offset_of!(STORAGE_DEVICE_NUMBER_EX, DeviceGuid) == 20);
        assert!(offset_of!(STORAGE_DEVICE_NUMBER_EX, PartitionNumber) == 36);
    }
    let mut bytes = [0; DESCRIPTOR_BYTES];
    let mut returned = 0;
    // SAFETY: the borrowed File retains the live handle. The caller guarantees
    // synchronous I/O; the output buffer and byte-count pointer remain valid
    // for the entire call, and their capacities match the supplied sizes.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            IOCTL_STORAGE_GET_DEVICE_NUMBER_EX,
            ptr::null(),
            0,
            bytes.as_mut_ptr().cast(),
            DESCRIPTOR_BYTES as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(IdentityError::Query(io::Error::last_os_error()));
    }
    if returned as usize != bytes.len() {
        return Err(IdentityError::InvalidDescriptor("returned byte count"));
    }
    parse_identity(&bytes)
}
