// SPDX-License-Identifier: GPL-3.0-or-later
use super::{
    LockError,
    state::{self, Backend, DiskLayout, Extent, Held, Volume, VolumeName},
};
use crate::writer::{DeviceSnapshot, RetainedDevice, windows::WindowsRawDevice};
use std::{
    fs::{File, OpenOptions},
    io,
    mem::{offset_of, size_of},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        FILE_DEVICE_CD_ROM, FILE_SHARE_READ, FILE_SHARE_WRITE, FindFirstVolumeW, FindNextVolumeW,
        FindVolumeClose, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{
            DISK_EXTENT, DRIVE_LAYOUT_INFORMATION_EX, FSCTL_DISMOUNT_VOLUME, FSCTL_LOCK_VOLUME,
            FSCTL_UNLOCK_VOLUME, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, IOCTL_STORAGE_GET_DEVICE_NUMBER,
            PARTITION_INFORMATION_EX, STORAGE_DEVICE_NUMBER, VOLUME_DISK_EXTENTS,
        },
    },
};

// Wire parsers use these documented Windows ABI offsets and never create Rust
// bools or references from untrusted bytes returned by a storage driver.
const _: () = {
    assert!(size_of::<DISK_EXTENT>() == 24);
    assert!(offset_of!(DISK_EXTENT, StartingOffset) == 8);
    assert!(offset_of!(DISK_EXTENT, ExtentLength) == 16);
    assert!(offset_of!(VOLUME_DISK_EXTENTS, Extents) == 8);
    assert!(size_of::<PARTITION_INFORMATION_EX>() == 144);
    assert!(offset_of!(PARTITION_INFORMATION_EX, Anonymous) == 32);
    assert!(offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry) == 48);
};

/// A retained raw device and the volume locks acquired for its current layout.
///
/// This is not an authorization token or proof that all disk safety checks are
/// complete. The caller must still coordinate arrival/removal events and bind
/// the approved device, source and operation. No handle extraction or explicit
/// unlock operation is exposed; dropping this owner closes the raw device first.
pub struct LockedWindowsDevice {
    device: WindowsRawDevice,
    volumes: Vec<Held<NativeVolume>>,
}

impl LockedWindowsDevice {
    pub fn locked_volume_count(&self) -> usize {
        self.volumes.len()
    }
}

/// Acquire all discoverable target volume locks or return no capability.
///
/// This never elevates, opens a physical-device path, or forces a dismount after
/// a failed lock. Every volume path comes from bounded Windows enumeration.
/// Unknown classifications and unsupported layouts fail closed. Synchronous
/// driver calls have no user-space deadline; a stalled driver can block here.
/// Every nonempty partition requires an exact classified volume except GPT
/// BIOS Boot and Microsoft Reserved partitions. MBR extended and dynamic-disk
/// layouts are unsupported; unenumerated hidden or unknown partitions fail.
pub fn lock(
    mut device: WindowsRawDevice,
    expected: &DeviceSnapshot,
) -> Result<LockedWindowsDevice, LockError> {
    let volumes = state::acquire(
        &mut Native {
            device: &mut device,
        },
        expected,
    )?;
    Ok(LockedWindowsDevice { device, volumes })
}

impl RetainedDevice for LockedWindowsDevice {
    fn snapshot(&mut self) -> io::Result<DeviceSnapshot> {
        self.device.snapshot()
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.device.read_at(offset, buffer)
    }
    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> io::Result<usize> {
        self.device.write_at(offset, buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.device.flush()
    }
}

fn io_error(stage: &'static str, source: io::Error) -> LockError {
    LockError::Io { stage, source }
}

fn query(
    handle: HANDLE,
    code: u32,
    capacity: usize,
    stage: &'static str,
) -> Result<Vec<u8>, LockError> {
    let mut output = vec![0; capacity];
    let mut returned = 0;
    // SAFETY: all callers hold the synchronous device/volume handle live; the
    // initialized writable buffer has the advertised bounded capacity. These
    // read-only IOCTLs accept no input or asynchronous OVERLAPPED state.
    if unsafe {
        DeviceIoControl(
            handle,
            code,
            ptr::null(),
            0,
            output.as_mut_ptr().cast(),
            capacity as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io_error(stage, io::Error::last_os_error()));
    }
    if returned as usize > capacity {
        return Err(LockError::MissingEvidence("oversized IOCTL result"));
    }
    output.truncate(returned as usize);
    Ok(output)
}

struct Native<'a> {
    device: &'a mut WindowsRawDevice,
}
impl Backend for Native<'_> {
    type Volume = NativeVolume;
    fn snapshot(&mut self) -> Result<DeviceSnapshot, LockError> {
        self.device
            .snapshot()
            .map_err(|e| io_error("device revalidation", e))
    }
    fn layout(&mut self) -> Result<DiskLayout, LockError> {
        let bytes = query(
            self.device.retained_handle().as_raw_handle(),
            IOCTL_DISK_GET_DRIVE_LAYOUT_EX,
            48 + state::MAX_PARTITIONS * 144,
            "whole-device partition layout",
        )?;
        state::parse_layout(&bytes, &self.device.initial_snapshot().geometry)
    }
    fn enumerate(&mut self) -> Result<Vec<VolumeName>, LockError> {
        enumerate()
    }
    fn open(&mut self, name: &VolumeName, write: bool) -> Result<NativeVolume, LockError> {
        // Remove only the final backslash from the validated GUID path. Keeping
        // it would open the root directory rather than the volume device.
        let mut options = OpenOptions::new();
        options
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE);
        if write {
            options.write(true);
        } else {
            options.access_mode(0);
        }
        let file = options
            .open(&name.0[..name.0.len() - 1])
            .map_err(|e| io_error("open enumerated volume", e))?;
        Ok(NativeVolume {
            file,
            locked: false,
        })
    }
}

struct NativeVolume {
    file: File,
    locked: bool,
}
impl NativeVolume {
    fn control(&self, code: u32, stage: &'static str) -> Result<(), LockError> {
        let mut returned = 0;
        // SAFETY: live synchronous volume handle; these operations use no input
        // or output buffer. Lock ownership stays with this exact file object.
        if unsafe {
            DeviceIoControl(
                self.file.as_raw_handle(),
                code,
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io_error(stage, io::Error::last_os_error()));
        }
        Ok(())
    }
}
impl Volume for NativeVolume {
    fn extents(&mut self) -> Result<Option<Vec<Extent>>, LockError> {
        match query(
            self.file.as_raw_handle(),
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            8 + state::MAX_EXTENTS * 24,
            "volume disk extents",
        ) {
            Ok(bytes) => state::parse_extents(&bytes).map(Some),
            Err(error) => {
                // A CD-ROM volume cannot belong to a writable disk target and
                // does not support disk extents. Skip only positive device-type
                // evidence, never an access error or a guessed drive letter.
                let number = query(
                    self.file.as_raw_handle(),
                    IOCTL_STORAGE_GET_DEVICE_NUMBER,
                    size_of::<STORAGE_DEVICE_NUMBER>(),
                    "classify non-disk volume",
                );
                if let Ok(number) = number
                    && number.len() == size_of::<STORAGE_DEVICE_NUMBER>()
                    && u32::from_le_bytes(number[..4].try_into().unwrap()) == FILE_DEVICE_CD_ROM
                {
                    return Ok(None);
                }
                Err(error)
            }
        }
    }
    fn lock(&mut self) -> Result<(), LockError> {
        self.control(FSCTL_LOCK_VOLUME, "lock target volume")?;
        self.locked = true;
        Ok(())
    }
    fn dismount(&mut self) -> Result<(), LockError> {
        if !self.locked {
            return Err(LockError::MissingEvidence(
                "dismount requires successful retained lock",
            ));
        }
        self.control(FSCTL_DISMOUNT_VOLUME, "dismount locked target volume")
    }
}
impl Drop for NativeVolume {
    fn drop(&mut self) {
        if self.locked {
            // Closing the file object also releases the lock if explicit
            // unlock fails (for example because the device was removed).
            let _ = self.control(FSCTL_UNLOCK_VOLUME, "release volume lock");
        }
    }
}

struct Enumeration(HANDLE);
impl Drop for Enumeration {
    fn drop(&mut self) {
        // SAFETY: this is only a successful FindFirstVolume search handle.
        unsafe {
            FindVolumeClose(self.0);
        }
    }
}
fn enumerate() -> Result<Vec<VolumeName>, LockError> {
    let mut buffer = [0u16; 64];
    // SAFETY: writable buffer has the advertised UTF-16 character capacity.
    let handle = unsafe { FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len() as u32) };
    if handle == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
            Ok(Vec::new())
        } else {
            Err(io_error("begin volume enumeration", error))
        };
    }
    let enumeration = Enumeration(handle);
    let mut result = Vec::new();
    loop {
        let end = buffer
            .iter()
            .position(|character| *character == 0)
            .ok_or(LockError::MissingEvidence("unterminated volume name"))?;
        let text = String::from_utf16(&buffer[..end])
            .map_err(|_| LockError::MissingEvidence("invalid volume name encoding"))?;
        result.push(VolumeName::parse(&text)?);
        if result.len() > state::MAX_VOLUMES {
            return Err(LockError::MissingEvidence("volume count limit"));
        }
        buffer.fill(0);
        // SAFETY: retained enumeration handle and live bounded output buffer.
        if unsafe { FindNextVolumeW(enumeration.0, buffer.as_mut_ptr(), buffer.len() as u32) } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                break;
            }
            return Err(io_error("continue volume enumeration", error));
        }
    }
    Ok(result)
}
