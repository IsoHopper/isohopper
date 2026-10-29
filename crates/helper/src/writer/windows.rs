// SPDX-License-Identifier: GPL-3.0-or-later
//! Synchronous raw I/O through one caller-owned, already authorized handle.
use super::{DeviceSnapshot, Geometry, RetainedDevice, StableDeviceId, windows_metadata};
use windows_metadata::query_error;
#[path = "windows_readiness.rs"]
mod readiness;
use std::{
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::ERROR_WRITE_PROTECT,
    Storage::FileSystem::{
        FILE_BEGIN, FILE_DEVICE_DISK, FILE_TYPE_DISK, FlushFileBuffers, GetFileType, ReadFile,
        SetFilePointerEx, WriteFile,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{
            DISK_ATTRIBUTE_OFFLINE, DISK_ATTRIBUTE_READ_ONLY, GET_DISK_ATTRIBUTES,
            GET_LENGTH_INFORMATION, IOCTL_DISK_GET_DISK_ATTRIBUTES, IOCTL_DISK_GET_LENGTH_INFO,
            IOCTL_DISK_IS_WRITABLE, IOCTL_STORAGE_GET_DEVICE_NUMBER, IOCTL_STORAGE_QUERY_PROPERTY,
            PropertyExistsQuery, PropertyStandardQuery, STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR,
            STORAGE_DEVICE_NUMBER, STORAGE_PROPERTY_QUERY, StorageAccessAlignmentProperty,
            StorageDeviceIdProperty, StorageDeviceProperty,
        },
    },
};

const _: () = {
    assert!(size_of::<GET_DISK_ATTRIBUTES>() == readiness::ATTRIBUTES_BYTES);
    assert!(offset_of!(GET_DISK_ATTRIBUTES, Attributes) == 8);
    assert!(DISK_ATTRIBUTE_OFFLINE == 1);
    assert!(DISK_ATTRIBUTE_READ_ONLY == 2);
    assert!(ERROR_WRITE_PROTECT == 19);
};

/// Query disk attributes and writability without modifying media or flags.
///
/// A read-only file handle to a disk is sufficient. This does not establish
/// device identity, authorization, volume locks or full target safety. Unknown
/// status fails closed. The result is a point-in-time observation, not a lease.
///
/// # Safety
/// The file must contain a live disk handle opened synchronously, without
/// FILE_FLAG_OVERLAPPED. The query waits for completion before returning, so
/// a stalled driver can block it. No device path is accepted or reopened.
pub unsafe fn check_write_readiness(file: &File) -> io::Result<()> {
    handle_write_readiness(file)
}

fn handle_write_readiness(handle: &impl AsRawHandle) -> io::Result<()> {
    readiness::check(
        || {
            // Sentinel bytes cannot look like a valid empty attribute result
            // if a driver returns an incomplete structure as success.
            let mut bytes = [0xffu8; readiness::ATTRIBUTES_BYTES];
            let returned = control(
                handle,
                IOCTL_DISK_GET_DISK_ATTRIBUTES,
                None,
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )?;
            readiness::complete_attributes(bytes, returned)
        },
        || {
            let mut unused = 0;
            // SAFETY: the caller guarantees a synchronous live handle. This
            // read-only IOCTL accepts no input or output buffer. Win32 defines
            // lpBytesReturned as meaningless for an operation with no output,
            // so only the success status is evidence of current writability.
            if unsafe {
                DeviceIoControl(
                    handle.as_raw_handle(),
                    IOCTL_DISK_IS_WRITABLE,
                    ptr::null(),
                    0,
                    ptr::null_mut(),
                    0,
                    &mut unused,
                    ptr::null_mut(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        },
    )
}

pub struct WindowsRawDevice {
    handle: OwnedHandle,
    initial: DeviceSnapshot,
}

impl WindowsRawDevice {
    /// Take exclusive ownership of a retained whole-device handle.
    ///
    /// # Safety
    /// The handle must have been opened synchronously (no FILE_FLAG_OVERLAPPED),
    /// with GENERIC_READ | GENERIC_WRITE, FILE_FLAG_NO_BUFFERING and
    /// FILE_FLAG_WRITE_THROUGH. No duplicated handle may concurrently alter its
    /// file position or issue I/O. The caller must retain the required volume
    /// locks and finish independent target authorization before calling writes.
    /// This constructor checks metadata and current write readiness, not
    /// authorization or lock state.
    pub unsafe fn from_owned_handle(handle: OwnedHandle) -> io::Result<Self> {
        // SAFETY: OwnedHandle keeps the live handle valid for this call.
        if unsafe { GetFileType(handle.as_raw_handle()) } != FILE_TYPE_DISK {
            return Err(invalid("handle is not a disk device"));
        }
        // SAFETY: synchronous live device handle is required by this constructor.
        let initial = unsafe { inspect(&handle)? };
        initial
            .validate_identity()
            .map_err(|_| invalid("device has no hardware serial or supported NAA-6 device ID"))?;
        handle_write_readiness(&handle)?;
        Ok(Self { handle, initial })
    }

    pub fn initial_snapshot(&self) -> &DeviceSnapshot {
        &self.initial
    }

    /// Refresh the non-mutating readiness observation on this retained handle.
    /// This does not replace the caller's independent target safety checks.
    pub fn check_write_readiness(&self) -> io::Result<()> {
        handle_write_readiness(&self.handle)
    }

    pub(crate) fn retained_handle(&self) -> &OwnedHandle {
        &self.handle
    }

    fn position(&self, offset: u64, pointer: usize, length: usize) -> io::Result<()> {
        let geometry = &self.initial.geometry;
        geometry.check_io(offset, pointer, length)?;
        let mut actual = 0;
        // SAFETY: the retained handle is synchronous and uniquely used. Bounds
        // were checked against a geometry that fits signed Windows offsets.
        if unsafe {
            SetFilePointerEx(
                self.handle.as_raw_handle(),
                offset as i64,
                &mut actual,
                FILE_BEGIN,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if actual != offset as i64 {
            return Err(invalid("device seek returned a different offset"));
        }
        Ok(())
    }
}

impl RetainedDevice for WindowsRawDevice {
    fn snapshot(&mut self) -> io::Result<DeviceSnapshot> {
        // SAFETY: the owner preserves the constructor's synchronous-handle invariant.
        let snapshot = unsafe { inspect(&self.handle)? };
        self.check_write_readiness()?;
        Ok(snapshot)
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.position(offset, buffer.as_ptr() as usize, buffer.len())?;
        let mut count = 0;
        // SAFETY: the caller-owned slice is live and writable for the checked
        // length, alignment is checked, and this synchronous call finishes I/O
        // before returning. There are no other operations on this handle.
        if unsafe {
            ReadFile(
                self.handle.as_raw_handle(),
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                &mut count,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if count as usize > buffer.len() {
            return Err(invalid("invalid device read count"));
        }
        Ok(count as usize)
    }

    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> io::Result<usize> {
        // Recheck immediately before each bounded write so a long-running job
        // does not reuse its initial readiness. Three fixed-size/no-output
        // IOCTLs per <=1 MiB write trade throughput for prompt fail-closed refusal.
        // A later driver state change remains possible; WriteFile can still fail.
        self.check_write_readiness()?;
        self.position(offset, buffer.as_ptr() as usize, buffer.len())?;
        let mut count = 0;
        // SAFETY: the slice remains valid until synchronous I/O completes;
        // position() checked its alignment, length and device bounds.
        if unsafe {
            WriteFile(
                self.handle.as_raw_handle(),
                buffer.as_ptr(),
                buffer.len() as u32,
                &mut count,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if count as usize > buffer.len() {
            return Err(invalid("invalid device write count"));
        }
        Ok(count as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        // SAFETY: the owned handle is valid and no concurrent I/O is issued.
        if unsafe { FlushFileBuffers(self.handle.as_raw_handle()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn control(
    handle: &impl AsRawHandle,
    code: u32,
    query: Option<&STORAGE_PROPERTY_QUERY>,
    output: *mut core::ffi::c_void,
    length: usize,
) -> io::Result<usize> {
    let mut returned = 0;
    let (input, input_length) = query.map_or((ptr::null(), 0), |q| {
        (
            (q as *const STORAGE_PROPERTY_QUERY).cast(),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
        )
    });
    // SAFETY: all callers supply initialized input, a live correctly sized
    // writable output buffer and the same synchronous retained handle. The
    // constructor's synchronous-handle precondition also applies during inspect.
    if unsafe {
        DeviceIoControl(
            handle.as_raw_handle(),
            code,
            input,
            input_length,
            output,
            length as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned as usize > length {
        return Err(invalid("oversized device control result"));
    }
    Ok(returned as usize)
}

fn value<T: Default>(
    handle: &OwnedHandle,
    code: u32,
    query: Option<&STORAGE_PROPERTY_QUERY>,
) -> io::Result<T> {
    // Only the integer-only Windows structs below are used with this private
    // helper, so every bit pattern written by the driver is a valid Rust value.
    let mut output = T::default();
    if control(
        handle,
        code,
        query,
        (&mut output as *mut T).cast(),
        size_of::<T>(),
    )? != size_of::<T>()
    {
        return Err(invalid("truncated device control result"));
    }
    Ok(output)
}

/// Read device metadata without testing or changing writability.
///
/// # Safety
/// The handle must remain live and synchronous (no FILE_FLAG_OVERLAPPED).
pub(crate) unsafe fn inspect(handle: &OwnedHandle) -> io::Result<DeviceSnapshot> {
    let number: STORAGE_DEVICE_NUMBER = value(handle, IOCTL_STORAGE_GET_DEVICE_NUMBER, None)
        .map_err(|error| query_error("IOCTL_STORAGE_GET_DEVICE_NUMBER", error))?;
    if number.DeviceType != FILE_DEVICE_DISK || number.PartitionNumber != 0 {
        return Err(invalid(
            "handle must address a whole physical disk, not a partition",
        ));
    }
    let length: GET_LENGTH_INFORMATION = value(handle, IOCTL_DISK_GET_LENGTH_INFO, None)
        .map_err(|error| query_error("IOCTL_DISK_GET_LENGTH_INFO", error))?;
    let mut query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageAccessAlignmentProperty,
        QueryType: PropertyStandardQuery,
        ..Default::default()
    };
    let alignment: STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR =
        value(handle, IOCTL_STORAGE_QUERY_PROPERTY, Some(&query))
            .map_err(|error| query_error("StorageAccessAlignmentProperty", error))?;
    if alignment.Version as usize != size_of::<STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR>()
        || alignment.Size as usize != size_of::<STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR>()
        || alignment.BytesOffsetForSectorAlignment != 0
        || length.Length <= 0
    {
        return Err(invalid("unsupported device alignment descriptor"));
    }
    let geometry = Geometry {
        size_bytes: length.Length as u64,
        logical_sector_size: alignment.BytesPerLogicalSector,
        physical_sector_size: alignment.BytesPerPhysicalSector,
    };
    geometry
        .validate()
        .map_err(|_| invalid("unsupported device geometry"))?;
    query.PropertyId = StorageDeviceProperty;
    let mut header = [0u8; 8];
    if control(
        handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        Some(&query),
        header.as_mut_ptr().cast(),
        header.len(),
    )
    .map_err(|error| query_error("StorageDeviceProperty/header", error))?
        != header.len()
    {
        return Err(invalid("truncated storage descriptor header"));
    }
    let mut descriptor = vec![0u8; windows_metadata::descriptor_size(&header)?];
    let returned = control(
        handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        Some(&query),
        descriptor.as_mut_ptr().cast(),
        descriptor.len(),
    )
    .map_err(|error| query_error("StorageDeviceProperty/body", error))?;
    let (serial, bus_type) = windows_metadata::parse_descriptor(&descriptor[..returned])?;
    let device_id = inspect_device_id(handle)?;
    Ok(DeviceSnapshot {
        device_number: number.DeviceNumber,
        serial,
        device_id,
        bus_type,
        geometry,
    })
}

fn inspect_device_id(handle: &OwnedHandle) -> io::Result<Option<StableDeviceId>> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceIdProperty,
        QueryType: PropertyStandardQuery,
        ..Default::default()
    };
    let mut header = [0u8; 8];
    match control(
        handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        Some(&query),
        header.as_mut_ptr().cast(),
        header.len(),
    ) {
        // Some devices only expose a serial. Unsupported VPD83 is not a
        // substitute identity: the constructor still requires serial or ID,
        // and later snapshots compare any previously present ID as well.
        Err(error) => {
            windows_metadata::device_id_header_failure(error, || {
                device_id_property_exists(handle)
            })?;
            return Ok(None);
        }
        Ok(count) if count != header.len() => {
            return Err(invalid("truncated storage device ID descriptor header"));
        }
        Ok(_) => {}
    }
    let mut descriptor = vec![0u8; windows_metadata::id_descriptor_size(&header)?];
    let returned = control(
        handle,
        IOCTL_STORAGE_QUERY_PROPERTY,
        Some(&query),
        descriptor.as_mut_ptr().cast(),
        descriptor.len(),
    )
    .map_err(|error| query_error("StorageDeviceIdProperty/body", error))?;
    windows_metadata::parse_device_ids(&descriptor[..returned])
}

fn device_id_property_exists(handle: &OwnedHandle) -> io::Result<()> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceIdProperty,
        QueryType: PropertyExistsQuery,
        ..Default::default()
    };
    let mut unused = 0;
    // SAFETY: inspect retains this same synchronous handle and the initialized
    // query lives through the call. PropertyExistsQuery has no output buffer;
    // the success status, not lpBytesReturned, reports property support.
    // https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-storage_property_query
    if unsafe {
        DeviceIoControl(
            handle.as_raw_handle(),
            IOCTL_STORAGE_QUERY_PROPERTY,
            (&query as *const STORAGE_PROPERTY_QUERY).cast(),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            ptr::null_mut(),
            0,
            &mut unused,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
