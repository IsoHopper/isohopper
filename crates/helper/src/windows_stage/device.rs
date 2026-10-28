// SPDX-License-Identifier: GPL-3.0-or-later
//! Private device views always borrow the owner of a newly created VHD.
use super::super::build_policy::SelectedVolume;
use super::*;
use crate::{
    windows_identity::{DiskIdentity, query_identity},
    windows_lock::{TargetCoverage, TargetVolumeProbe},
    writer::{
        DeviceSnapshot,
        windows::{WindowsRawDevice, inspect},
    },
};
use cap_std::fs::Dir;
use std::{ffi::OsString, os::windows::ffi::OsStringExt};
use windows_sys::Win32::{
    Foundation::{ERROR_WRITE_PROTECT, GENERIC_READ, GENERIC_WRITE},
    Storage::FileSystem::{
        FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH, FlushFileBuffers, GetDiskFreeSpaceExW,
        GetDiskFreeSpaceW, GetFinalPathNameByHandleW, GetVolumeInformationByHandleW,
        GetVolumePathNamesForVolumeNameW, VOLUME_NAME_GUID,
    },
    System::{IO::DeviceIoControl, Ioctl::IOCTL_DISK_IS_WRITABLE},
};

pub(super) fn context(stage: &'static str, e: impl std::fmt::Display) -> StageError {
    error(stage, io::Error::other(e.to_string()))
}
fn physical(owner: &OwnedStageDisk) -> Result<(PathBuf, u32), StageError> {
    if !owner.attached {
        return Err(StageError::Invalid("VHD is not attached"));
    }
    let mut output = [0u16; 260];
    let mut bytes = size_of_val(&output) as u32;
    // SAFETY: the owner retains this attached VHD; output size is in bytes.
    status("owned VHD device path", unsafe {
        GetVirtualDiskPhysicalPath(
            owner
                .disk
                .as_ref()
                .ok_or(StageError::Invalid("closed VHD"))?
                .as_raw_handle(),
            &mut bytes,
            output.as_mut_ptr(),
        )
    })?;
    if bytes as usize > size_of_val(&output) || !bytes.is_multiple_of(2) {
        return Err(StageError::Invalid("VHD path length"));
    }
    let end = output[..bytes as usize / 2]
        .iter()
        .position(|c| *c == 0)
        .ok_or(StageError::Invalid("unterminated VHD path"))?;
    let value =
        String::from_utf16(&output[..end]).map_err(|_| StageError::Invalid("VHD path encoding"))?;
    let number = value
        .strip_prefix(r"\\.\PhysicalDrive")
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse().ok())
        .ok_or(StageError::Invalid("unexpected owned VHD path"))?;
    Ok((PathBuf::from(OsString::from_wide(&output[..end])), number))
}
pub(super) struct View<'a> {
    owner: &'a OwnedStageDisk,
    pub(super) file: File,
    metadata: OwnedHandle,
    pub(super) snapshot: DeviceSnapshot,
    identity: DiskIdentity,
    path: PathBuf,
}
impl<'a> View<'a> {
    pub(super) fn open(owner: &'a OwnedStageDisk) -> Result<Self, StageError> {
        owner.revalidate()?;
        let (path, number) = physical(owner)?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&path)
            .map_err(|e| error("open owned virtual device", e))?;
        // SAFETY: this private synchronous file was opened from the retained VHD.
        let metadata: OwnedHandle = file
            .try_clone()
            .map_err(|e| error("retain VHD metadata", e))?
            .into();
        let snapshot =
            unsafe { inspect(&metadata) }.map_err(|e| error("inspect owned virtual device", e))?;
        let identity =
            unsafe { query_identity(&file) }.map_err(|e| context("owned VHD identity", e))?;
        if snapshot.geometry != owner.geometry
            || snapshot.device_number != number
            || identity.device_number() != number
            || snapshot.bus_type != 15
        {
            return Err(StageError::Invalid("owned virtual device geometry or kind"));
        }
        let view = Self {
            owner,
            file,
            metadata,
            snapshot,
            identity,
            path,
        };
        view.check()?;
        Ok(view)
    }
    pub(super) fn check(&self) -> Result<(), StageError> {
        self.owner.revalidate()?;
        if physical(self.owner)? != (self.path.clone(), self.snapshot.device_number) {
            return Err(StageError::Invalid("owned VHD device path changed"));
        }
        // SAFETY: synchronous live handle stays borrowed with its VHD owner.
        if unsafe { inspect(&self.metadata) }.map_err(|e| error("recheck owned VHD", e))?
            != self.snapshot
            || unsafe { query_identity(&self.file) }
                .map_err(|e| context("recheck owned VHD identity", e))?
                != self.identity
        {
            return Err(StageError::Invalid("owned VHD changed"));
        }
        Ok(())
    }
    pub(super) fn same_disk(
        &self,
        other: &DeviceSnapshot,
        identity: &DiskIdentity,
    ) -> Result<(), StageError> {
        if self.snapshot.geometry != other.geometry
            || self.snapshot.serial != other.serial
            || self.snapshot.device_id != other.device_id
            || self.snapshot.bus_type != other.bus_type
            || self.identity.device_guid() != identity.device_guid()
            || self.identity.origin() != identity.origin()
        {
            return Err(StageError::Invalid(
                "owned VHD identity changed on reattachment",
            ));
        }
        Ok(())
    }
    pub(super) fn facts(&self) -> (DeviceSnapshot, DiskIdentity) {
        (self.snapshot.clone(), self.identity.clone())
    }
    pub(super) fn coverage(&self) -> Result<TargetCoverage, StageError> {
        self.check()?;
        let file = self
            .file
            .try_clone()
            .map_err(|e| error("retain VHD coverage", e))?;
        // SAFETY: duplicated synchronous read-only handle to this same owned disk.
        let mut probe =
            unsafe { TargetVolumeProbe::from_owned_handle(file.into(), &self.snapshot) }
                .map_err(|e| context("owned VHD coverage", e))?;
        let value = probe
            .revalidate()
            .map_err(|e| context("recheck VHD coverage", e))?
            .clone();
        self.check()?;
        Ok(value)
    }
    pub(super) fn writer(&self) -> Result<WindowsRawDevice, StageError> {
        self.check()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH)
            .open(&self.path)
            .map_err(|e| error("open owned VHD writer", e))?;
        // SAFETY: private synchronous unbuffered write-through handle for a NEW
        // owned VHD. Caller verified RAW/empty layout, so no filesystem locks exist.
        let device = unsafe { WindowsRawDevice::from_owned_handle(file.into()) }
            .map_err(|e| error("validate owned VHD writer", e))?;
        if device.initial_snapshot() != &self.snapshot {
            return Err(StageError::Invalid("owned VHD writer differs"));
        }
        self.check()?;
        Ok(device)
    }
    pub(super) fn read_only(&self) -> Result<(), StageError> {
        self.check()?;
        let mut returned = 0;
        // SAFETY: synchronous read-only status IOCTL with no payload buffers.
        let ok = unsafe {
            DeviceIoControl(
                self.file.as_raw_handle(),
                IOCTL_DISK_IS_WRITABLE,
                ptr::null(),
                0,
                ptr::null_mut(),
                0,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok != 0 || io::Error::last_os_error().raw_os_error() != Some(ERROR_WRITE_PROTECT as i32)
        {
            return Err(StageError::Invalid("VHD is not explicitly write protected"));
        }
        Ok(())
    }
}
pub(super) fn no_mounts(data: &SelectedVolume) -> Result<(), StageError> {
    let name: Vec<_> = data.guid.encode_utf16().chain(Some(0)).collect();
    let mut buffer = [0u16; 1024];
    let mut size = 0;
    // SAFETY: validated canonical GUID, bounded initialized output.
    if unsafe {
        GetVolumePathNamesForVolumeNameW(
            name.as_ptr(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            &mut size,
        )
    } == 0
    {
        return Err(error(
            "check owned volume mount paths",
            io::Error::last_os_error(),
        ));
    }
    if size == 0 || size as usize > buffer.len() || buffer[0] != 0 {
        return Err(StageError::Invalid("owned volume has mount paths"));
    }
    Ok(())
}
pub(super) fn root(data: &SelectedVolume) -> Result<Dir, StageError> {
    no_mounts(data)?;
    let root = Dir::open_ambient_dir(&data.guid, cap_std::ambient_authority())
        .map_err(|e| error("open owned data root", e))?;
    let mut path = [0u16; 64];
    // SAFETY: synchronous metadata query on the retained root and fixed output.
    let n = unsafe {
        GetFinalPathNameByHandleW(
            root.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            VOLUME_NAME_GUID,
        )
    } as usize;
    if n == 0
        || n >= path.len()
        || !String::from_utf16(&path[..n])
            .map_err(|_| StageError::Invalid("root GUID encoding"))?
            .eq_ignore_ascii_case(&data.guid)
    {
        return Err(StageError::Invalid("owned root GUID differs"));
    }
    let mut fs = [0u16; 32];
    if unsafe {
        GetVolumeInformationByHandleW(
            root.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    } == 0
    {
        return Err(error("owned data filesystem", io::Error::last_os_error()));
    }
    let end = fs
        .iter()
        .position(|c| *c == 0)
        .ok_or(StageError::Invalid("filesystem name length"))?;
    if String::from_utf16_lossy(&fs[..end]) != "exFAT" {
        return Err(StageError::Invalid("owned data is not exFAT"));
    }
    Ok(root)
}
pub(super) fn space(path: &Path) -> Result<u64, StageError> {
    let path = wide(path)?;
    let mut free = 0;
    // SAFETY: protected or validated owned-volume path; only u64 free output.
    if unsafe { GetDiskFreeSpaceExW(path.as_ptr(), &mut free, ptr::null_mut(), ptr::null_mut()) }
        == 0
    {
        return Err(error("stage available space", io::Error::last_os_error()));
    }
    Ok(free)
}
pub(super) fn data_space(data: &SelectedVolume) -> Result<(u64, u64), StageError> {
    let path: Vec<_> = data.guid.encode_utf16().chain(Some(0)).collect();
    let (mut sectors, mut bytes, mut free, mut total) = (0, 0, 0, 0);
    // SAFETY: canonical own-volume GUID and four writable DWORD outputs.
    if unsafe {
        GetDiskFreeSpaceW(
            path.as_ptr(),
            &mut sectors,
            &mut bytes,
            &mut free,
            &mut total,
        )
    } == 0
    {
        return Err(error("data allocation unit", io::Error::last_os_error()));
    }
    let unit = u64::from(sectors) * u64::from(bytes);
    if unit != u64::from(data.allocation_unit) {
        return Err(StageError::Invalid("data allocation unit differs"));
    }
    Ok((space(Path::new(&data.guid))?, unit))
}
pub(super) fn flush(data: &SelectedVolume) -> Result<(), StageError> {
    let file = OpenOptions::new()
        .access_mode(GENERIC_READ | GENERIC_WRITE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&data.guid[..data.guid.len() - 1])
        .map_err(|e| error("open data volume for flush", e))?;
    // SAFETY: synchronous handle to the freshly formatted owned data volume.
    if unsafe { FlushFileBuffers(file.as_raw_handle()) } == 0 {
        return Err(error("flush owned data volume", io::Error::last_os_error()));
    }
    Ok(())
}
