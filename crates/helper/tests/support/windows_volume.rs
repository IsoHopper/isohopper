// SPDX-License-Identifier: GPL-3.0-or-later
//! Independent read-only volume discovery for owned disposable VHD fixtures.
pub fn has_exact_data_range(
    plan: &isohopper_core::layout::Layout,
    ranges: &[(u64, u64)],
) -> std::io::Result<bool> {
    use std::{collections::BTreeSet, io};
    let invalid = || io::Error::other("unexpected or duplicate owned VHD volume extent");
    isohopper_core::layout::validate(plan).map_err(|_| invalid())?;
    let expected: BTreeSet<_> = plan
        .partitions
        .iter()
        .map(|p| {
            (
                p.start_lba * plan.logical_sector_size,
                (p.end_lba - p.start_lba + 1) * plan.logical_sector_size,
            )
        })
        .collect();
    let observed: BTreeSet<_> = ranges.iter().copied().collect();
    if observed.len() != ranges.len() || !observed.is_subset(&expected) {
        return Err(invalid());
    }
    let data = &plan.partitions[0];
    Ok(observed.contains(&(
        data.start_lba * plan.logical_sector_size,
        (data.end_lba - data.start_lba + 1) * plan.logical_sector_size,
    )))
}

pub fn volume_name(buffer: &[u16]) -> std::io::Result<String> {
    let invalid = |message| std::io::Error::new(std::io::ErrorKind::InvalidData, message);
    let end = buffer
        .iter()
        .position(|value| *value == 0)
        .ok_or_else(|| invalid("unterminated volume GUID"))?;
    let name =
        String::from_utf16(&buffer[..end]).map_err(|_| invalid("invalid volume GUID encoding"))?;
    let guid = name
        .strip_prefix(r"\\?\Volume{")
        .and_then(|s| s.strip_suffix("}\\"))
        .ok_or_else(|| invalid("invalid volume GUID path"))?;
    if guid.len() != 36
        || !guid.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(invalid("invalid volume GUID"));
    }
    // Volume APIs document the canonical Volume prefix. Normalize only the
    // GUID, matching production VolumeName, and retain the trailing backslash.
    Ok(format!(r"\\?\Volume{{{}}}\", guid.to_ascii_lowercase()))
}

#[cfg(windows)]
mod native {
    use super::volume_name;
    use crate::{lock_image, vhd_support};
    use isohopper_core::layout::Layout;
    use std::{
        collections::BTreeSet,
        fs::{File, OpenOptions},
        io::{self, Read, Seek},
        mem::{offset_of, size_of},
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        ptr, thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{ERROR_NO_MORE_FILES, HANDLE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            FILE_DEVICE_DISK, FILE_SHARE_READ, FILE_SHARE_WRITE, FindFirstVolumeW, FindNextVolumeW,
            FindVolumeClose, GetVolumeInformationW, GetVolumePathNamesForVolumeNameW,
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
        },
        System::{
            IO::DeviceIoControl,
            Ioctl::{
                DISK_EXTENT, IOCTL_STORAGE_GET_DEVICE_NUMBER, STORAGE_DEVICE_NUMBER,
                VOLUME_DISK_EXTENTS,
            },
        },
    };
    fn invalid(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, message)
    }

    fn checked(ok: i32, stage: &str) -> io::Result<()> {
        if ok == 0 {
            Err(vhd_support::context(stage, io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    struct Enumeration(HANDLE);
    impl Drop for Enumeration {
        fn drop(&mut self) {
            // SAFETY: the only constructor is successful FindFirstVolumeW.
            unsafe {
                FindVolumeClose(self.0);
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct Volume {
        pub name: String,
        pub start: u64,
        pub length: u64,
    }

    fn query(file: &File, code: u32, buffer: &mut [u8]) -> io::Result<usize> {
        let mut returned = 0;
        // SAFETY: live synchronous read-only handle and bounded writable
        // output; these discovery IOCTLs have no input or overlapped state.
        checked(
            unsafe {
                DeviceIoControl(
                    file.as_raw_handle(),
                    code,
                    ptr::null(),
                    0,
                    buffer.as_mut_ptr().cast(),
                    buffer.len() as u32,
                    &mut returned,
                    ptr::null_mut(),
                )
            },
            "test volume discovery",
        )?;
        if returned as usize > buffer.len() {
            return Err(invalid("oversized test volume discovery result"));
        }
        Ok(returned as usize)
    }

    fn inspect_volume(name: String, disk_number: u32) -> io::Result<Option<Volume>> {
        // Access zero permits metadata discovery without taking a filesystem
        // file handle. Only positive device-number evidence selects a volume.
        let file = OpenOptions::new()
            .read(true)
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&name[..name.len() - 1])?;
        let mut number = [0u8; size_of::<STORAGE_DEVICE_NUMBER>()];
        let count = match query(&file, IOCTL_STORAGE_GET_DEVICE_NUMBER, &mut number) {
            Ok(count) => count,
            // Unclassified volumes are never selected by this test discovery.
            // Production lock() independently applies its stricter full survey.
            Err(_) => return Ok(None),
        };
        if count != number.len() {
            return Err(invalid("truncated volume device number"));
        }
        let kind = u32::from_le_bytes(number[..4].try_into().unwrap());
        let actual_number = u32::from_le_bytes(number[4..8].try_into().unwrap());
        if kind != FILE_DEVICE_DISK || actual_number != disk_number {
            return Ok(None);
        }
        let mut extent = [0u8; 32];
        if query(&file, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, &mut extent)? != extent.len()
            || u32::from_le_bytes(extent[..4].try_into().unwrap()) != 1
            || u32::from_le_bytes(extent[8..12].try_into().unwrap()) != disk_number
        {
            return Err(invalid("owned VHD volume is not one exact disk extent"));
        }
        let start = u64::from_le_bytes(extent[16..24].try_into().unwrap());
        let length = u64::from_le_bytes(extent[24..32].try_into().unwrap());
        if length == 0 || start > lock_image::CAPACITY || length > lock_image::CAPACITY - start {
            return Err(invalid("owned VHD volume extent is outside capacity"));
        }
        Ok(Some(Volume {
            name,
            start,
            length,
        }))
    }

    /// Query actual volume extents independently of production source parsing.
    /// The SDK structure supplies offsets/widths, instead of the mapper's parser.
    pub fn volume_extents(name: &str) -> io::Result<Vec<(u32, u64, u64)>> {
        let wide: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        let name = volume_name(&wide)?;
        let file = OpenOptions::new()
            .read(true)
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&name[..name.len() - 1])?;
        let start = offset_of!(VOLUME_DISK_EXTENTS, Extents);
        let stride = size_of::<DISK_EXTENT>();
        let mut buffer = vec![0u8; start + 64 * stride];
        let returned = query(&file, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, &mut buffer)?;
        if returned < start {
            return Err(invalid("truncated independent volume extent header"));
        }
        let count = u32::from_le_bytes(buffer[..4].try_into().unwrap()) as usize;
        if count == 0 || count > 64 || returned != start + count * stride {
            return Err(invalid("invalid independent volume extent count or size"));
        }
        let mut extents = Vec::with_capacity(count);
        for index in 0..count {
            // SAFETY: the returned byte count covers a complete SDK structure;
            // read_unaligned avoids requiring alignment from the byte buffer.
            let extent = unsafe {
                buffer
                    .as_ptr()
                    .add(start + index * stride)
                    .cast::<DISK_EXTENT>()
                    .read_unaligned()
            };
            if extent.StartingOffset < 0
                || extent.ExtentLength <= 0
                || extent
                    .StartingOffset
                    .checked_add(extent.ExtentLength)
                    .is_none()
            {
                return Err(invalid("invalid independent volume extent range"));
            }
            extents.push((
                extent.DiskNumber,
                extent.StartingOffset as u64,
                extent.ExtentLength as u64,
            ));
        }
        extents.sort();
        Ok(extents)
    }

    fn enumerate(disk_number: u32) -> io::Result<Vec<Volume>> {
        let mut buffer = [0u16; 64];
        // SAFETY: live fixed output buffer of the advertised character count.
        let handle = unsafe { FindFirstVolumeW(buffer.as_mut_ptr(), buffer.len() as u32) };
        if handle == INVALID_HANDLE_VALUE {
            let error = io::Error::last_os_error();
            return if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                Ok(Vec::new())
            } else {
                Err(error)
            };
        }
        let owner = Enumeration(handle);
        let mut result = Vec::new();
        let mut names = BTreeSet::new();
        loop {
            let name = volume_name(&buffer)?;
            if names.len() == 1024 || !names.insert(name.clone()) {
                return Err(invalid("duplicate or excessive enumerated volume GUIDs"));
            }
            if let Some(volume) = inspect_volume(name, disk_number)? {
                result.push(volume);
            }
            buffer.fill(0);
            // SAFETY: retained enumeration handle and fixed live output buffer.
            if unsafe { FindNextVolumeW(owner.0, buffer.as_mut_ptr(), buffer.len() as u32) } == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
                    break;
                }
                return Err(error);
            }
        }
        result.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(result)
    }

    pub fn verify_filesystem(volume: &Volume) -> io::Result<()> {
        verify_filesystem_kind(volume, "FAT32")
    }

    /// Also rejects drive letters and mounted folders on the owned fixture.
    pub fn verify_filesystem_kind(volume: &Volume, expected: &str) -> io::Result<()> {
        verify_no_mount_paths(volume)?;
        let name: Vec<_> = volume.name.encode_utf16().chain(Some(0)).collect();
        let mut filesystem = [0u16; 32];
        // SAFETY: optional outputs are null; only this positively matched VHD
        // volume is probed for its filesystem. Buffer and path remain live.
        checked(
            unsafe {
                GetVolumeInformationW(
                    name.as_ptr(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    filesystem.as_mut_ptr(),
                    filesystem.len() as u32,
                )
            },
            "read owned VHD filesystem",
        )?;
        let end = filesystem
            .iter()
            .position(|c| *c == 0)
            .ok_or_else(|| invalid("unterminated filesystem name"))?;
        if String::from_utf16_lossy(&filesystem[..end]) != expected {
            return Err(invalid(
                "owned VHD volume mounted with an unexpected filesystem",
            ));
        }
        Ok(())
    }

    pub fn verify_no_mount_paths(volume: &Volume) -> io::Result<()> {
        let name: Vec<_> = volume.name.encode_utf16().chain(Some(0)).collect();
        let mut paths = [0u16; 1024];
        let mut returned = 0;
        // SAFETY: terminated GUID path and bounded output buffer remain live.
        checked(
            unsafe {
                GetVolumePathNamesForVolumeNameW(
                    name.as_ptr(),
                    paths.as_mut_ptr(),
                    paths.len() as u32,
                    &mut returned,
                )
            },
            "check owned VHD has no drive letters or mounted folders",
        )?;
        if returned == 0 || returned as usize > paths.len() || paths[0] != 0 {
            return Err(invalid("owned VHD unexpectedly has a mount path"));
        }
        Ok(())
    }

    pub fn open_payload(volume: &Volume) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(format!("{}EFI\\BOOT\\BOOTX64.EFI", volume.name))
    }

    pub fn verify_payload(file: &mut File) -> io::Result<()> {
        let expected = lock_image::payload();
        if file.metadata()?.len() != expected.len() as u64 {
            return Err(invalid("owned VHD payload has wrong length"));
        }
        file.rewind()?;
        let mut actual = vec![0; expected.len()];
        file.read_exact(&mut actual)?;
        if actual != expected || file.read(&mut [0])? != 0 {
            return Err(invalid("owned VHD payload bytes differ"));
        }
        file.rewind()?;
        Ok(())
    }

    pub fn wait_for_volumes(disk_number: u32, plan: &Layout) -> io::Result<Vec<Volume>> {
        let expected: BTreeSet<_> = plan.partitions[1..]
            .iter()
            .map(|p| (p.start_lba * 512, (p.end_lba - p.start_lba + 1) * 512))
            .collect();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let volumes = enumerate(disk_number)?;
            let ranges: BTreeSet<_> = volumes.iter().map(|v| (v.start, v.length)).collect();
            if ranges.iter().any(|range| !expected.contains(range)) || ranges.len() != volumes.len()
            {
                return Err(invalid("unexpected or duplicate owned VHD volume extent"));
            }
            if ranges == expected {
                for volume in &volumes {
                    verify_filesystem(volume)?;
                    verify_payload(&mut open_payload(volume)?)?;
                }
                return Ok(volumes);
            }
            if Instant::now() >= deadline {
                return Err(invalid(
                    "owned VHD's two expected volumes did not enumerate within 10 seconds",
                ));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    /// Select only the canonical basic-data partition, allowing the two ESPs
    /// to be enumerated or hidden. Every observed own-disk range must match the
    /// validated plan; no approximate range, duplicate or foreign range passes.
    pub fn wait_for_data_volume(disk_number: u32, plan: &Layout) -> io::Result<Volume> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let volumes = enumerate(disk_number)?;
            let ranges: Vec<_> = volumes.iter().map(|v| (v.start, v.length)).collect();
            if super::has_exact_data_range(plan, &ranges)? {
                return Ok(volumes
                    .into_iter()
                    .find(|v| v.start == plan.partitions[0].start_lba * plan.logical_sector_size)
                    .expect("validated exact data range"));
            }
            if Instant::now() >= deadline {
                return Err(invalid(
                    "owned VHD data volume did not enumerate within 10 seconds",
                ));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }
}

#[cfg(windows)]
#[allow(unused_imports)] // Individual integration binaries use different helpers.
pub use native::{
    Volume, open_payload, verify_filesystem, verify_filesystem_kind, verify_no_mount_paths,
    verify_payload, volume_extents, wait_for_data_volume, wait_for_volumes,
};
