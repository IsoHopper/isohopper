// SPDX-License-Identifier: GPL-3.0-or-later
//! Characterization only: an observed metadata handle is not a production
//! pagefile-exclusion capability. No file contents or paging settings are read
//! or changed. No result from this test enables physical preparation.
#![cfg(windows)]

use isohopper_inventory::windows_pagefiles;
use std::{
    collections::BTreeMap,
    fmt,
    fs::{File, OpenOptions},
    io,
    mem::{offset_of, size_of},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION},
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_TYPE_DISK, GetFileInformationByHandle, GetFileType, GetFinalPathNameByHandleW,
        IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, VOLUME_NAME_GUID,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{DISK_EXTENT, VOLUME_DISK_EXTENTS},
    },
};

// Never retain OS text or observed paths in an error: test runners print Debug.
#[derive(Debug)]
struct ProbeError {
    stage: &'static str,
    win32: Option<i32>,
}
impl fmt::Display for ProbeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "stage={}, Win32={:?}", self.stage, self.win32)
    }
}
impl std::error::Error for ProbeError {}
type ProbeResult<T> = Result<T, ProbeError>;

fn invalid(stage: &'static str) -> ProbeError {
    ProbeError { stage, win32: None }
}
fn os_error(stage: &'static str, error: io::Error) -> ProbeError {
    ProbeError {
        stage,
        win32: error.raw_os_error(),
    }
}

#[derive(PartialEq, Eq)]
struct FileIdentity {
    volume_serial: u32,
    index: u64,
    created: u64,
}

fn identity(file: &File) -> ProbeResult<FileIdentity> {
    // SAFETY: this test owns live synchronous handles and typed output storage.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(invalid("pagefile file type"));
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(os_error("pagefile metadata", io::Error::last_os_error()));
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(invalid("pagefile directory or reparse attributes"));
    }
    // Active paging may change length/write time. These fields are only
    // identity change sentinels, not an assertion of immutable pagefile bytes.
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        index: u64::from(info.nFileIndexLow) | (u64::from(info.nFileIndexHigh) << 32),
        created: u64::from(info.ftCreationTime.dwLowDateTime)
            | (u64::from(info.ftCreationTime.dwHighDateTime) << 32),
    })
}

fn volume_guid(file: &File) -> ProbeResult<String> {
    let mut units = vec![u16::MAX; 32_768];
    // SAFETY: live retained file and bounded writable UTF-16 buffer.
    let count = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            units.as_mut_ptr(),
            units.len() as u32,
            VOLUME_NAME_GUID,
        )
    } as usize;
    if count == 0 {
        return Err(os_error(
            "pagefile final GUID path",
            io::Error::last_os_error(),
        ));
    }
    if count >= units.len() || units[count] != 0 || units[..count].contains(&0) {
        return Err(invalid("pagefile final GUID path bounds"));
    }
    let path =
        String::from_utf16(&units[..count]).map_err(|_| invalid("pagefile path encoding"))?;
    let suffix = path
        .strip_prefix(r"\\?\Volume{")
        .ok_or_else(|| invalid("pagefile canonical GUID prefix"))?;
    let guid = suffix
        .get(..36)
        .ok_or_else(|| invalid("pagefile GUID length"))?;
    let relative = suffix
        .get(36..)
        .and_then(|s| s.strip_prefix("}\\"))
        .ok_or_else(|| invalid("pagefile GUID boundary"))?;
    if !guid.bytes().enumerate().all(|(index, byte)| {
        if [8, 13, 18, 23].contains(&index) {
            byte == b'-'
        } else {
            byte.is_ascii_hexdigit()
        }
    }) || relative.is_empty()
        || relative.contains(['/', ':', '<', '>', '|', '?', '*', '"'])
        || relative.chars().any(char::is_control)
        || relative
            .split('\\')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
    {
        return Err(invalid("pagefile canonical GUID path"));
    }
    Ok(format!(r"\\?\Volume{{{}}}\", guid.to_ascii_lowercase()))
}

fn extents(volume: &File) -> ProbeResult<Vec<(u32, i64, i64)>> {
    // Aligned space for the SDK prefix plus at most 64 DISK_EXTENT records.
    let mut words = [0u64; 193];
    let mut returned = 0;
    // SAFETY: retained synchronous volume, no input, bounded writable output.
    if unsafe {
        DeviceIoControl(
            volume.as_raw_handle(),
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            ptr::null(),
            0,
            words.as_mut_ptr().cast(),
            size_of_val(&words) as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(os_error(
            "pagefile volume extents",
            io::Error::last_os_error(),
        ));
    }
    if (returned as usize) < size_of::<VOLUME_DISK_EXTENTS>()
        || returned as usize > size_of_val(&words)
    {
        return Err(invalid("pagefile extent response bounds"));
    }
    // SAFETY: aligned initialized integer-only prefix within returned bytes.
    let header = unsafe { &*words.as_ptr().cast::<VOLUME_DISK_EXTENTS>() };
    let count = header.NumberOfDiskExtents as usize;
    if !(1..=64).contains(&count)
        || returned as usize
            != offset_of!(VOLUME_DISK_EXTENTS, Extents) + count * size_of::<DISK_EXTENT>()
    {
        return Err(invalid("pagefile extent count"));
    }
    // SAFETY: complete aligned SDK entries fit inside checked returned bytes.
    let entries = unsafe {
        std::slice::from_raw_parts(
            words
                .as_ptr()
                .cast::<u8>()
                .add(offset_of!(VOLUME_DISK_EXTENTS, Extents))
                .cast::<DISK_EXTENT>(),
            count,
        )
    };
    let mut result = Vec::with_capacity(count);
    for entry in entries {
        if entry.StartingOffset < 0
            || entry.ExtentLength <= 0
            || entry
                .StartingOffset
                .checked_add(entry.ExtentLength)
                .is_none()
            || entry.DiskNumber == u32::MAX
        {
            return Err(invalid("pagefile extent geometry"));
        }
        result.push((entry.DiskNumber, entry.StartingOffset, entry.ExtentLength));
    }
    result.sort();
    if result
        .windows(2)
        .any(|p| p[0].0 == p[1].0 && p[0].1 + p[0].2 > p[1].1)
    {
        return Err(invalid("pagefile overlapping extents"));
    }
    Ok(result)
}

struct RetainedObservation {
    file: File,
    volume: File,
    identity: FileIdentity,
    guid: String,
    extents: Vec<(u32, i64, i64)>,
}
impl RetainedObservation {
    fn check(&self) -> ProbeResult<()> {
        if identity(&self.file)? != self.identity
            || volume_guid(&self.file)? != self.guid
            || extents(&self.volume)? != self.extents
        {
            return Err(invalid("pagefile retained mapping changed"));
        }
        Ok(())
    }
}

#[test]
#[ignore = "characterizes zero-access handles to active pagefiles; metadata only, no paging changes or content reads"]
fn windows_active_pagefile_zero_access_metadata_probe() -> ProbeResult<()> {
    let before =
        windows_pagefiles::collect().map_err(|_| invalid("active pagefile enumeration"))?;
    let mut retained = Vec::new();
    let mut refusals = BTreeMap::<i32, usize>::new();
    for pagefile in &before.pagefiles {
        // Collector supplies strictly validated local absolute names. Access
        // zero requests no file data. Sharing all access avoids restricting the
        // active paging file; OPEN_REPARSE_POINT prevents a final link fallback.
        let file = match OpenOptions::new()
            .read(true)
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&pagefile.path)
        {
            Ok(file) => file,
            Err(error)
                if error.raw_os_error().is_some_and(|code| {
                    code == ERROR_ACCESS_DENIED as i32 || code == ERROR_SHARING_VIOLATION as i32
                }) =>
            {
                *refusals.entry(error.raw_os_error().unwrap()).or_default() += 1;
                continue;
            }
            Err(error) => return Err(os_error("open active pagefile", error)),
        };
        let file_identity = identity(&file)?;
        let guid = volume_guid(&file)?;
        let volume = OpenOptions::new()
            .read(true)
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&guid[..guid.len() - 1])
            .map_err(|error| os_error("open pagefile volume", error))?;
        let observed_extents = extents(&volume)?;
        let observation = RetainedObservation {
            file,
            volume,
            identity: file_identity,
            guid,
            extents: observed_extents,
        };
        observation.check()?;
        retained.push(observation);
    }
    // Keep every successful file/volume handle open across the second query.
    let after =
        windows_pagefiles::collect().map_err(|_| invalid("repeat active pagefile enumeration"))?;
    if before != after {
        return Err(invalid("active pagefile names changed"));
    }
    for observation in &retained {
        observation.check()?;
    }
    if before.pagefiles.is_empty() {
        println!("UNSUPPORTED: no active pagefiles observed; zero handle mappings verified");
    } else if !refusals.is_empty() {
        for (code, count) in refusals {
            println!("UNSUPPORTED: stage=open active pagefile, Win32={code}, count={count}");
        }
        println!(
            "Observed {} active pagefiles; {} metadata mappings queried; complete pagefile mapping remains unsupported",
            before.pagefiles.len(),
            retained.len()
        );
    } else {
        println!(
            "OBSERVED: {} active pagefile metadata handles, GUIDs and extents remained consistent; no production exclusion or backing-ancestry claim",
            retained.len()
        );
    }
    Ok(())
}
