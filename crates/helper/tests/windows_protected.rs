// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::{windows_protected::ProtectedError, windows_sources::SourceError};
#[cfg(windows)]
use isohopper_helper::{
    windows_protected::{self, ImageRole},
    windows_sources::SourceExtent,
    writer::{DeviceSnapshot, Geometry},
};
use std::io;
#[cfg(windows)]
use std::{
    fs::{File, OpenOptions},
    mem::{offset_of, size_of},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
#[cfg(windows)]
use windows_sys::Win32::{
    Storage::FileSystem::{
        FILE_SHARE_READ, FILE_SHARE_WRITE, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{DISK_EXTENT, VOLUME_DISK_EXTENTS},
    },
};

#[cfg(windows)]
fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Independently decode the SDK layout instead of reusing production parsing.
// The only handles opened are volume GUIDs returned by the protected mapping.
#[cfg(windows)]
fn independent_extents(guid: &str) -> io::Result<Vec<(u32, u64, u64)>> {
    let volume = OpenOptions::new()
        .read(true)
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(
            guid.strip_suffix('\\')
                .ok_or_else(|| invalid("missing GUID suffix"))?,
        )?;
    let mut words = [0u64; 193];
    let mut returned = 0;
    // SAFETY: live synchronous metadata-only volume and bounded aligned output.
    let success = unsafe {
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
    };
    if success == 0 {
        return Err(io::Error::last_os_error());
    }
    if returned as usize > size_of_val(&words)
        || (returned as usize) < size_of::<VOLUME_DISK_EXTENTS>()
    {
        return Err(invalid("invalid independent extent response length"));
    }
    // SAFETY: aligned initialized integer-only output, with its prefix checked.
    let header = unsafe { &*words.as_ptr().cast::<VOLUME_DISK_EXTENTS>() };
    let count = header.NumberOfDiskExtents as usize;
    if !(1..=64).contains(&count)
        || returned as usize
            != offset_of!(VOLUME_DISK_EXTENTS, Extents) + count * size_of::<DISK_EXTENT>()
    {
        return Err(invalid("invalid independent extent count"));
    }
    // SAFETY: each initialized integer-only entry lies in checked returned bytes.
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
    let mut result = Vec::new();
    for entry in entries {
        if entry.StartingOffset < 0 || entry.ExtentLength <= 0 {
            return Err(invalid("invalid independent extent geometry"));
        }
        result.push((
            entry.DiskNumber,
            entry.StartingOffset as u64,
            entry.ExtentLength as u64,
        ));
    }
    result.sort();
    Ok(result)
}

#[cfg(windows)]
fn compare_extents(guid: &str, extents: &[SourceExtent]) -> io::Result<()> {
    let mut observed = extents
        .iter()
        .map(|e| (e.disk_number, e.start_offset, e.length_bytes))
        .collect::<Vec<_>>();
    observed.sort();
    if observed != independent_extents(guid)? {
        return Err(invalid(
            "protected and independently queried volume extents differ",
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn synthetic_target() -> DeviceSnapshot {
    // No target handle is opened. This intentionally synthetic nonmatching
    // number exercises mapping, not real target authentication or preparation.
    DeviceSnapshot {
        device_number: u32::MAX,
        serial: "synthetic-read-only-observation-target".into(),
        device_id: None,
        bus_type: 0,
        geometry: Geometry {
            size_bytes: 64 * 1024 * 1024,
            logical_sector_size: 512,
            physical_sector_size: 512,
        },
    }
}

// Return a fixed filesystem class, never arbitrary driver-supplied text. The
// native buffer is MAX_PATH + 1 WCHARs as required by the volume API.
fn filesystem_label(units: &[u16]) -> Result<&'static str, &'static str> {
    if units.len() > 261 {
        return Err("oversized_filesystem_name");
    }
    let end = units
        .iter()
        .position(|&unit| unit == 0)
        .filter(|&end| end > 0)
        .ok_or("invalid_filesystem_name")?;
    let name = String::from_utf16(&units[..end]).map_err(|_| "invalid_filesystem_encoding")?;
    Ok(match name.as_str() {
        "NTFS" => "NTFS",
        "ReFS" => "ReFS",
        "FAT" => "FAT",
        "FAT32" => "FAT32",
        "exFAT" => "exFAT",
        "UDF" => "UDF",
        "CDFS" => "CDFS",
        "CSVFS" => "CSVFS",
        _ => "other",
    })
}

fn wof_observation(hresult: i32, version: u32) -> serde_json::Value {
    serde_json::json!({
        "status": if hresult >= 0 { "ok" } else { "error" },
        "hresult": hresult as u32,
        "version": (hresult >= 0).then_some(version),
    })
}

// Test-only observations: never serialized, and never used by production to
// authorize a source. Access time is excluded because observation can affect it.
#[derive(Clone, PartialEq, Eq)]
struct ReopenSnapshot {
    volume: u64,
    id: [u8; 16],
    bytes: i64,
    allocated: i64,
    created: i64,
    written: i64,
    changed: i64,
    attributes: u32,
    links: u32,
    delete_pending: bool,
    directory: bool,
}

impl ReopenSnapshot {
    fn fixture() -> Self {
        Self {
            volume: 1,
            id: [1; 16],
            bytes: 1,
            allocated: 4096,
            created: 1,
            written: 1,
            changed: 1,
            attributes: 0,
            links: 1,
            delete_pending: false,
            directory: false,
        }
    }
}

fn diagnostic_error(stage: &'static str, error: &io::Error) -> serde_json::Value {
    serde_json::json!({
        "status":"error", "stage":stage,
        "win32_error":error.raw_os_error().map(|code| code as u32),
        "mapping_remains_blocked":true,
    })
}

fn compare_reopened(
    before: &ReopenSnapshot,
    mut snapshot: impl FnMut(bool) -> io::Result<ReopenSnapshot>,
    mut query: impl FnMut(bool) -> serde_json::Value,
) -> serde_json::Value {
    let mut result = serde_json::json!({
        "status":"observed", "mapping_remains_blocked":true,
        "identity_matches":true, "sentinels_match":true,
    });
    for stage in ["before_query", "after_query"] {
        for reopened in [true, false] {
            let observed = match snapshot(reopened) {
                Ok(value) => value,
                Err(error) => return diagnostic_error(stage, &error),
            };
            if &observed != before {
                result["status"] = "changed".into();
                result["stage"] = stage.into();
                result["identity_matches"] =
                    (observed.volume == before.volume && observed.id == before.id).into();
                result["sentinels_match"] = false.into();
                return result;
            }
        }
        if stage == "before_query" {
            result["original"] = query(false);
            result["reopened"] = query(true);
        }
    }
    result
}

fn backing_result(
    status: Result<(), Option<u32>>,
    returned: u32,
    bytes: &[u8; 256],
) -> serde_json::Value {
    if let Err(code) = status {
        // No output field, including byte count, is evidence after failure.
        return serde_json::json!({"status":"error", "win32_error":code});
    }
    if !(8..=256).contains(&returned) {
        return serde_json::json!({"status":"invalid", "returned_bytes":returned});
    }
    serde_json::json!({
        "status":"success", "returned_bytes":returned,
        "version":u32::from_le_bytes(bytes[..4].try_into().unwrap()),
        "provider":u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
    })
}

#[cfg(windows)]
fn reopen_snapshot(file: &File) -> io::Result<ReopenSnapshot> {
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_BASIC_INFO, FILE_ID_INFO, FILE_STANDARD_INFO, FileBasicInfo, FileIdInfo,
        FileStandardInfo, GetFileInformationByHandleEx,
    };
    let mut id = FILE_ID_INFO::default();
    let mut basic = FILE_BASIC_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    for (class, output, length) in [
        (
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>(),
        ),
        (
            FileBasicInfo,
            (&mut basic as *mut FILE_BASIC_INFO).cast(),
            size_of::<FILE_BASIC_INFO>(),
        ),
        (
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>(),
        ),
    ] {
        // SAFETY: live retained file and initialized, correctly typed SDK
        // output for each exact class/size. These are synchronous metadata reads.
        if unsafe {
            GetFileInformationByHandleEx(file.as_raw_handle(), class, output, length as u32)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    if standard.EndOfFile < 0 || standard.AllocationSize < 0 || standard.Directory {
        return Err(invalid("unsupported reopened file metadata"));
    }
    Ok(ReopenSnapshot {
        volume: id.VolumeSerialNumber,
        id: id.FileId.Identifier,
        bytes: standard.EndOfFile,
        allocated: standard.AllocationSize,
        created: basic.CreationTime,
        written: basic.LastWriteTime,
        changed: basic.ChangeTime,
        attributes: basic.FileAttributes,
        links: standard.NumberOfLinks,
        delete_pending: standard.DeletePending,
        directory: standard.Directory,
    })
}

#[cfg(windows)]
fn reopened_backing_diagnostic(original: &File) -> serde_json::Value {
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::{
        Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{FILE_FLAG_OPEN_REPARSE_POINT, ReOpenFile},
        System::Ioctl::FSCTL_GET_EXTERNAL_BACKING,
    };
    let before = match reopen_snapshot(original) {
        Ok(value) => value,
        Err(error) => return diagnostic_error("initial_metadata", &error),
    };
    // SAFETY: original is a retained synchronous File::open object. ReOpenFile
    // acts on that object, never a pathname. Request only read access, share
    // read, and no OVERLAPPED flag, so both later FSCTL calls are synchronous.
    // This flag is documented as ignored when the file is not a reparse point.
    // https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-reopenfile
    let raw = unsafe {
        ReOpenFile(
            original.as_raw_handle(),
            GENERIC_READ,
            FILE_SHARE_READ,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return diagnostic_error("reopen", &io::Error::last_os_error());
    }
    if raw.is_null() {
        return diagnostic_error("reopen", &invalid("invalid reopened handle"));
    }
    // SAFETY: successful ReOpenFile transfers one new owned file handle.
    let reopened = unsafe { File::from_raw_handle(raw) };
    let handle = |is_reopened| if is_reopened { &reopened } else { original };
    compare_reopened(
        &before,
        |which| reopen_snapshot(handle(which)),
        |which| {
            let mut bytes = [0u8; 256];
            let mut returned = 0;
            // SAFETY: both handles are live synchronous files. Bounded initialized
            // output and count remain live through completion; no input is supplied.
            let status = unsafe {
                DeviceIoControl(
                    handle(which).as_raw_handle(),
                    FSCTL_GET_EXTERNAL_BACKING,
                    ptr::null(),
                    0,
                    bytes.as_mut_ptr().cast(),
                    bytes.len() as u32,
                    &mut returned,
                    ptr::null_mut(),
                )
            };
            let status = if status != 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error()
                    .raw_os_error()
                    .map(|code| code as u32))
            };
            backing_result(status, returned, &bytes)
        },
    )
}

#[cfg(windows)]
fn backing_diagnostic(role: ImageRole, retained: Result<&File, &io::Error>) -> serde_json::Value {
    use serde_json::json;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle, GetVolumeInformationByHandleW,
        WOF_PROVIDER_FILE, WOF_PROVIDER_WIM, WofGetDriverVersion,
    };

    // Fixed keys, labels and bounded numeric fields only. Do not request volume
    // names or serials, and do not serialize file IDs, pathnames or OS messages.
    let mut result = json!({
        "event": "protected_external_backing",
        "role": match role { ImageRole::Helper => "helper", ImageRole::Caller => "caller" },
        "external_backing_win32": 1,
        "retained_handle": { "status": "ok" },
        "filesystem": { "status": "not_queried" },
        "file": { "status": "not_queried" },
        "wof_wim": { "status": "not_queried" },
        "wof_file": { "status": "not_queried" },
        "same_object_reopen": { "status": "not_queried" },
    });
    let file = match retained {
        Ok(file) => file,
        Err(error) => {
            result["retained_handle"] = json!({
                "status": "unsupported", "win32_error": error.raw_os_error().map(|code| code as u32),
            });
            return result;
        }
    };

    let mut filesystem = [0u16; 261];
    let mut flags = 0;
    let mut component_length = 0;
    // SAFETY: this duplicate retains the exact synchronous readable file object
    // used by the failed binding. All output pointers are live, correctly typed
    // and bounded. Null name/serial outputs deliberately omit private metadata.
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getvolumeinformationbyhandlew
    let volume_ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut component_length,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    result["filesystem"] = if volume_ok != 0 {
        match filesystem_label(&filesystem) {
            Ok(name) => json!({
                "status": "ok", "name": name, "flags": flags,
                "maximum_component_length": component_length,
            }),
            Err(reason) => json!({ "status": "invalid", "reason": reason }),
        }
    } else {
        let error = io::Error::last_os_error();
        json!({ "status": "error", "win32_error": error.raw_os_error().map(|code| code as u32) })
    };

    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: same retained file and a live initialized SDK output structure.
    // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandle
    let file_ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut information) };
    result["file"] = if file_ok != 0 {
        json!({ "status": "ok", "attributes": information.dwFileAttributes })
    } else {
        let error = io::Error::last_os_error();
        json!({ "status": "error", "win32_error": error.raw_os_error().map(|code| code as u32) })
    };

    for (key, provider) in [
        ("wof_wim", WOF_PROVIDER_WIM),
        ("wof_file", WOF_PROVIDER_FILE),
    ] {
        let mut version = 0;
        // SAFETY: documented read-only version query accepts a file handle;
        // the retained file and typed version output live throughout the call.
        // An absent provider returns an HRESULT, never negative backing proof.
        // https://learn.microsoft.com/en-us/windows/win32/api/wofapi/nf-wofapi-wofgetdriverversion
        let status = unsafe { WofGetDriverVersion(file.as_raw_handle(), provider, &mut version) };
        result[key] = wof_observation(status, version);
    }
    result["same_object_reopen"] = reopened_backing_diagnostic(file);
    result
}

#[test]
fn backing_diagnostic_classifies_filesystems_without_printing_untrusted_names() {
    for name in [
        "NTFS", "ReFS", "FAT", "FAT32", "exFAT", "UDF", "CDFS", "CSVFS",
    ] {
        let units: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        assert_eq!(filesystem_label(&units).unwrap(), name);
    }
    for name in ["private-path", "C:\\private", "unknown\nname", "🦀"] {
        let units: Vec<_> = name.encode_utf16().chain(Some(0)).collect();
        assert_eq!(filesystem_label(&units).unwrap(), "other");
    }
    for units in [vec![], vec![0], vec![b'N' as u16], vec![0xd800, 0]] {
        assert!(filesystem_label(&units).is_err());
    }
    let mut maximum = vec![b'X' as u16; 260];
    maximum.push(0);
    assert_eq!(filesystem_label(&maximum).unwrap(), "other");
    maximum.push(0);
    assert_eq!(filesystem_label(&maximum), Err("oversized_filesystem_name"));
}

#[test]
fn backing_diagnostic_preserves_hresult_and_never_reports_failed_output_as_version() {
    let failure = wof_observation(0x8007_0001u32 as i32, u32::MAX);
    assert_eq!(failure["status"], "error");
    assert_eq!(failure["hresult"], 0x8007_0001u32);
    assert_eq!(failure["version"], serde_json::Value::Null);
    let success = wof_observation(0, 0x0a00_1234);
    assert_eq!(success["status"], "ok");
    assert_eq!(success["hresult"], 0);
    assert_eq!(success["version"], 0x0a00_1234);
    assert!(failure.to_string().len() < 128);
    assert!(success.to_string().len() < 128);
}

#[test]
fn reopened_diagnostic_refuses_changed_identity_or_sentinels_before_queries() {
    let before = ReopenSnapshot::fixture();
    for changed in [
        ReopenSnapshot {
            volume: 2,
            ..before.clone()
        },
        ReopenSnapshot {
            id: [2; 16],
            ..before.clone()
        },
        ReopenSnapshot {
            bytes: 2,
            ..before.clone()
        },
        ReopenSnapshot {
            changed: 2,
            ..before.clone()
        },
    ] {
        let mut queries = 0;
        let result = compare_reopened(
            &before,
            |_| Ok(changed.clone()),
            |_| {
                queries += 1;
                serde_json::Value::Null
            },
        );
        assert_eq!(result["status"], "changed");
        assert_eq!(result["stage"], "before_query");
        assert_eq!(queries, 0);
    }
}

#[test]
fn reopened_diagnostic_checks_both_handles_after_observing_backing() {
    let before = ReopenSnapshot::fixture();
    let mut snapshots = 0;
    let mut queried = Vec::new();
    let result = compare_reopened(
        &before,
        |_| {
            snapshots += 1;
            Ok(ReopenSnapshot {
                bytes: if snapshots == 4 { 2 } else { before.bytes },
                ..before.clone()
            })
        },
        |reopened| {
            queried.push(reopened);
            serde_json::json!({"status":"error", "win32_error":1})
        },
    );
    assert_eq!(queried, [false, true]);
    assert_eq!(result["status"], "changed");
    assert_eq!(result["stage"], "after_query");
    assert_eq!(result["mapping_remains_blocked"], true);

    let stable = compare_reopened(
        &before,
        |_| Ok(before.clone()),
        |reopened| backing_result(Err(Some(if reopened { 342 } else { 1 })), 0, &[0; 256]),
    );
    assert_eq!(stable["status"], "observed");
    assert_eq!(stable["original"]["win32_error"], 1);
    assert_eq!(stable["reopened"]["win32_error"], 342);
    assert_eq!(stable["mapping_remains_blocked"], true);
    assert!(stable.to_string().len() < 512);
}

#[test]
fn backing_result_ignores_failed_output_and_bounds_successful_prefix() {
    let failed = backing_result(Err(Some(1)), u32::MAX, &[255; 256]);
    assert_eq!(
        failed,
        serde_json::json!({"status":"error", "win32_error":1})
    );
    let explicit_negative = backing_result(Err(Some(342)), 256, &[255; 256]);
    assert_eq!(explicit_negative["win32_error"], 342);
    for returned in [0, 7, 257, u32::MAX] {
        assert_eq!(
            backing_result(Ok(()), returned, &[0; 256])["status"],
            "invalid"
        );
    }
    let mut bytes = [0; 256];
    bytes[..8].copy_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0]);
    let success = backing_result(Ok(()), 8, &bytes);
    assert_eq!(success["version"], 1);
    assert_eq!(success["provider"], 2);
    assert!(success.to_string().len() < 128);
}

fn unsupported_external_backing(error: &ProtectedError) -> bool {
    matches!(
        error,
        ProtectedError::Source(SourceError::Io { stage, source })
            if *stage == "source external backing" && source.raw_os_error() == Some(1)
    )
}

#[test]
fn protected_smoke_only_classifies_exact_unsupported_external_backing() {
    let error = |stage, code| {
        ProtectedError::Source(SourceError::Io {
            stage,
            source: io::Error::from_raw_os_error(code),
        })
    };
    assert!(unsupported_external_backing(&error(
        "source external backing",
        1
    )));
    for code in [5, 32, 50, 342] {
        assert!(!unsupported_external_backing(&error(
            "source external backing",
            code
        )));
    }
    assert!(!unsupported_external_backing(&error(
        "source backing dependencies",
        1
    )));
    assert!(!unsupported_external_backing(&ProtectedError::Io {
        stage: "source external backing",
        source: io::Error::from_raw_os_error(1),
    }));
    assert!(!unsupported_external_backing(&ProtectedError::Source(
        SourceError::ExternalBacking
    )));
}

#[cfg(windows)]
#[test]
#[ignore = "read-only mapping of the actual Windows directory and current test executable; no physical writes"]
fn windows_protected_system_and_executable_mappings_are_read_only()
-> Result<(), Box<dyn std::error::Error>> {
    let target = synthetic_target();
    let system = windows_protected::bind_system_directory(&target)?;
    compare_extents(system.volume_guid(), system.extents())?;
    system.revalidate(&target)?;
    let mut changed = target.clone();
    changed.serial.push_str("-changed");
    if !matches!(system.revalidate(&changed), Err(ProtectedError::Changed)) {
        return Err(invalid("changed candidate evidence was accepted").into());
    }
    let mut overlapping = target.clone();
    overlapping.device_number = system.extents()[0].disk_number;
    match windows_protected::bind_system_directory(&overlapping) {
        Err(ProtectedError::Source(SourceError::OnTarget { extents }))
            if extents
                .iter()
                .any(|extent| extent.disk_number == overlapping.device_number) => {}
        Err(error) => {
            return Err(format!("system overlap did not reach explicit refusal: {error}").into());
        }
        Ok(_) => return Err(invalid("actual system-volume disk was accepted").into()),
    }
    let mut mapped = 1;
    let mut overlap_refusals = 1;
    let mut unsupported = 0;

    // current_exe locates a read-only fixture. It is not an authentication
    // mechanism: production must supply independently authenticated handles.
    let image_path = std::env::current_exe()?;
    for role in [ImageRole::Helper, ImageRole::Caller] {
        let image = File::open(&image_path)?;
        // Duplicate the existing file object before bind_file takes ownership.
        // A clone error affects diagnostics only, not the original test result.
        // No pathname is reopened to diagnose a failed binding.
        let diagnostic_image = image.try_clone();
        // SAFETY: File::open is readable and synchronous without OVERLAPPED.
        let binding = match unsafe { windows_protected::bind_file(role, image, &target) } {
            Ok(binding) => binding,
            Err(error) if unsupported_external_backing(&error) => {
                // FSCTL_GET_EXTERNAL_BACKING documents INVALID_DEVICE_REQUEST
                // for an absent or stopped backing service, not proof that the
                // file has no external backing. Characterize this runner's
                // unsupported query; production still rejects the binding.
                // https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/fsctl-get-external-backing
                println!(
                    "UNSUPPORTED executable role={role:?}: external-backing query returned Win32 1; mapping remains blocked"
                );
                println!(
                    "PROTECTED_BACKING_DIAGNOSTIC {}",
                    backing_diagnostic(role, diagnostic_image.as_ref())
                );
                unsupported += 1;
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        compare_extents(binding.volume_guid(), binding.extents())?;
        binding.revalidate(&target)?;
        if !matches!(
            binding.revalidate(&changed),
            Err(ProtectedError::Source(SourceError::Changed))
        ) {
            return Err(invalid("changed executable candidate evidence was accepted").into());
        }
        let mut overlapping = target.clone();
        overlapping.device_number = binding.extents()[0].disk_number;
        let image = File::open(&image_path)?;
        // SAFETY: same known synchronous readable File::open construction.
        match unsafe { windows_protected::bind_file(role, image, &overlapping) } {
            Err(ProtectedError::Source(SourceError::OnTarget { extents }))
                if extents
                    .iter()
                    .any(|extent| extent.disk_number == overlapping.device_number) => {}
            Err(error) => {
                return Err(
                    format!("executable overlap did not reach explicit refusal: {error}").into(),
                );
            }
            Ok(_) => return Err(invalid("actual executable-volume disk was accepted").into()),
        }
        mapped += 1;
        overlap_refusals += 1;
    }
    println!(
        "Protected storage observations: successful_mappings={mapped}, actual_volume_overlap_refusals={overlap_refusals}, unsupported_executable_roles={unsupported}"
    );
    Ok(())
}
