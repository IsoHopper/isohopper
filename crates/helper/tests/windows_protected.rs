// SPDX-License-Identifier: GPL-3.0-or-later
#![cfg(windows)]

use isohopper_helper::{
    windows_protected::{self, ImageRole, ProtectedError},
    windows_sources::{SourceError, SourceExtent},
    writer::{DeviceSnapshot, Geometry},
};
use std::{
    fs::{File, OpenOptions},
    io,
    mem::{offset_of, size_of},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        FILE_SHARE_READ, FILE_SHARE_WRITE, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{DISK_EXTENT, VOLUME_DISK_EXTENTS},
    },
};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

// Independently decode the SDK layout instead of reusing production parsing.
// The only handles opened are volume GUIDs returned by the protected mapping.
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
