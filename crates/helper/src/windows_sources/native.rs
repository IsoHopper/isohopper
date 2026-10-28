// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    windows_installation::{InstalledRole, MachineInstallation},
    writer::DeviceSnapshot,
};
use std::{
    fs::{File, OpenOptions},
    mem::{offset_of, size_of},
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    ptr,
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::ERROR_VIRTDISK_NOT_VIRTUAL_DISK,
    Storage::{
        FileSystem::{
            BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK, GetFileInformationByHandle,
            GetFileType, GetFinalPathNameByHandleW, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            VOLUME_NAME_GUID,
        },
        Vhd::{
            GET_STORAGE_DEPENDENCY_FLAG_HOST_VOLUMES, GetStorageDependencyInformation,
            STORAGE_DEPENDENCY_INFO, STORAGE_DEPENDENCY_INFO_TYPE_1,
        },
    },
    System::IO::DeviceIoControl,
};

const _: () = {
    assert!(offset_of!(STORAGE_DEPENDENCY_INFO, Anonymous) == 8);
    assert!(size_of::<STORAGE_DEPENDENCY_INFO_TYPE_1>() == 28);
    assert!(ERROR_VIRTDISK_NOT_VIRTUAL_DISK == 0xc03a0015);
};

fn io_error(stage: &'static str, source: io::Error) -> SourceError {
    SourceError::Io { stage, source }
}

// No caller-selectable bypass: only bind_installed_source can construct the
// installed mode, and its source is a duplicate of that owner's fixed image.
enum BackingCheck {
    FileControl,
    Installed {
        installation: Arc<MachineInstallation>,
        role: InstalledRole,
    },
}

impl BackingCheck {
    fn check(&self, source: &File) -> Result<(), SourceError> {
        match self {
            Self::FileControl => no_external_backing(source),
            Self::Installed { installation, role } => {
                installation
                    .require_inline_backing(*role)
                    .map_err(SourceError::InstalledBacking)?;
                if file_identity(source)? != file_identity(installation.image(*role))? {
                    return Err(SourceError::Changed);
                }
                Ok(())
            }
        }
    }
}

/// Owns the exact source and volume handles used for this mapping.
/// Records filesystem-reported extents after rejecting VHD/ISO and external
/// file backing. Storage Spaces/RAID ancestry remains the caller's preflight
/// responsibility. This does not authorize writes or verify source bytes.
pub struct SourceBinding {
    source: File,
    volume: File,
    mapping: Mapping,
    target: DeviceSnapshot,
    backing: BackingCheck,
}

impl SourceBinding {
    pub fn source_file(&self) -> &File {
        &self.source
    }
    pub fn volume_guid(&self) -> &str {
        &self.mapping.guid
    }
    pub fn extents(&self) -> &[SourceExtent] {
        &self.mapping.extents
    }

    /// Refreshes evidence using the retained handles. File-index and time
    /// metadata are change sentinels, not proof of immutable file contents.
    /// The caller must revalidate the actual target and hash source bytes.
    pub fn revalidate(&self, target: &DeviceSnapshot) -> Result<(), SourceError> {
        if *target != self.target {
            return Err(SourceError::Changed);
        }
        let actual = mapping(&self.source, &self.volume)?;
        unchanged(&self.mapping, &actual)?;
        reject_target(&actual.extents, target.device_number)?;
        // SAFETY: bind_source owns this synchronously opened volume handle.
        unsafe { no_virtual_dependencies(&self.volume)? };
        self.backing.check(&self.source)?;
        unchanged(&actual, &mapping(&self.source, &self.volume)?)
    }
}

/// `target` must be fresh evidence from the caller's retained target handle.
/// No target path is accepted or opened. The source remains owned until the
/// binding is dropped; callers must separately retain source write exclusion.
///
/// # Safety
/// `source` must hold a live, readable file handle opened synchronously, without
/// FILE_FLAG_OVERLAPPED. Its control queries use no OVERLAPPED structure and
/// wait for completion. The returned binding retains this handle invariant,
/// allowing subsequent calls to `SourceBinding::revalidate` to remain safe.
pub unsafe fn bind_source(
    source: File,
    target: &DeviceSnapshot,
) -> Result<SourceBinding, SourceError> {
    // SAFETY: unchanged synchronous source contract supplied by this caller.
    unsafe { bind(source, target, BackingCheck::FileControl) }
}

/// The only installed-source constructor duplicates a fixed retained image;
/// no caller handle, path, hash or alternate backing predicate is accepted.
pub(crate) fn bind_installed_source(
    installation: Arc<MachineInstallation>,
    role: InstalledRole,
    target: &DeviceSnapshot,
) -> Result<SourceBinding, SourceError> {
    installation
        .revalidate()
        .map_err(SourceError::InstalledBacking)?;
    let source = installation
        .image(role)
        .try_clone()
        .map_err(|e| io_error("retain installed source", e))?;
    // SAFETY: MachineInstallation opens this image synchronously read-only.
    // Duplicating that retained handle preserves its synchronous I/O mode.
    unsafe {
        bind(
            source,
            target,
            BackingCheck::Installed { installation, role },
        )
    }
}

// Caller establishes the same synchronous source invariant as bind_source.
unsafe fn bind(
    source: File,
    target: &DeviceSnapshot,
    backing: BackingCheck,
) -> Result<SourceBinding, SourceError> {
    target
        .geometry
        .validate()
        .map_err(|_| SourceError::Mapping("invalid target geometry"))?;
    let before = file_identity(&source)?;
    let guid = source_guid(&source)?;
    // Only a canonical GUID obtained from the retained source is opened.
    // Removing its final slash opens the volume, not its root directory.
    let volume = OpenOptions::new()
        .read(true)
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&guid[..guid.len() - 1])
        .map_err(|e| io_error("open source volume", e))?;
    let observed = mapping(&source, &volume)?;
    if observed.file != before || observed.guid != guid {
        return Err(SourceError::Changed);
    }
    reject_target(&observed.extents, target.device_number)?;
    // SAFETY: volume was opened synchronously above and remains live.
    unsafe { no_virtual_dependencies(&volume)? };
    backing.check(&source)?;
    unchanged(&observed, &mapping(&source, &volume)?)?;
    Ok(SourceBinding {
        source,
        volume,
        mapping: observed,
        target: target.clone(),
        backing,
    })
}

fn file_identity(file: &File) -> Result<FileIdentity, SourceError> {
    // SAFETY: File retains the live handle and output is a typed writable
    // integer-only structure; neither call changes file data or position.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK
        || !file
            .metadata()
            .map_err(|e| io_error("source metadata", e))?
            .is_file()
    {
        return Err(SourceError::NotRegularFile);
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io_error("source identity", io::Error::last_os_error()));
    }
    if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(SourceError::Mapping(
            "directory or reparse-backed source is unsupported",
        ));
    }
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        length: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        last_write: (u64::from(info.ftLastWriteTime.dwHighDateTime) << 32)
            | u64::from(info.ftLastWriteTime.dwLowDateTime),
        created: (u64::from(info.ftCreationTime.dwHighDateTime) << 32)
            | u64::from(info.ftCreationTime.dwLowDateTime),
    })
}

pub(crate) fn source_guid(source: &File) -> Result<String, SourceError> {
    let mut path = vec![0u16; MAX_PATH_UNITS];
    // SAFETY: retained source and bounded writable UTF-16 buffer. No path
    // input or fallback is used, including when a network GUID is absent.
    let count = unsafe {
        GetFinalPathNameByHandleW(
            source.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            VOLUME_NAME_GUID,
        )
    } as usize;
    if count == 0 {
        return Err(io_error("source volume GUID", io::Error::last_os_error()));
    }
    if count >= path.len() || path[count] != 0 {
        return Err(SourceError::Mapping(
            "oversized or unterminated source path",
        ));
    }
    volume_guid(&path[..count])
}

fn mapping(source: &File, volume: &File) -> Result<Mapping, SourceError> {
    let file = file_identity(source)?;
    let guid = source_guid(source)?;
    // SAFETY: both callers use the synchronous volume owned by bind_source.
    let extents = unsafe { volume_extents(volume)? };
    Ok(Mapping {
        file,
        guid,
        extents,
    })
}

/// # Safety
/// Caller retains a synchronous, access-zero volume handle for this query.
pub(crate) unsafe fn volume_extents(volume: &File) -> Result<Vec<SourceExtent>, SourceError> {
    let mut bytes = [0u8; 8 + MAX_EXTENTS * 24];
    let mut returned = 0;
    // SAFETY: live access-zero retained volume, fixed output capacity, and
    // no input/asynchronous state. This IOCTL only reports disk extents.
    if unsafe {
        DeviceIoControl(
            volume.as_raw_handle(),
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
            ptr::null(),
            0,
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(io_error(
            "source volume extents",
            io::Error::last_os_error(),
        ));
    }
    if returned as usize > bytes.len() {
        return Err(SourceError::Mapping("oversized source volume extents"));
    }
    parse_extents(&bytes[..returned as usize])
}

/// # Safety
/// Caller retains a synchronous volume handle for this query.
pub(crate) unsafe fn no_virtual_dependencies(volume: &File) -> Result<(), SourceError> {
    // u64 allocation supplies alignment for STORAGE_DEPENDENCY_INFO. Only
    // its integer-only version-1 prefix/entries are parsed, never pointers.
    // A sentinel count prevents untouched bytes from becoming a valid
    // empty result, even if the API reports success with an incomplete fill.
    let mut words = [u64::MAX; (8 + 64 * 28) / 8];
    let capacity = size_of_val(&words);
    // SAFETY: words is initialized, aligned and writable for capacity bytes.
    let bytes =
        unsafe { std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), capacity) };
    bytes[..4].copy_from_slice(&1u32.to_le_bytes());
    let mut used = 0;
    // SAFETY: the retained handle is a volume, not a regular file or disk.
    // HOST_VOLUMES asks for ancestors. No API-returned pointer is followed.
    let code = unsafe {
        GetStorageDependencyInformation(
            volume.as_raw_handle(),
            GET_STORAGE_DEPENDENCY_FLAG_HOST_VOLUMES,
            capacity as u32,
            bytes.as_mut_ptr().cast(),
            &mut used,
        )
    };
    if code != 0 {
        // On failure the output is undefined. Dispatch the exact documented
        // nonvirtual status before interpreting the payload or its reported
        // size; all other failures remain errors.
        return check_dependency_response(code, &[]);
    }
    if used as usize > bytes.len() {
        return Err(SourceError::Mapping(
            "oversized source backing dependencies",
        ));
    }
    check_dependency_response(code, &bytes[..used as usize])
}

fn no_external_backing(source: &File) -> Result<(), SourceError> {
    use windows_sys::Win32::{
        Foundation::ERROR_OBJECT_NOT_EXTERNALLY_BACKED, System::Ioctl::FSCTL_GET_EXTERNAL_BACKING,
    };
    const _: () = assert!(ERROR_OBJECT_NOT_EXTERNALLY_BACKED == 342);
    let mut bytes = [0u8; 256];
    let mut returned = 0;
    // SAFETY: the exact retained regular file and fixed output buffer live
    // throughout this synchronous query. No returned structure is trusted:
    // success means external backing and is rejected regardless of provider.
    let success = unsafe {
        DeviceIoControl(
            source.as_raw_handle(),
            FSCTL_GET_EXTERNAL_BACKING,
            ptr::null(),
            0,
            bytes.as_mut_ptr().cast(),
            bytes.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    check_external_backing(if success != 0 {
        Ok(returned as usize)
    } else {
        Err(io::Error::last_os_error())
    })
}
