// SPDX-License-Identifier: GPL-3.0-or-later
use super::{state::*, *};
use crate::{
    windows_installation::{InstalledRole, MachineInstallation},
    windows_sources::{self, SourceBinding},
    writer::DeviceSnapshot,
};
use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
    sync::Arc,
};
use windows_sys::Win32::{
    Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TYPE_DISK,
        GetFileInformationByHandle, GetFileType,
    },
    System::SystemInformation::GetSystemWindowsDirectoryW,
};

/// Storage of a retained executable file. The role labels an authenticated
/// handle supplied by the caller; this module does not authenticate the file,
/// infer process identity from a pathname, or enumerate its loaded libraries.
pub struct ProtectedFileBinding {
    role: ImageRole,
    source: SourceBinding,
}

impl ProtectedFileBinding {
    pub fn role(&self) -> ImageRole {
        self.role
    }
    pub fn source_file(&self) -> &File {
        self.source.source_file()
    }
    pub fn volume_guid(&self) -> &str {
        self.source.volume_guid()
    }
    pub fn extents(&self) -> &[SourceExtent] {
        self.source.extents()
    }
    pub fn revalidate(&self, target: &DeviceSnapshot) -> Result<(), ProtectedError> {
        self.source.revalidate(target).map_err(Into::into)
    }
}

/// Bind an already authenticated helper or caller executable handle. `target`
/// must be fresh evidence from the retained candidate device. The binding owns
/// the file and volume handles and preserves the source mapper's fail-closed
/// external-backing and virtual-dependency checks. Loaded DLLs, app resources,
/// active pagefiles and other boot/system volumes require separate evidence.
///
/// # Safety
/// `file` must be a live readable synchronous handle, without
/// FILE_FLAG_OVERLAPPED, as required by `windows_sources::bind_source`.
pub unsafe fn bind_file(
    role: ImageRole,
    file: File,
    target: &DeviceSnapshot,
) -> Result<ProtectedFileBinding, ProtectedError> {
    // SAFETY: the caller supplies the same live synchronous readable handle
    // invariant required by bind_source. The binding takes ownership of it.
    let source = unsafe { windows_sources::bind_source(file, target) }?;
    Ok(ProtectedFileBinding { role, source })
}

/// Bind only a fixed file from a retained protected machine installation.
/// WOF inline-backing evidence is checked against its guarded path and original
/// handle; volume extents and virtual dependencies use the retained source.
/// `target` must be fresh evidence from the caller's retained target handle.
/// This correlates installed-file storage, not a running process, and grants no
/// authority to write. Loaded modules and other protected storage are separate.
pub fn bind_installed_file(
    installation: Arc<MachineInstallation>,
    role: InstalledRole,
    target: &DeviceSnapshot,
) -> Result<ProtectedFileBinding, ProtectedError> {
    let source = windows_sources::bind_installed_source(installation, role, target)?;
    let role = match role {
        InstalledRole::Studio => ImageRole::Caller,
        InstalledRole::Helper => ImageRole::Helper,
    };
    Ok(ProtectedFileBinding { role, source })
}

/// Owns the actual OS directory and its filesystem-reported volume. Only
/// storage exclusion is established; directory identity metadata is a change
/// sentinel, not an integrity proof or globally unique filesystem identity.
/// This does not identify the EFI/system partition or all OS resources.
pub struct SystemDirectoryBinding {
    directory: File,
    volume: File,
    mapping: DirectoryMapping,
    target: DeviceSnapshot,
}

impl SystemDirectoryBinding {
    pub fn volume_guid(&self) -> &str {
        &self.mapping.guid
    }
    pub fn extents(&self) -> &[SourceExtent] {
        &self.mapping.extents
    }

    /// Repeat the current OS directory lookup and compare a newly retained
    /// directory with the original handle, then recheck volume and dependency
    /// evidence. This is a bounded observation, not an atomic topology lock.
    pub fn revalidate(&self, target: &DeviceSnapshot) -> Result<(), ProtectedError> {
        if target != &self.target {
            return Err(ProtectedError::Changed);
        }
        let os_path = windows_directory_path()?;
        if os_path != self.mapping.os_path {
            return Err(ProtectedError::Changed);
        }
        let current = open_directory(&os_path)?;
        unchanged(
            &self.mapping,
            &observe(&self.directory, &self.volume, &os_path)?,
        )?;
        unchanged(&self.mapping, &observe(&current, &self.volume, &os_path)?)?;
        exclude_target(&self.mapping.extents, target.device_number)?;
        // SAFETY: volume was opened here synchronously with access zero and
        // remains privately owned; no replacement or overlapped I/O is exposed.
        unsafe { windows_sources::no_virtual_dependencies(&self.volume) }?;
        if windows_directory_path()? != os_path {
            return Err(ProtectedError::Changed);
        }
        unchanged(&self.mapping, &observe(&current, &self.volume, &os_path)?)?;
        unchanged(
            &self.mapping,
            &observe(&self.directory, &self.volume, &os_path)?,
        )
    }
}

/// Discover the shared Windows directory through GetSystemWindowsDirectoryW,
/// retain its directory handle, and derive a canonical volume GUID from that
/// handle. No environment variable or caller pathname selects system storage.
/// Windows installations at a volume root, missing GUIDs, and unproven backing
/// remain unsupported rather than falling back to a drive letter.
pub fn bind_system_directory(
    target: &DeviceSnapshot,
) -> Result<SystemDirectoryBinding, ProtectedError> {
    target
        .geometry
        .validate()
        .map_err(|_| ProtectedError::MissingEvidence("invalid candidate geometry"))?;
    let os_path = windows_directory_path()?;
    let directory = open_directory(&os_path)?;
    let identity = directory_identity(&directory)?;
    let guid = windows_sources::source_guid(&directory)?;
    let volume = OpenOptions::new()
        .read(true)
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(&guid[..guid.len() - 1])
        .map_err(|source| io_error("open protected volume", source))?;
    let mapping = observe(&directory, &volume, &os_path)?;
    if mapping.identity != identity || mapping.guid != guid {
        return Err(ProtectedError::Changed);
    }
    exclude_target(&mapping.extents, target.device_number)?;
    let binding = SystemDirectoryBinding {
        directory,
        volume,
        mapping,
        target: target.clone(),
    };
    binding.revalidate(target)?;
    Ok(binding)
}

fn io_error(stage: &'static str, source: io::Error) -> ProtectedError {
    ProtectedError::Io { stage, source }
}

fn windows_directory_path() -> Result<String, ProtectedError> {
    let mut units = vec![u16::MAX; MAX_PATH_UNITS];
    // SAFETY: fixed bounded writable UTF-16 buffer, no borrowed output retained.
    let count =
        unsafe { GetSystemWindowsDirectoryW(units.as_mut_ptr(), units.len() as u32) } as usize;
    if count == 0 {
        return Err(io_error(
            "Windows directory lookup",
            io::Error::last_os_error(),
        ));
    }
    if count >= units.len() || units[count] != 0 {
        return Err(ProtectedError::MissingEvidence(
            "oversized or unterminated Windows directory",
        ));
    }
    system_path(&units[..count])
}

fn open_directory(path: &str) -> Result<File, ProtectedError> {
    // This path comes only from windows_directory_path. Access zero allows
    // metadata queries, BACKUP_SEMANTICS opens the directory, and omitting
    // FILE_SHARE_DELETE prevents deletion/rename of this retained directory.
    OpenOptions::new()
        .read(true)
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|source| io_error("open Windows directory", source))
}

fn directory_identity(directory: &File) -> Result<DirectoryIdentity, ProtectedError> {
    // SAFETY: live privately owned handle and a writable integer-only output.
    if unsafe { GetFileType(directory.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(ProtectedError::MissingEvidence(
            "Windows directory is not local disk storage",
        ));
    }
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(directory.as_raw_handle(), &mut info) } == 0 {
        return Err(io_error(
            "Windows directory identity",
            io::Error::last_os_error(),
        ));
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
        || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(ProtectedError::MissingEvidence(
            "Windows directory is missing or reparse-backed",
        ));
    }
    Ok(DirectoryIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        file_index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        created: (u64::from(info.ftCreationTime.dwHighDateTime) << 32)
            | u64::from(info.ftCreationTime.dwLowDateTime),
    })
}

fn observe(
    directory: &File,
    volume: &File,
    os_path: &str,
) -> Result<DirectoryMapping, ProtectedError> {
    let identity = directory_identity(directory)?;
    let guid = windows_sources::source_guid(directory)?;
    // SAFETY: only privately retained access-zero synchronous volume handles
    // opened by bind_system_directory reach this function.
    let extents = unsafe { windows_sources::volume_extents(volume) }?;
    Ok(DirectoryMapping {
        os_path: os_path.into(),
        identity,
        guid,
        extents,
    })
}
