// SPDX-License-Identifier: GPL-3.0-or-later
use super::{
    StageError,
    policy::{privilege_enabled, validate_geometry},
};
use crate::{
    windows_installation::{MachineInstallation, check_stage_object},
    writer::Geometry,
};
use std::{
    fs::{File, OpenOptions},
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr,
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::{LUID, LocalFree},
    Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        GetTokenInformation, LookupPrivilegeValueW, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        TOKEN_QUERY, TokenPrivileges,
    },
    Storage::{
        FileSystem::{
            CreateDirectoryW, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_ENCRYPTED,
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        },
        Vhd::*,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};

const _: () = {
    use windows_sys::Win32::Security::{LUID_AND_ATTRIBUTES, TOKEN_PRIVILEGES};
    assert!(std::mem::offset_of!(TOKEN_PRIVILEGES, Privileges) == 4);
    assert!(size_of::<LUID_AND_ATTRIBUTES>() == 12);
    assert!(std::mem::offset_of!(LUID_AND_ATTRIBUTES, Attributes) == 8);
};

// No ordinary-user access. OWNER RIGHTS prevents a newly created object's
// default user owner from receiving implicit WRITE_DAC; explicit owner is BA.
const PRIVATE_SD: &str = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;RC;;;OW)";
const BACKING_NAME: &str = "stage.vhdx";

fn error(operation: &'static str, source: io::Error) -> StageError {
    StageError::Io { operation, source }
}
fn status(operation: &'static str, code: u32) -> Result<(), StageError> {
    if code == 0 {
        Ok(())
    } else {
        Err(error(operation, io::Error::from_raw_os_error(code as i32)))
    }
}
fn wide(path: &Path) -> Result<Vec<u16>, StageError> {
    let mut value: Vec<_> = path.as_os_str().encode_wide().collect();
    if value.is_empty() || value.len() >= 260 || value.contains(&0) {
        return Err(StageError::Invalid("staging path length"));
    }
    value.push(0);
    Ok(value)
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Descriptor {
    fn private() -> Result<Self, StageError> {
        let text: Vec<_> = PRIVATE_SD.encode_utf16().chain(Some(0)).collect();
        let mut output = ptr::null_mut();
        // SAFETY: constant terminated input and writable output; success
        // transfers one LocalAlloc allocation, freed by Descriptor.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut output,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(error(
                "create private descriptor",
                io::Error::last_os_error(),
            ));
        }
        if output.is_null() {
            return Err(StageError::Invalid("null private descriptor"));
        }
        Ok(Self(output))
    }
}
impl Drop for Descriptor {
    fn drop(&mut self) {
        // SAFETY: the successful conversion supplied this LocalAlloc pointer.
        unsafe {
            LocalFree(self.0);
        }
    }
}

fn require_privilege() -> Result<(), StageError> {
    let mut token = ptr::null_mut();
    // SAFETY: query-only token handle; this module never adjusts privileges.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(error("query process token", io::Error::last_os_error()));
    }
    // SAFETY: successful OpenProcessToken transfers one owned handle.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let text: Vec<_> = "SeManageVolumePrivilege"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut luid = LUID::default();
    // SAFETY: terminated fixed privilege name and writable SDK LUID.
    if unsafe { LookupPrivilegeValueW(ptr::null(), text.as_ptr(), &mut luid) } == 0 {
        return Err(error(
            "resolve volume privilege",
            io::Error::last_os_error(),
        ));
    }
    let mut words = [0u32; 1 + 128 * 3];
    let mut returned = 0;
    // SAFETY: query-only live token, DWORD-aligned bounded output allocation.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenPrivileges,
            words.as_mut_ptr().cast(),
            size_of_val(&words) as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(error("read volume privilege", io::Error::last_os_error()));
    }
    if returned as usize > size_of_val(&words) {
        return Err(StageError::Invalid("oversized privileges"));
    }
    // SAFETY: initialized aligned allocation; returned has been bounded.
    let bytes =
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), returned as usize) };
    let id = u64::from(luid.LowPart) | ((luid.HighPart as u32 as u64) << 32);
    if privilege_enabled(bytes, id)? {
        Ok(())
    } else {
        Err(StageError::Privilege)
    }
}

enum Root {
    Installation(Arc<MachineInstallation>),
    #[cfg(test)]
    Fixture {
        path: PathBuf,
        handle: File,
    },
}
impl Root {
    fn path(&self) -> &Path {
        match self {
            Self::Installation(value) => value.directory(),
            #[cfg(test)]
            Self::Fixture { path, .. } => path,
        }
    }
    fn revalidate(&self) -> Result<(), StageError> {
        match self {
            Self::Installation(value) => value.revalidate().map_err(StageError::Installation),
            #[cfg(test)]
            Self::Fixture { handle, .. } => {
                check_stage_object(handle, true).map_err(StageError::Installation)
            }
        }
    }
}

fn create_private_directory(path: &Path, descriptor: &Descriptor) -> Result<File, StageError> {
    let name = wide(path)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    // SAFETY: constant descriptor and terminated path remain valid. This is a
    // single atomic creation, never opening/adopting an existing directory.
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        return Err(error("create job directory", io::Error::last_os_error()));
    }
    let result = OpenOptions::new()
        .access_mode(0x0002_0080)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|e| error("retain job directory", e))
        .and_then(|file| {
            check_stage_object(&file, true).map_err(StageError::Installation)?;
            Ok(file)
        });
    if result.is_err() {
        let _ = std::fs::remove_dir(path);
    }
    result
}

/// Owns one newly created private VHDX under the fixed machine installation.
/// It exposes neither its path nor storage handles. Creating/attaching this
/// virtual disk is not physical-target authorization or a sealed image.
///
/// SeManageVolumePrivilege must already be enabled before peers capture token
/// identity. No constructor/method changes token privileges. Administrators
/// and SYSTEM are trusted, as for MachineInstallation; no adoption/resume API.
/// This does not establish the backing volume's physical storage ancestry.
/// Initially supports 512-byte logical and 512/4096-byte physical sectors.
pub struct OwnedStageDisk {
    // If explicit cleanup fails, automatic field drops still close the VHD
    // before releasing its directory and protected installation guards.
    disk: Option<OwnedHandle>,
    directory_handle: Option<File>,
    directory: PathBuf,
    root: Root,
    attached: bool,
    cleanup_attempted: bool,
    geometry: Geometry,
    owned_files: Vec<&'static str>,
}
impl OwnedStageDisk {
    pub fn create(
        installation: Arc<MachineInstallation>,
        geometry: Geometry,
    ) -> Result<Self, StageError> {
        Self::create_under(Root::Installation(installation), geometry)
    }
    fn create_under(root: Root, geometry: Geometry) -> Result<Self, StageError> {
        validate_geometry(&geometry)?;
        root.revalidate()?;
        require_privilege()?;
        let mut nonce = [0u8; 32];
        // SAFETY: system RNG flag permits a null algorithm handle; exact buffer.
        let code = unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                nonce.as_mut_ptr(),
                nonce.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if code < 0 {
            return Err(StageError::Invalid("job entropy unavailable"));
        }
        let directory = root.path().join(format!("job-{}", hex::encode(nonce)));
        let descriptor = Descriptor::private()?;
        let handle = create_private_directory(&directory, &descriptor)?;
        let mut owned = Self {
            root,
            directory,
            directory_handle: Some(handle),
            disk: None,
            attached: false,
            cleanup_attempted: false,
            geometry,
            owned_files: vec![BACKING_NAME],
        };
        owned.revalidate()?;
        let name = wide(&owned.directory.join(BACKING_NAME))?;
        let storage = VIRTUAL_STORAGE_TYPE {
            DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
            VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };
        let parameters = CREATE_VIRTUAL_DISK_PARAMETERS {
            Version: CREATE_VIRTUAL_DISK_VERSION_2,
            Anonymous: CREATE_VIRTUAL_DISK_PARAMETERS_0 {
                Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
                    MaximumSize: owned.geometry.size_bytes,
                    BlockSizeInBytes: 2 * 1024 * 1024,
                    SectorSizeInBytes: owned.geometry.logical_sector_size,
                    PhysicalSectorSizeInBytes: owned.geometry.physical_sector_size,
                    ..Default::default()
                },
            },
        };
        let mut disk = ptr::null_mut();
        // SAFETY: stable new private pathname, explicit final ACL, no parent
        // or source image, no async buffers. Failure leaves disk undefined.
        status("create VHDX", unsafe {
            CreateVirtualDisk(
                &storage,
                name.as_ptr(),
                VIRTUAL_DISK_ACCESS_NONE,
                descriptor.0,
                CREATE_VIRTUAL_DISK_FLAG_NONE,
                0,
                &parameters,
                ptr::null(),
                &mut disk,
            )
        })?;
        if disk.is_null() || disk == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err(StageError::Invalid("invalid successful VHD handle"));
        }
        // SAFETY: successful creation transferred one validated owned handle.
        owned.disk = Some(unsafe { OwnedHandle::from_raw_handle(disk) });
        let backing = OpenOptions::new()
            .access_mode(0x0002_0080)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(owned.directory.join(BACKING_NAME))
            .map_err(|e| error("inspect new VHD backing", e))?;
        check_stage_object(&backing, false).map_err(StageError::Installation)?;
        use std::os::windows::fs::MetadataExt;
        if backing
            .metadata()
            .map_err(|e| error("VHD backing attributes", e))?
            .file_attributes()
            & (FILE_ATTRIBUTE_COMPRESSED | FILE_ATTRIBUTE_ENCRYPTED)
            != 0
        {
            return Err(StageError::Invalid("compressed or encrypted VHD backing"));
        }
        owned.revalidate()?;
        Ok(owned)
    }
    fn revalidate(&self) -> Result<(), StageError> {
        self.root.revalidate()?;
        check_stage_object(
            self.directory_handle
                .as_ref()
                .ok_or(StageError::Invalid("closed stage"))?,
            true,
        )
        .map_err(StageError::Installation)
    }
    pub fn attach(&mut self, read_only: bool) -> Result<(), StageError> {
        if self.attached {
            return Err(StageError::Invalid("VHD is already attached"));
        }
        self.revalidate()?;
        require_privilege()?;
        let descriptor = Descriptor::private()?;
        let parameters = ATTACH_VIRTUAL_DISK_PARAMETERS {
            Version: ATTACH_VIRTUAL_DISK_VERSION_1,
            ..Default::default()
        };
        let flags = ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER
            | if read_only {
                ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY
            } else {
                0
            };
        // SAFETY: live owned VHD, stable descriptor/parameters, synchronous call.
        // The attached device gets its own explicit restrictive ACL. A backing
        // file ACL alone is not treated as device-object protection.
        status("attach owned VHD", unsafe {
            AttachVirtualDisk(
                self.disk
                    .as_ref()
                    .ok_or(StageError::Invalid("closed VHD"))?
                    .as_raw_handle(),
                descriptor.0,
                flags,
                0,
                &parameters,
                ptr::null(),
            )
        })?;
        self.attached = true;
        self.revalidate()
    }
    pub fn detach(&mut self) -> Result<(), StageError> {
        if self.attached {
            // SAFETY: this is the same live VHD handle used for attachment.
            status("detach owned VHD", unsafe {
                DetachVirtualDisk(
                    self.disk
                        .as_ref()
                        .ok_or(StageError::Invalid("closed VHD"))?
                        .as_raw_handle(),
                    DETACH_VIRTUAL_DISK_FLAG_NONE,
                    0,
                )
            })?;
            self.attached = false;
        }
        Ok(())
    }
    /// Explicit cleanup reports errors. Failure may leave the private job on
    /// disk; cleanup never recurses or deletes anything except its known file.
    pub fn close(mut self) -> Result<(), StageError> {
        self.cleanup()
    }
    fn cleanup(&mut self) -> Result<(), StageError> {
        if self.cleanup_attempted {
            return Ok(());
        }
        self.cleanup_attempted = true;
        self.detach()?;
        drop(self.disk.take());
        for name in &self.owned_files {
            match std::fs::remove_file(self.directory.join(name)) {
                Ok(()) => (),
                Err(e) if e.kind() == io::ErrorKind::NotFound => (),
                Err(e) => return Err(error("remove owned stage file", e)),
            }
        }
        drop(self.directory_handle.take());
        std::fs::remove_dir(&self.directory).map_err(|e| error("remove empty job directory", e))
    }
}
impl Drop for OwnedStageDisk {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(test)]
#[path = "native_tests.rs"]
mod tests;

#[path = "build.rs"]
mod build;
#[path = "device.rs"]
mod device;
pub use build::{SealedStage, TargetBoundStage, build};
