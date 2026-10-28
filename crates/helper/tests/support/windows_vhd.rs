// SPDX-License-Identifier: GPL-3.0-or-later
//! Test-only ownership of newly created virtual disks. No external disk paths.
use isohopper_helper::writer::{CHUNK_BYTES, windows::WindowsRawDevice};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, Read, Seek},
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::PathBuf,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{GetLastError, LUID},
    Security::{
        AdjustTokenPrivileges, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
    Storage::{
        FileSystem::{
            FILE_DEVICE_DISK, FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH, FILE_SHARE_READ,
            FILE_SHARE_WRITE,
        },
        Vhd::{
            ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY,
            ATTACH_VIRTUAL_DISK_PARAMETERS, ATTACH_VIRTUAL_DISK_VERSION_1, AttachVirtualDisk,
            CREATE_VIRTUAL_DISK_FLAG_NONE, CREATE_VIRTUAL_DISK_PARAMETERS,
            CREATE_VIRTUAL_DISK_PARAMETERS_0, CREATE_VIRTUAL_DISK_PARAMETERS_0_1,
            CREATE_VIRTUAL_DISK_VERSION_2, CreateVirtualDisk, DETACH_VIRTUAL_DISK_FLAG_NONE,
            DetachVirtualDisk, GetVirtualDiskPhysicalPath, VIRTUAL_DISK_ACCESS_NONE,
            VIRTUAL_STORAGE_TYPE, VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
            VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        },
    },
    System::{
        IO::DeviceIoControl,
        Ioctl::{
            GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO, IOCTL_STORAGE_GET_DEVICE_NUMBER,
            IOCTL_STORAGE_QUERY_PROPERTY, PropertyStandardQuery, STORAGE_DEVICE_NUMBER,
            STORAGE_PROPERTY_QUERY, StorageDeviceIdProperty, StorageDeviceProperty,
        },
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

pub const CAPACITY: u64 = 256 * 1024 * 1024;

// Print only the descriptor of the newly created test VHD. This is deliberately
// test-local: production device identifiers are not uploaded to CI logs.
fn describe_test_vhd(file: &File) -> io::Result<()> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: StorageDeviceProperty,
        QueryType: PropertyStandardQuery,
        ..Default::default()
    };
    let mut output = [0u8; 4096];
    let mut returned = 0;
    // SAFETY: all buffers and the synchronous retained VHD handle remain live
    // through the call. The output allocation is fixed and bounded.
    if unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            IOCTL_STORAGE_QUERY_PROPERTY,
            (&query as *const STORAGE_PROPERTY_QUERY).cast(),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            output.as_mut_ptr().cast(),
            output.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(context(
            "test VHD descriptor diagnostics",
            io::Error::last_os_error(),
        ));
    }
    if returned as usize > output.len() {
        return Err(io::Error::other("oversized test descriptor"));
    }
    println!(
        "New test VHD storage descriptor: returned={returned}, prefix={}",
        hex::encode(&output[..(returned as usize).min(256)])
    );
    Ok(())
}

pub fn context(stage: &str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{stage}: {error}"))
}

fn status(stage: &str, code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(context(stage, io::Error::from_raw_os_error(code as i32)))
    }
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

pub fn hash_exact(file: &mut File) -> io::Result<[u8; 32]> {
    assert_eq!(file.metadata()?.len(), CAPACITY);
    file.rewind()?;
    let mut hash = Sha256::new();
    let mut remaining = CAPACITY;
    let mut bytes = vec![0u8; CHUNK_BYTES];
    while remaining != 0 {
        let count = remaining.min(bytes.len() as u64) as usize;
        file.read_exact(&mut bytes[..count])?;
        hash.update(&bytes[..count]);
        remaining -= count as u64;
    }
    assert_eq!(file.read(&mut [0])?, 0);
    file.rewind()?;
    Ok(hash.finalize().into())
}

pub struct TemporaryVhd {
    handle: OwnedHandle,
    attached: bool,
}

impl TemporaryVhd {
    /// Diagnostics only: compare VPD page 0x83 across this owned VHD's
    /// detach/reattach boundary before any write is attempted.
    pub fn diagnose_device_ids(&mut self) -> io::Result<()> {
        let before = self.read_device_id_for_diagnostics()?;
        self.detach()?;
        self.attach(false)?;
        let after = self.read_device_id_for_diagnostics()?;
        println!(
            "New test VHD device-ID descriptor stable across reattachment: {}",
            before.is_some() && before == after
        );
        Ok(())
    }

    fn read_device_id_for_diagnostics(&self) -> io::Result<Option<Vec<u8>>> {
        let (path, number) = self.physical_path()?;
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(path)?;
        assert_readback_binding(&file, number)?;
        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceIdProperty,
            QueryType: PropertyStandardQuery,
            ..Default::default()
        };
        let mut output = [0u8; 4096];
        let mut returned = 0;
        // SAFETY: the retained test VHD handle is synchronous and all buffers
        // are live with fixed bounds. This is a read-only descriptor request.
        if unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                IOCTL_STORAGE_QUERY_PROPERTY,
                (&query as *const STORAGE_PROPERTY_QUERY).cast(),
                size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                output.as_mut_ptr().cast(),
                output.len() as u32,
                &mut returned,
                ptr::null_mut(),
            )
        } == 0
        {
            println!(
                "New test VHD device-ID descriptor unavailable: {}",
                io::Error::last_os_error()
            );
            return Ok(None);
        }
        if returned as usize > output.len() {
            return Err(io::Error::other("oversized test device-ID descriptor"));
        }
        println!(
            "New test VHD device-ID descriptor: returned={returned}, prefix={}",
            hex::encode(&output[..(returned as usize).min(512)])
        );
        Ok(Some(output[..returned as usize].to_vec()))
    }

    pub fn open_raw_device(&self) -> io::Result<WindowsRawDevice> {
        let (path, number) = self.physical_path()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH)
            .open(path)?;
        assert_readback_binding(&file, number)?;
        describe_test_vhd(&file)?;
        // SAFETY: synchronous unbuffered write-through handle derived only
        // from this owned test VHD. No aliases. Callers write either its blank
        // initial state or through the production lock owner.
        unsafe { WindowsRawDevice::from_owned_handle(file.into()) }
            .map_err(|error| context("inspect newly created VHD with production adapter", error))
    }
    pub fn create(path: PathBuf) -> io::Result<Self> {
        assert!(!path.exists(), "test VHD must be new");
        let path = wide(path.as_os_str());
        let storage = VIRTUAL_STORAGE_TYPE {
            DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHDX,
            VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
        };
        let parameters = CREATE_VIRTUAL_DISK_PARAMETERS {
            Version: CREATE_VIRTUAL_DISK_VERSION_2,
            Anonymous: CREATE_VIRTUAL_DISK_PARAMETERS_0 {
                Version2: CREATE_VIRTUAL_DISK_PARAMETERS_0_1 {
                    MaximumSize: CAPACITY,
                    BlockSizeInBytes: 2 * 1024 * 1024,
                    SectorSizeInBytes: 512,
                    PhysicalSectorSizeInBytes: 4096,
                    ..Default::default()
                },
            },
        };
        let mut handle = ptr::null_mut();
        // SAFETY: all structures and the terminated path remain live through
        // this synchronous call. Null parent/source paths create a new disk;
        // access NONE is required for CREATE_VIRTUAL_DISK_VERSION_2.
        status("CreateVirtualDisk", unsafe {
            CreateVirtualDisk(
                &storage,
                path.as_ptr(),
                VIRTUAL_DISK_ACCESS_NONE,
                ptr::null_mut(),
                CREATE_VIRTUAL_DISK_FLAG_NONE,
                0,
                &parameters,
                ptr::null(),
                &mut handle,
            )
        })?;
        // SAFETY: successful CreateVirtualDisk transfers a new owned handle.
        Ok(Self {
            handle: unsafe { OwnedHandle::from_raw_handle(handle) },
            attached: false,
        })
    }

    pub fn attach(&mut self, read_only: bool) -> io::Result<()> {
        assert!(!self.attached);
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
        // SAFETY: retained VHD handle and parameters are live. No permanent
        // lifetime flag: closing this handle is also a final detach safeguard.
        status("AttachVirtualDisk", unsafe {
            AttachVirtualDisk(
                self.handle.as_raw_handle(),
                ptr::null_mut(),
                flags,
                0,
                &parameters,
                ptr::null(),
            )
        })?;
        self.attached = true;
        Ok(())
    }

    pub fn physical_path(&self) -> io::Result<(OsString, u32)> {
        assert!(self.attached);
        let mut buffer = [0u16; 260];
        let mut bytes = size_of_val(&buffer) as u32;
        // SAFETY: output size describes this bounded UTF-16 buffer. No retry
        // allocates based on external data; an oversized result fails closed.
        status("GetVirtualDiskPhysicalPath", unsafe {
            GetVirtualDiskPhysicalPath(self.handle.as_raw_handle(), &mut bytes, buffer.as_mut_ptr())
        })?;
        if bytes as usize > size_of_val(&buffer) || !bytes.is_multiple_of(2) {
            return Err(io::Error::other("invalid VHD physical path length"));
        }
        let text = &buffer[..bytes as usize / 2];
        let end = text
            .iter()
            .position(|value| *value == 0)
            .ok_or_else(|| io::Error::other("unterminated VHD physical path"))?;
        let text = String::from_utf16(&text[..end])
            .map_err(|_| io::Error::other("invalid VHD path encoding"))?;
        let number = text
            .strip_prefix(r"\\.\PhysicalDrive")
            .filter(|suffix| !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit()))
            .and_then(|suffix| suffix.parse::<u32>().ok())
            .ok_or_else(|| io::Error::other("VHD returned an unexpected physical path"))?;
        Ok((OsString::from_wide(&buffer[..end]), number))
    }

    pub fn detach(&mut self) -> io::Result<()> {
        if self.attached {
            // SAFETY: only the retained handle for this test's VHD is detached.
            status("DetachVirtualDisk", unsafe {
                DetachVirtualDisk(
                    self.handle.as_raw_handle(),
                    DETACH_VIRTUAL_DISK_FLAG_NONE,
                    0,
                )
            })?;
            self.attached = false;
        }
        Ok(())
    }
}

impl Drop for TemporaryVhd {
    fn drop(&mut self) {
        if let Err(error) = self.detach() {
            eprintln!(
                "temporary VHD cleanup: {error}; closing its non-permanent attachment handle"
            );
        }
    }
}

pub fn assert_readback_binding(file: &File, number: u32) -> io::Result<()> {
    let mut disk = STORAGE_DEVICE_NUMBER::default();
    let mut length = GET_LENGTH_INFORMATION::default();
    for (code, output, size) in [
        (
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            (&mut disk as *mut STORAGE_DEVICE_NUMBER).cast(),
            size_of::<STORAGE_DEVICE_NUMBER>(),
        ),
        (
            IOCTL_DISK_GET_LENGTH_INFO,
            (&mut length as *mut GET_LENGTH_INFORMATION).cast(),
            size_of::<GET_LENGTH_INFORMATION>(),
        ),
    ] {
        let mut returned = 0;
        // SAFETY: file is a live synchronous handle and each typed writable
        // buffer has the exact advertised size. No input buffer is needed.
        if unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                code,
                ptr::null(),
                0,
                output,
                size as u32,
                &mut returned,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(context(
                "read-only reattachment identity",
                io::Error::last_os_error(),
            ));
        }
        assert_eq!(returned as usize, size);
    }
    assert_eq!(disk.DeviceType, FILE_DEVICE_DISK);
    assert_eq!(disk.DeviceNumber, number);
    assert_eq!(disk.PartitionNumber, 0);
    assert_eq!(length.Length, CAPACITY as i64);
    Ok(())
}

pub struct ManageVolumePrivilege {
    token: OwnedHandle,
    previous: TOKEN_PRIVILEGES,
}

impl ManageVolumePrivilege {
    pub fn enable() -> io::Result<Self> {
        let mut token = ptr::null_mut();
        // SAFETY: current-process pseudo handle is valid; output is writable.
        if unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                &mut token,
            )
        } == 0
        {
            return Err(context("OpenProcessToken", io::Error::last_os_error()));
        }
        // SAFETY: successful OpenProcessToken transfers a new owned handle.
        let token = unsafe { OwnedHandle::from_raw_handle(token) };
        let name = wide(OsStr::new("SeManageVolumePrivilege"));
        let mut luid = LUID::default();
        // SAFETY: terminated name and writable LUID are valid; null selects
        // the local system. This does not acquire privileges the user lacks.
        if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) } == 0 {
            return Err(context("LookupPrivilegeValueW", io::Error::last_os_error()));
        }
        let requested = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };
        let mut previous = TOKEN_PRIVILEGES::default();
        let mut returned = 0;
        // SAFETY: both one-entry privilege buffers have the advertised size.
        let success = unsafe {
            AdjustTokenPrivileges(
                token.as_raw_handle(),
                0,
                &requested,
                size_of::<TOKEN_PRIVILEGES>() as u32,
                &mut previous,
                &mut returned,
            )
        };
        // AdjustTokenPrivileges may return success with NOT_ALL_ASSIGNED.
        let error = unsafe { GetLastError() };
        if success == 0 || error != 0 {
            return Err(context(
                "enable SeManageVolumePrivilege",
                io::Error::from_raw_os_error(error as i32),
            ));
        }
        Ok(Self { token, previous })
    }
}

impl Drop for ManageVolumePrivilege {
    fn drop(&mut self) {
        // SAFETY: restore only this token's previous state while its owned
        // handle is still live. No storage handles remain when this runs.
        if unsafe {
            AdjustTokenPrivileges(
                self.token.as_raw_handle(),
                0,
                &self.previous,
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == 0
        {
            eprintln!(
                "restoring storage privilege failed: {}",
                io::Error::last_os_error()
            );
        }
    }
}
