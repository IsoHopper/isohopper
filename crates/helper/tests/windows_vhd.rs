// SPDX-License-Identifier: GPL-3.0-or-later
//! Explicitly opted-in Windows storage integration. No caller-supplied paths.
//! Only a newly created temporary VHDX is attached and modified. No filesystem
//! is formatted, and neither attachment may assign drive letters.
#![cfg(windows)]

use isohopper_core::{layout, virtualdisk};
use isohopper_helper::writer::{CHUNK_BYTES, Phase, windows::WindowsRawDevice, write_image};
use sha2::{Digest, Sha256};
use std::{
    ffi::{OsStr, OsString},
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    mem::size_of,
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::PathBuf,
    ptr,
    sync::atomic::AtomicBool,
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
            STORAGE_DEVICE_NUMBER,
        },
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

const CAPACITY: u64 = 256 * 1024 * 1024;

#[test]
#[ignore = "creates, attaches, writes and detaches only its own 256 MiB temporary VHDX; requires Windows administrator storage privileges"]
fn windows_vhd_writer_persists_verified_gpt() -> Result<(), Box<dyn std::error::Error>> {
    // Declaration order keeps the privilege enabled until the VHD is detached
    // and drops all handles before the temporary directory is removed.
    let _privilege = ManageVolumePrivilege::enable()?;
    let directory = tempfile::tempdir()?;
    let source_path = directory.path().join("source.img");
    let persisted_path = directory.path().join("persisted.img");
    let plan = layout::plan(CAPACITY, 512, false)?;
    virtualdisk::create(&source_path, &plan)?;
    let mut source = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&source_path)?;
    // A multi-chunk sentinel in the unformatted data area exercises persisted
    // nonzero bytes independently of the small primary and backup GPT tables.
    source.seek(SeekFrom::Start(
        plan.partitions[0].start_lba * 512 + 4 * 1024 * 1024,
    ))?;
    let sentinel: Vec<u8> = (0..2 * CHUNK_BYTES + 512)
        .map(|i| (i % 251) as u8)
        .collect();
    source.write_all(&sentinel)?;
    source.sync_all()?;
    virtualdisk::verify(&source_path)?;
    let expected_hash = hash_exact(&mut source)?;

    let mut vhd = TemporaryVhd::create(directory.path().join("writer-test.vhdx"))?;
    vhd.attach(false)?;
    let (physical_path, number) = vhd.physical_path()?;
    // The path is returned only by our retained VHD handle. It is neither an
    // argument, an environment variable, nor a result from inventory discovery.
    let raw = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH)
        .open(physical_path)?;
    // SAFETY: this is the new blank VHD owned above, with no formatted/mounted
    // volumes. The synchronous unbuffered write-through handle has no aliases.
    // The VHD owner remains attached for the entire operation.
    let mut device = unsafe { WindowsRawDevice::from_owned_handle(raw.into()) }
        .map_err(|error| context("inspect newly created VHD with production adapter", error))?;
    let expected = device.initial_snapshot().clone();
    assert_eq!(expected.device_number, number, "VHD path/handle binding");
    assert_eq!(expected.geometry.size_bytes, CAPACITY);
    assert_eq!(expected.geometry.logical_sector_size, 512);
    assert_eq!(expected.geometry.physical_sector_size, 4096);
    // No serial or geometry exceptions: missing VHD identity must fail exactly
    // as it does for a production raw-device handle.
    assert!(!expected.serial.is_empty());
    let mut phases = Vec::new();
    let report = write_image(
        &mut device,
        &mut source,
        &expected,
        expected_hash,
        &AtomicBool::new(false),
        |progress| {
            assert_eq!(progress.total_bytes, CAPACITY);
            assert!(progress.completed_bytes <= CAPACITY);
            if phases.last() != Some(&progress.phase) {
                phases.push(progress.phase);
            }
        },
    )?;
    assert_eq!(report.bytes_written, CAPACITY);
    assert_eq!(report.bytes_verified, CAPACITY);
    assert_eq!(report.sha256, expected_hash);
    assert_eq!(
        phases,
        [
            Phase::CheckingSource,
            Phase::Writing,
            Phase::Flushing,
            Phase::Verifying,
            Phase::Complete
        ]
    );
    drop(device);
    vhd.detach()?;

    // Reattach read-only through the same retained VHD handle. This cannot
    // accidentally validate bytes cached by the original raw device handle.
    vhd.attach(true)?;
    let (physical_path, number) = vhd.physical_path()?;
    let mut persisted = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(physical_path)?;
    assert_readback_binding(&persisted, number)?;
    let mut copy = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&persisted_path)?;
    assert_eq!(
        io::copy(&mut Read::by_ref(&mut persisted).take(CAPACITY), &mut copy)?,
        CAPACITY
    );
    copy.sync_all()?;
    assert_eq!(
        hash_exact(&mut copy)?,
        expected_hash,
        "persisted complete-image digest"
    );
    drop(copy);
    drop(persisted);
    vhd.detach()?;
    virtualdisk::verify(&persisted_path)?;
    println!(
        "VHD integration passed: {CAPACITY} bytes written and read back; read-only reattachment digest and primary/backup GPT verified; no USB hardware exercised"
    );
    Ok(())
}

fn context(stage: &str, error: io::Error) -> io::Error {
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

fn hash_exact(file: &mut File) -> io::Result<[u8; 32]> {
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

struct TemporaryVhd {
    handle: OwnedHandle,
    attached: bool,
}

impl TemporaryVhd {
    fn create(path: PathBuf) -> io::Result<Self> {
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

    fn attach(&mut self, read_only: bool) -> io::Result<()> {
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

    fn physical_path(&self) -> io::Result<(OsString, u32)> {
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

    fn detach(&mut self) -> io::Result<()> {
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

fn assert_readback_binding(file: &File, number: u32) -> io::Result<()> {
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

struct ManageVolumePrivilege {
    token: OwnedHandle,
    previous: TOKEN_PRIVILEGES,
}

impl ManageVolumePrivilege {
    fn enable() -> io::Result<Self> {
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
