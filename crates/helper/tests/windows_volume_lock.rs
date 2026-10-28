// SPDX-License-Identifier: GPL-3.0-or-later
#[path = "support/lock_image.rs"]
mod lock_image;

// Shared VHD support also has diagnostic entry points used by windows_vhd.rs.
#[cfg(windows)]
#[allow(dead_code)]
#[path = "support/windows_vhd.rs"]
mod vhd_support;

#[cfg(windows)]
#[test]
#[ignore = "creates and formats only its own 256 MiB temporary VHDX; requires Windows administrator storage privileges"]
fn windows_vhd_lock_refuses_open_file_and_releases_locks() -> Result<(), Box<dyn std::error::Error>>
{
    native::run()
}

#[test]
fn adapted_lock_fixture_has_two_fat_volumes_and_verified_gpt_copies() {
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
    };
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lock.img");
    let plan = lock_image::create(&path).unwrap();
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    for partition in &plan.partitions[1..] {
        file.seek(SeekFrom::Start(partition.start_lba * 512))
            .unwrap();
        let mut sector = [0; 512];
        file.read_exact(&mut sector).unwrap();
        assert_eq!(&sector[82..90], b"FAT32   ");
        assert_eq!(&sector[510..], &[0x55, 0xaa]);
        assert_eq!(
            u32::from_le_bytes(sector[28..32].try_into().unwrap()) as u64,
            partition.start_lba
        );
    }
    file.seek(SeekFrom::Start(1024 + 128)).unwrap();
    file.write_all(&[0]).unwrap();
    assert!(lock_image::verify(&mut file, &plan).is_err());
    file.seek(SeekFrom::Start(1024 + 128)).unwrap();
    file.write_all(&[0xa2]).unwrap();
    lock_image::verify(&mut file, &plan).unwrap();
    file.seek(SeekFrom::Start((plan.total_sectors - 1) * 512 + 16))
        .unwrap();
    file.write_all(&[0; 4]).unwrap();
    assert!(lock_image::verify(&mut file, &plan).is_err());
}

#[cfg(windows)]
mod native {
    use super::{lock_image, vhd_support};
    use isohopper_core::layout::Layout;
    use isohopper_helper::{
        windows_lock::{self, LockError},
        writer::{RetainedDevice, write_image},
    };
    use std::{
        collections::BTreeSet,
        fs::{File, OpenOptions},
        io::{self, Read, Seek},
        mem::size_of,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        ptr,
        sync::atomic::AtomicBool,
        thread,
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
            Ioctl::{IOCTL_STORAGE_GET_DEVICE_NUMBER, STORAGE_DEVICE_NUMBER},
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
    struct Volume {
        name: String,
        start: u64,
        length: u64,
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

    fn volume_name(buffer: &[u16]) -> io::Result<String> {
        let end = buffer
            .iter()
            .position(|value| *value == 0)
            .ok_or_else(|| invalid("unterminated volume GUID"))?;
        let name = String::from_utf16(&buffer[..end])
            .map_err(|_| invalid("invalid volume GUID encoding"))?;
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
        Ok(name.to_ascii_lowercase())
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

    fn verify_filesystem(volume: &Volume) -> io::Result<()> {
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
        if String::from_utf16_lossy(&filesystem[..end]) != "FAT32" {
            return Err(invalid("owned VHD volume did not mount as FAT32"));
        }
        Ok(())
    }

    fn open_payload(volume: &Volume) -> io::Result<File> {
        OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(format!("{}EFI\\BOOT\\BOOTX64.EFI", volume.name))
    }

    fn verify_payload(file: &mut File) -> io::Result<()> {
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

    fn wait_for_volumes(disk_number: u32, plan: &Layout) -> io::Result<Vec<Volume>> {
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

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        let _privilege = vhd_support::ManageVolumePrivilege::enable()?;
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("formatted-lock.img");
        let plan = lock_image::create(&path)?;
        let mut source = File::open(path)?;
        let digest = vhd_support::hash_exact(&mut source)?;
        let mut vhd =
            vhd_support::TemporaryVhd::create(directory.path().join("formatted-lock.vhdx"))?;
        vhd.attach(false)?;
        let mut seed_device = vhd.open_raw_device()?;
        let seed_snapshot = seed_device.initial_snapshot().clone();
        assert!(seed_snapshot.device_id.is_some());
        // Only a newly created, blank VHD is written before filesystem locks.
        let report = write_image(
            &mut seed_device,
            &mut source,
            &seed_snapshot,
            digest,
            &AtomicBool::new(false),
            |_| {},
        )?;
        assert_eq!(report.bytes_verified, lock_image::CAPACITY);
        drop(seed_device);
        vhd.detach()?;
        vhd.attach(false)?;
        let device = vhd.open_raw_device()?;
        let expected = device.initial_snapshot().clone();
        assert_eq!(seed_snapshot.device_id, expected.device_id);
        let volumes = wait_for_volumes(expected.device_number, &plan)?;
        assert_eq!(volumes.len(), 2);
        // Hold a file on the later sorted GUID and require lock refusal. The
        // public error does not reveal which lock failed, so this runtime test
        // proves subsequent readability and retry, not partial-lock rollback.
        // Acquired-lock rollback is covered by the portable state tests.
        let mut held_file = open_payload(&volumes[1])?;
        verify_payload(&mut held_file)?;
        match windows_lock::lock(device, &expected) {
            Err(LockError::Io {
                stage: "lock target volume",
                ..
            }) => {}
            Err(error) => {
                return Err(format!("expected open-file lock refusal, got {error}").into());
            }
            Ok(_) => return Err("volume lock incorrectly succeeded with an open file".into()),
        }
        verify_payload(&mut open_payload(&volumes[0])?)?;
        verify_payload(&mut held_file)?;
        drop(held_file);

        let device = vhd.open_raw_device()?;
        assert_eq!(device.initial_snapshot(), &expected);
        let mut locked = windows_lock::lock(device, &expected)?;
        assert_eq!(locked.locked_volume_count(), 2);
        assert_eq!(locked.snapshot()?, expected);
        for volume in &volumes {
            match open_payload(volume) {
                Err(error)
                    if error.kind() == io::ErrorKind::PermissionDenied
                        || matches!(error.raw_os_error(), Some(32 | 33)) => {}
                Err(error) => {
                    return Err(format!("unexpected locked-volume open error: {error}").into());
                }
                Ok(_) => return Err("file open succeeded while volume lock was held".into()),
            }
        }
        drop(locked);
        for volume in &volumes {
            verify_filesystem(volume)?;
            verify_payload(&mut open_payload(volume)?)?;
        }
        vhd.detach()?;
        println!(
            "VHD lock integration passed: two exact FAT32 extents; open-file lock refusal followed by readable payloads and successful retry; retained locks deny file opens; drop restores both payloads; no USB hardware exercised"
        );
        Ok(())
    }
}
