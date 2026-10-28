// SPDX-License-Identifier: GPL-3.0-or-later
#[path = "support/lock_image.rs"]
mod lock_image;

#[path = "support/windows_volume.rs"]
#[allow(dead_code)] // Shared discovery also supports source-mapping integration.
mod volume_support;
use volume_support::volume_name;

#[test]
fn enumerated_volume_path_keeps_canonical_prefix_and_normalizes_only_guid() {
    let input = r"\\?\Volume{01234567-89AB-CDEF-0123-456789ABCDEF}\";
    let wide: Vec<_> = input.encode_utf16().chain(Some(0)).collect();
    assert_eq!(
        volume_name(&wide).unwrap(),
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\"
    );
    for invalid in [
        r"\\?\volume{01234567-89ab-cdef-0123-456789abcdef}\",
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}",
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdeg}\",
        r"\\?\Volume{0123456789ab-cdef-0123-456789abcdef}\",
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\extra",
    ] {
        let wide: Vec<_> = invalid.encode_utf16().chain(Some(0)).collect();
        assert!(volume_name(&wide).is_err());
    }
    assert!(volume_name(&wide[..wide.len() - 1]).is_err());
    assert!(volume_name(&[0xd800, 0]).is_err());
}

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
    use super::volume_support::{
        open_payload, verify_filesystem, verify_payload, wait_for_volumes,
    };
    use super::{lock_image, vhd_support};
    use isohopper_helper::{
        windows_lock::{self, LockError, TargetVolumeProbe},
        writer::{RetainedDevice, write_image},
    };
    use std::{
        fs::{File, OpenOptions},
        io,
        os::windows::fs::OpenOptionsExt,
        sync::atomic::AtomicBool,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

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
        let (device_path, number) = vhd.physical_path()?;
        let read_only = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(device_path)?;
        vhd_support::assert_readback_binding(&read_only, number)?;
        // SAFETY: synchronous read-only whole-device handle from this owned
        // VHD only. No FILE_FLAG_OVERLAPPED and no other handle aliases.
        let mut probe =
            unsafe { TargetVolumeProbe::from_owned_handle(read_only.into(), &expected)? };
        assert_eq!(probe.coverage().device, expected);
        assert_eq!(probe.coverage().partition_style, 1);
        assert_eq!(probe.coverage().partitions.len(), 2);
        for partition in &probe.coverage().partitions {
            let independent = volumes
                .iter()
                .find(|volume| Some(volume.name.as_str()) == partition.volume_guid.as_deref())
                .expect("probe must bind the independently discovered volume GUID");
            assert_eq!(partition.start_offset, independent.start);
            assert_eq!(partition.length_bytes, independent.length);
            assert!(partition.volume_required);
        }
        probe.revalidate()?;
        // A held ordinary file cannot prevent read-only probing. Fresh file
        // opens while the probe lives independently show no volume lock/dismount.
        verify_payload(&mut held_file)?;
        verify_payload(&mut open_payload(&volumes[0])?)?;
        drop(probe);
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
            "VHD lock integration passed: read-only retained probe matches two independently discovered FAT32 extents without blocking payload access; open-file lock refusal followed by readable payloads and successful retry; retained locks deny file opens; drop restores both payloads; no USB hardware exercised"
        );
        Ok(())
    }
}
