// SPDX-License-Identifier: GPL-3.0-or-later
//! Only a newly created temporary VHDX is attached and modified. The fixture
//! has no formatted filesystem and neither attachment assigns drive letters.
#![cfg(windows)]
#[path = "support/windows_vhd.rs"]
mod support;
use isohopper_core::{layout, virtualdisk};
use isohopper_helper::{
    raw_image_job::{
        BootArtifactFingerprint, ImageFingerprint, PreparedRawImage, RawImageDescription,
        RawImageError,
    },
    windows_lock,
    windows_target::BoundTarget,
    writer::{CHUNK_BYTES, Phase, write_image},
};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{self, Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    sync::atomic::AtomicBool,
};
use support::{CAPACITY, ManageVolumePrivilege, TemporaryVhd, assert_readback_binding, hash_exact};
use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE};

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
    let source_bytes = source.metadata()?.len();

    let mut vhd = TemporaryVhd::create(directory.path().join("writer-test.vhdx"))?;
    vhd.attach(false)?;
    vhd.diagnose_device_ids()?;
    let first = vhd.open_raw_device()?;
    let first_id = first
        .initial_snapshot()
        .device_id
        .clone()
        .expect("VHD must expose a device-associated NAA-6 identifier");
    assert!(
        first.initial_snapshot().serial.is_empty(),
        "VHD fixture reports no hardware serial"
    );
    drop(first);
    vhd.detach()?;
    vhd.attach(false)?;
    let device = vhd.open_raw_device()?;
    let expected = device.initial_snapshot().clone();
    assert_eq!(expected.geometry.size_bytes, CAPACITY);
    assert_eq!(expected.geometry.logical_sector_size, 512);
    assert_eq!(expected.geometry.physical_sector_size, 4096);
    // Compare parsed device identity, independent of descriptor padding or
    // enumeration number. No serial is fabricated for a serial-less VHD.
    assert!(expected.serial.is_empty());
    assert_eq!(expected.device_id, Some(first_id));
    // This describes the actual retained image and target. The provenance is
    // only our generated sentinel input; this fixture contains no OS payload
    // and passing this test establishes neither bootability nor USB safety.
    let prepared = PreparedRawImage::new(RawImageDescription {
        target: expected.clone(),
        image: ImageFingerprint {
            bytes: source_bytes,
            sha256: expected_hash,
        },
        boot_artifacts: vec![BootArtifactFingerprint {
            role: "test_sentinel".into(),
            version: None,
            bytes: sentinel.len() as u64,
            sha256: Sha256::digest(&sentinel).into(),
        }],
    })?;
    let digest = prepared.digest();
    let challenge = prepared.challenge().to_owned();
    let mut pending = prepared.into_confirmation();
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert!(matches!(
        pending.confirm(&wrong_digest, &expected, &challenge),
        Err(RawImageError::DigestMismatch)
    ));
    let mut wrong_target = expected.clone();
    wrong_target.device_number ^= 1;
    assert!(matches!(
        pending.confirm(&digest, &wrong_target, &challenge),
        Err(RawImageError::TargetMismatch)
    ));
    assert!(matches!(
        pending.confirm(&digest, &expected, &format!("{challenge} ")),
        Err(RawImageError::ChallengeMismatch)
    ));
    let receipt = pending.confirm(&digest, &expected, &challenge)?;
    assert!(matches!(
        pending.confirm(&digest, &expected, &challenge),
        Err(RawImageError::AlreadyConfirmed)
    ));
    let confirmed = receipt.description();
    assert_eq!(confirmed.target(), &expected);
    assert_eq!(confirmed.image().bytes, source.metadata()?.len());
    assert_eq!(confirmed.image().sha256, expected_hash);
    // All rejected attempts and the single successful confirmation above
    // precede any volume lock or raw write. The receipt describes the job;
    // the disposable VHD fixture independently establishes the allowed target.
    let (physical_path, number) = vhd.physical_path()?;
    let read_only = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(physical_path)?;
    assert_readback_binding(&read_only, number)?;
    // SAFETY: this is a synchronous read-only whole-device handle obtained
    // only from the retained, newly created VHD fixture. No host disk selected.
    let binding = unsafe { BoundTarget::from_owned_handle(read_only.into(), confirmed.target())? };
    assert!(binding.observation().coverage.partitions.is_empty());
    let mut device = windows_lock::lock_observed(device, binding)?;
    assert_eq!(device.locked_volume_count(), 0);
    // The first write must revalidate the blank topology. Subsequent writes,
    // flushing and readback must remain bound to the same native device while
    // allowing the intended newly written GPT to replace that initial layout.
    let mut phases = Vec::new();
    let report = write_image(
        &mut device,
        &mut source,
        confirmed.target(),
        confirmed.image().sha256,
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
        "VHD integration passed: exact one-shot raw-image confirmation, checked target-to-lock handoff and first-write gate; {CAPACITY} bytes written and read back after intended GPT change; read-only reattachment digest and primary/backup GPT verified; generated test image only, no OS boot or USB hardware exercised"
    );
    Ok(())
}
