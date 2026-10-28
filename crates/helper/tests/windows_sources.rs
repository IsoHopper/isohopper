// SPDX-License-Identifier: GPL-3.0-or-later
#![cfg(windows)]

#[path = "support/lock_image.rs"]
mod lock_image;
#[allow(dead_code)]
#[path = "support/windows_vhd.rs"]
mod vhd_support;
#[allow(dead_code)]
#[path = "support/windows_volume.rs"]
mod volume_support;

use isohopper_helper::{
    windows_sources::{self, SourceError, SourceExtent},
    writer::write_image,
};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    sync::atomic::AtomicBool,
};
use volume_support::{open_payload, verify_payload, volume_extents, wait_for_volumes};

fn extent_tuples(extents: &[SourceExtent]) -> Vec<(u32, u64, u64)> {
    let mut extents: Vec<_> = extents
        .iter()
        .map(|extent| (extent.disk_number, extent.start_offset, extent.length_bytes))
        .collect();
    extents.sort();
    extents
}

#[test]
#[ignore = "creates only two owned 256 MiB temporary VHDX files; requires Windows administrator storage privileges"]
fn windows_sources_reject_target_extents_and_virtual_dependencies()
-> Result<(), Box<dyn std::error::Error>> {
    let _privilege = vhd_support::ManageVolumePrivilege::enable()?;
    // Declared before the VHD owners so error unwinding detaches both disks
    // before TempDir removes their backing files. No caller-supplied disk IDs.
    let directory = tempfile::tempdir()?;
    let image_path = directory.path().join("source-volume.img");
    let plan = lock_image::create(&image_path)?;
    let mut image = File::open(image_path)?;
    let digest = vhd_support::hash_exact(&mut image)?;
    let mut source_vhd =
        vhd_support::TemporaryVhd::create(directory.path().join("source-volume.vhdx"))?;
    source_vhd.attach(false)?;
    let mut seed_device = source_vhd.open_raw_device()?;
    let initial = seed_device.initial_snapshot().clone();
    assert!(initial.device_id.is_some());
    // The sole raw write is to this test's new, blank VHD, before filesystems
    // exist. Mapping checks below never write to either attached device.
    let report = write_image(
        &mut seed_device,
        &mut image,
        &initial,
        digest,
        &AtomicBool::new(false),
        |_| {},
    )?;
    assert_eq!(report.bytes_verified, lock_image::CAPACITY);
    drop(seed_device);
    source_vhd.detach()?;
    source_vhd.attach(false)?;
    let source_device = source_vhd.open_raw_device()?;
    let source_target = source_device.initial_snapshot().clone();
    assert_eq!(initial.device_id, source_target.device_id);
    drop(source_device);
    let volumes = wait_for_volumes(source_target.device_number, &plan)?;
    assert_eq!(volumes.len(), 2);

    let mut other_vhd =
        vhd_support::TemporaryVhd::create(directory.path().join("other-target.vhdx"))?;
    other_vhd.attach(false)?;
    let other_device = other_vhd.open_raw_device()?;
    let other_target = other_device.initial_snapshot().clone();
    assert_ne!(source_target.device_number, other_target.device_number);
    assert!(other_target.device_id.is_some());
    drop(other_device);

    for volume in &volumes {
        let independent = volume_extents(&volume.name)?;
        assert_eq!(
            independent,
            vec![(source_target.device_number, volume.start, volume.length)],
            "source volume must have the independently discovered GPT extent"
        );
        let mut source = open_payload(volume)?;
        verify_payload(&mut source)?;
        match windows_sources::bind_source(source, &source_target) {
            Err(SourceError::OnTarget { extents }) => {
                assert_eq!(extent_tuples(&extents), independent);
            }
            Err(error) => {
                return Err(format!("same-target source was not identified: {error:?}").into());
            }
            Ok(_) => return Err("source on target VHD was accepted".into()),
        }

        // An unrelated target does not turn VHD-backed storage into direct
        // physical storage. Missing ancestry proof must not be called safe.
        match windows_sources::bind_source(open_payload(volume)?, &other_target) {
            Err(SourceError::VirtualDependency) => {}
            Err(error) => {
                return Err(format!("VHD ancestry was not identified: {error:?}").into());
            }
            Ok(_) => return Err("VHD-backed source was accepted for a different target".into()),
        }
        verify_payload(&mut open_payload(volume)?)?;
    }

    // Exercise a successful mapping using an ordinary host file, with no
    // special-case bypass for CI storage. Unsupported host ancestry fails with
    // evidence, rather than skipping or inventing a direct physical mapping.
    let host_path = directory.path().join("host-source.efi");
    std::fs::write(&host_path, lock_image::payload())?;
    let binding = windows_sources::bind_source(File::open(&host_path)?, &source_target)
        .map_err(|error| format!("ordinary host source mapping failed: {error:?}"))?;
    let independent = volume_extents(binding.volume_guid())?;
    assert!(!independent.is_empty());
    assert!(independent.iter().all(|extent| {
        extent.0 != source_target.device_number && extent.0 != other_target.device_number
    }));
    assert_eq!(extent_tuples(binding.extents()), independent);
    verify_payload(&mut binding.source_file().try_clone()?)?;
    assert!(matches!(
        binding.revalidate(&other_target),
        Err(SourceError::Changed)
    ));
    binding.revalidate(&source_target)?;
    verify_payload(&mut binding.source_file().try_clone()?)?;
    // The mapper detects changes; source write exclusion is the caller's job.
    // Mutate only this test's host file through an independent open handle.
    let original_length = binding.source_file().metadata()?.len();
    let mut writer = OpenOptions::new().append(true).open(&host_path)?;
    writer.write_all(&[0xa5])?;
    writer.sync_all()?;
    drop(writer);
    assert_eq!(binding.source_file().metadata()?.len(), original_length + 1);
    assert!(matches!(
        binding.revalidate(&source_target),
        Err(SourceError::Changed)
    ));
    drop(binding);

    // Keep both virtual-disk owners attached until every retained source and
    // volume handle has closed. Explicit detach reports cleanup errors.
    other_vhd.detach()?;
    source_vhd.detach()?;
    println!(
        "Source mapping integration passed: both GPT/FAT volumes rejected on target with independently verified extents; VHD ancestry rejected for another owned target; ordinary host file mapped and revalidated, then length mutation rejected; no USB hardware exercised"
    );
    Ok(())
}
