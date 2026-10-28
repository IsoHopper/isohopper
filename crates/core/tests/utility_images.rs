// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::{fat, layout, virtualdisk};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
};

fn efi(marker: u8) -> Vec<u8> {
    let mut bytes = vec![marker; 1536];
    bytes[..512].fill(0);
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&128u32.to_le_bytes());
    bytes[128..132].copy_from_slice(b"PE\0\0");
    bytes[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[134..136].copy_from_slice(&1u16.to_le_bytes());
    bytes[148..150].copy_from_slice(&240u16.to_le_bytes());
    bytes[150..152].copy_from_slice(&0x22u16.to_le_bytes());
    bytes[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[168..172].copy_from_slice(&4096u32.to_le_bytes());
    bytes[184..188].copy_from_slice(&4096u32.to_le_bytes());
    bytes[188..192].copy_from_slice(&512u32.to_le_bytes());
    bytes[208..212].copy_from_slice(&8192u32.to_le_bytes());
    bytes[212..216].copy_from_slice(&512u32.to_le_bytes());
    bytes[220..222].copy_from_slice(&10u16.to_le_bytes());
    bytes[260..264].copy_from_slice(&16u32.to_le_bytes());
    bytes[392..397].copy_from_slice(b".text");
    bytes[400..404].copy_from_slice(&1024u32.to_le_bytes());
    bytes[404..408].copy_from_slice(&4096u32.to_le_bytes());
    bytes[408..412].copy_from_slice(&1024u32.to_le_bytes());
    bytes[412..416].copy_from_slice(&512u32.to_le_bytes());
    bytes[428..432].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    bytes
}

fn u32le(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}
fn cluster(entry: &[u8]) -> u32 {
    (u32::from(u16::from_le_bytes(entry[20..22].try_into().unwrap())) << 16)
        | u32::from(u16::from_le_bytes(entry[26..28].try_into().unwrap()))
}
fn read(file: &mut std::fs::File, offset: u64, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(&mut bytes).unwrap();
    bytes
}

#[test]
fn utility_is_a_separate_root_file_with_complete_chains_in_both_slots() {
    for (sector, size) in [(512, 256 << 20), (4096, 2 << 30)] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("utility.img");
        let plan = layout::plan(size, sector, false).unwrap();
        let launcher = efi(0x41);
        let utility = efi(0x55);
        virtualdisk::create_bootable_with_utility(&path, &plan, &launcher, 3, &utility).unwrap();
        virtualdisk::verify_bootable_with_utility(&path, &launcher, &utility).unwrap();
        assert!(virtualdisk::verify_bootable(&path, &launcher).is_err());
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        for slot in &plan.partitions[1..3] {
            let base = slot.start_lba * sector;
            let boot = read(&mut file, base, sector as usize);
            let fat_start =
                base + u64::from(u16::from_le_bytes(boot[14..16].try_into().unwrap())) * sector;
            let fat_size = u64::from(u32le(&boot[36..40])) * sector;
            let data = fat_start + u64::from(boot[16]) * fat_size;
            let root = read(&mut file, data, sector as usize);
            let utility_entry = root
                .as_chunks::<32>()
                .0
                .iter()
                .find(|entry| &entry[..11] == b"IHUTIL  EFI")
                .unwrap();
            assert_eq!(utility_entry[11], 0x20);
            assert_eq!(u32le(&utility_entry[28..32]), utility.len() as u32);
            let mut at = cluster(utility_entry);
            let mut actual = Vec::new();
            let count = utility.len().div_ceil(sector as usize);
            for index in 0..count {
                assert!(
                    at >= 6,
                    "utility must not overlap directories or configuration"
                );
                actual.extend(read(
                    &mut file,
                    data + u64::from(at - 2) * sector,
                    sector as usize,
                ));
                let next = u32le(&read(&mut file, fat_start + u64::from(at) * 4, 4));
                let mirrored = u32le(&read(
                    &mut file,
                    fat_start + fat_size + u64::from(at) * 4,
                    4,
                ));
                assert_eq!(next, mirrored);
                if index + 1 == count {
                    assert!(next >= 0x0fff_fff8);
                } else {
                    at = next;
                }
            }
            assert_eq!(&actual[..utility.len()], utility);
            assert!(actual[utility.len()..].iter().all(|byte| *byte == 0));
            let info = read(&mut file, base + sector, sector as usize);
            let geom = fat::geometry(
                (slot.end_lba - slot.start_lba + 1) * sector,
                sector,
                launcher.len() as u64,
            )
            .unwrap();
            assert_eq!(
                u32le(&info[488..492]),
                geom.data_clusters - 4 - geom.file_clusters - count as u32
            );
        }
        let slot = &plan.partitions[2];
        let geom = fat::geometry(
            (slot.end_lba - slot.start_lba + 1) * sector,
            sector,
            launcher.len() as u64,
        )
        .unwrap();
        let utility_offset = slot.start_lba * sector
            + (u64::from(geom.data_start_sector) + 4 + u64::from(geom.file_clusters)) * sector;
        file.seek(SeekFrom::Start(utility_offset + 600)).unwrap();
        file.write_all(b"tampered").unwrap();
        assert!(virtualdisk::verify_bootable_with_utility(&path, &launcher, &utility).is_err());
    }
}

#[test]
fn malformed_utility_is_rejected_before_creating_an_image() {
    let directory = tempfile::tempdir().unwrap();
    let plan = layout::plan(256 << 20, 512, false).unwrap();
    let launcher = efi(0x41);
    for offset in [0, 128, 132, 152, 220] {
        let mut utility = efi(0x55);
        utility[offset] ^= 1;
        let path = directory.path().join(format!("bad-{offset}"));
        assert!(
            virtualdisk::create_bootable_with_utility(&path, &plan, &launcher, 7, &utility)
                .is_err()
        );
        assert!(!path.exists());
    }
    for (offset, value) in [
        (60, u32::MAX),
        (168, 0),
        (184, 0),
        (188, 3),
        (208, 0),
        (212, 0),
        (260, u32::MAX),
        (404, u32::MAX),
        (412, u32::MAX),
        (428, 0),
    ] {
        let mut utility = efi(0x55);
        utility[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        let path = directory.path().join(format!("bounds-{offset}"));
        assert!(
            virtualdisk::create_bootable_with_utility(&path, &plan, &launcher, 7, &utility)
                .is_err()
        );
        assert!(!path.exists());
    }
    let mut utility = efi(0x55);
    utility[134..136].copy_from_slice(&2u16.to_le_bytes());
    utility.copy_within(392..432, 432);
    assert!(
        fat::validate_efi_x64(&utility).is_err(),
        "overlapping sections must fail"
    );
}

#[test]
fn combined_files_must_fit_before_output_creation_and_existing_files_survive() {
    let directory = tempfile::tempdir().unwrap();
    let plan = layout::plan(256 << 20, 512, false).unwrap();
    let mut launcher = efi(0x41);
    let mut utility = efi(0x55);
    launcher.resize(40 << 20, 0);
    utility.resize(30 << 20, 0);
    let path = directory.path().join("full");
    assert!(
        virtualdisk::create_bootable_with_utility(&path, &plan, &launcher, 7, &utility).is_err()
    );
    assert!(!path.exists());
    std::fs::write(&path, b"keep").unwrap();
    assert!(virtualdisk::create_bootable_with_utility(&path, &plan, &efi(1), 7, &efi(2)).is_err());
    assert_eq!(std::fs::read(path).unwrap(), b"keep");
}
