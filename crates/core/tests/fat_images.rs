// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::{fat, layout, virtualdisk};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

fn payload(size: usize) -> Vec<u8> {
    let mut b = vec![0; size.max(512)];
    for (i, v) in b.iter_mut().enumerate().skip(512) {
        *v = (i % 251) as u8;
    }
    b[..2].copy_from_slice(b"MZ");
    b[60..64].copy_from_slice(&128_u32.to_le_bytes());
    b[128..132].copy_from_slice(b"PE\0\0");
    b[132..134].copy_from_slice(&0x8664_u16.to_le_bytes());
    b[134..136].copy_from_slice(&1_u16.to_le_bytes());
    b[148..150].copy_from_slice(&240_u16.to_le_bytes());
    b[152..154].copy_from_slice(&0x20b_u16.to_le_bytes());
    b[220..222].copy_from_slice(&10_u16.to_le_bytes());
    b
}
fn read(f: &mut File, offset: u64, size: usize) -> Vec<u8> {
    let mut b = vec![0; size];
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.read_exact(&mut b).unwrap();
    b
}
fn u16le(b: &[u8]) -> u16 {
    u16::from_le_bytes(b.try_into().unwrap())
}
fn u32le(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().unwrap())
}
fn entry_cluster(e: &[u8]) -> u32 {
    (u32::from(u16le(&e[20..22])) << 16) | u32::from(u16le(&e[26..28]))
}

#[test]
fn fat32_geometry_meets_real_cluster_minimum() {
    let a = fat::geometry(64 << 20, 512, 5000).unwrap();
    assert_eq!(a.fat_sectors, 1009);
    assert_eq!(a.data_clusters, 129022);
    assert_eq!(a.file_clusters, 10);
    let b = fat::geometry(512 << 20, 4096, 5000).unwrap();
    assert_eq!(b.fat_sectors, 128);
    assert_eq!(b.data_clusters, 130784);
    assert_eq!(b.file_clusters, 2);
    for (size, sector, len) in [
        (64 << 20, 4096, 512),
        (1, 512, 512),
        (u64::MAX, 512, 512),
        (64 << 20, 0, 512),
        (64 << 20, 1024, 512),
        (64 << 20, 512, 0),
        (64 << 20, 512, 64 << 20),
        (64 << 20, 512, u64::from(u32::MAX) + 1),
    ] {
        assert!(
            fat::geometry(size, sector, len).is_err(),
            "{size}/{sector}/{len}"
        );
    }
}

#[test]
fn tiny_volumes_fail_without_arithmetic_panics() {
    for sector in [512, 4096] {
        for sectors in 1..1024 {
            assert!(fat::geometry(sectors * sector, sector, 512).is_err());
        }
    }
}

#[test]
fn invalid_pe_payload_never_creates_output() {
    let mut cases = vec![vec![], vec![0; 512]];
    for offset in [0, 128, 132, 152, 220] {
        let mut b = payload(512);
        b[offset] ^= 1;
        cases.push(b);
    }
    let mut outside = payload(512);
    outside[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
    cases.push(outside);
    let mut sections = payload(512);
    sections[134..136].copy_from_slice(&u16::MAX.to_le_bytes());
    cases.push(sections);
    let mut optional = payload(512);
    optional[148..150].copy_from_slice(&8_u16.to_le_bytes());
    cases.push(optional);
    let p = layout::plan(256 << 20, 512, false).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for (i, b) in cases.iter().enumerate() {
        let path = dir.path().join(format!("bad{i}"));
        assert!(fat::validate_efi_x64(b).is_err());
        assert!(virtualdisk::create_bootable(&path, &p, b).is_err());
        assert!(!path.exists());
    }
    let path = dir.path().join("oversized");
    assert!(virtualdisk::create_bootable(&path, &p, &payload(64 << 20)).is_err());
    assert!(!path.exists());
}

#[test]
fn both_boot_slots_have_independently_readable_efi_trees() {
    for (sector, size) in [(512, 256 << 20), (4096, 2 << 30)] {
        let p = layout::plan(size, sector, false).unwrap();
        let expected = payload((sector * 257 + 27) as usize);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot.img");
        virtualdisk::create_bootable(&path, &p, &expected).unwrap();
        virtualdisk::verify_bootable(&path, &expected).unwrap();
        virtualdisk::verify(&path).unwrap();
        let mut f = File::open(&path).unwrap();
        for (slot, part) in p.partitions[1..3].iter().enumerate() {
            let offset = part.start_lba * sector;
            let boot = read(&mut f, offset, sector as usize);
            assert_eq!(&boot[510..512], &[0x55, 0xaa]);
            assert_eq!(u16le(&boot[11..13]), sector as u16);
            assert_eq!(boot[13], 1);
            assert_eq!(boot[16], 2);
            assert_eq!(&boot[82..90], b"FAT32   ");
            assert_eq!(
                &boot[71..82],
                if slot == 0 {
                    b"ISOHOPPER-A"
                } else {
                    b"ISOHOPPER-B"
                }
            );
            assert_eq!(boot, read(&mut f, offset + 6 * sector, sector as usize));
            let reserved = u64::from(u16le(&boot[14..16]));
            let fats = u64::from(u32le(&boot[36..40]));
            let data = offset + (reserved + 2 * fats) * sector;
            let fsinfo = read(&mut f, offset + sector, sector as usize);
            assert_eq!(u32le(&fsinfo[..4]), 0x41615252);
            assert_eq!(u32le(&fsinfo[484..488]), 0x61417272);
            assert_eq!(u32le(&fsinfo[508..512]), 0xaa550000);
            assert_eq!(fsinfo, read(&mut f, offset + 7 * sector, sector as usize));
            let fat_table = read(&mut f, offset + reserved * sector, (fats * sector) as usize);
            assert_eq!(
                fat_table,
                read(
                    &mut f,
                    offset + (reserved + fats) * sector,
                    (fats * sector) as usize
                )
            );
            let mut directory = u32le(&boot[44..48]);
            for name in [b"EFI        ", b"BOOT       "] {
                let entries = read(
                    &mut f,
                    data + u64::from(directory - 2) * sector,
                    sector as usize,
                );
                let entry = entries
                    .as_chunks::<32>()
                    .0
                    .iter()
                    .find(|e| &e[..11] == name)
                    .unwrap();
                assert_eq!(entry[11], 0x10);
                directory = entry_cluster(entry);
            }
            let entries = read(
                &mut f,
                data + u64::from(directory - 2) * sector,
                sector as usize,
            );
            let file = entries
                .as_chunks::<32>()
                .0
                .iter()
                .find(|e| &e[..11] == b"BOOTX64 EFI")
                .unwrap();
            assert_eq!(u32le(&file[28..32]) as usize, expected.len());
            let mut cluster = entry_cluster(file);
            let mut actual = Vec::new();
            let mut traversed = 0;
            while cluster < 0x0fff_fff8 {
                assert!(cluster >= 2);
                actual.extend(read(
                    &mut f,
                    data + u64::from(cluster - 2) * sector,
                    sector as usize,
                ));
                cluster =
                    u32le(&fat_table[cluster as usize * 4..cluster as usize * 4 + 4]) & 0x0fff_ffff;
                traversed += 1;
                assert!(traversed <= expected.len().div_ceil(sector as usize));
            }
            assert!(actual[expected.len()..].iter().all(|b| *b == 0));
            actual.truncate(expected.len());
            assert_eq!(actual, expected);
        }
        assert_eq!(
            read(&mut f, p.partitions[0].start_lba * sector, 512),
            vec![0; 512]
        );
    }
}

#[test]
fn bootable_writer_refuses_overwrite_and_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keep");
    fs::write(&path, b"preserve").unwrap();
    let p = layout::plan(256 << 20, 512, false).unwrap();
    let b = payload(512);
    assert!(virtualdisk::create_bootable(&path, &p, &b).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"preserve");
    #[cfg(unix)]
    {
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(virtualdisk::create_bootable(&link, &p, &b).is_err());
        assert!(virtualdisk::verify_bootable(&link, &b).is_err());
    }
}

#[test]
fn bootable_verification_detects_metadata_and_payload_corruption() {
    let p = layout::plan(256 << 20, 512, false).unwrap();
    let b = payload(2500);
    for slot in 1..3 {
        for region in [0, 1, 6, 7, 32, 1041, 2050, 2053, 2054] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("boot");
            virtualdisk::create_bootable(&path, &p, &b).unwrap();
            let mut f = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let offset = (p.partitions[slot].start_lba + region) * 512;
            let mut byte = read(&mut f, offset, 1);
            byte[0] ^= 1;
            f.seek(SeekFrom::Start(offset)).unwrap();
            f.write_all(&byte).unwrap();
            assert!(
                virtualdisk::verify_bootable(&path, &b).is_err(),
                "slot {slot} region {region}"
            );
        }
    }
}

fn power_location(
    file: &mut File,
    partition: &layout::Partition,
    sector: u64,
) -> (u64, u32, Vec<u8>) {
    let base = partition.start_lba * sector;
    let boot = read(file, base, sector as usize);
    let reserved = u64::from(u16le(&boot[14..16]));
    let fat_sectors = u64::from(u32le(&boot[36..40]));
    let data = base + (reserved + 2 * fat_sectors) * sector;
    let root_cluster = u64::from(u32le(&boot[44..48]));
    let root = read(file, data + (root_cluster - 2) * sector, sector as usize);
    let entry = root
        .as_chunks::<32>()
        .0
        .iter()
        .find(|e| &e[..11] == b"IHPOWER CFG")
        .expect("root power file");
    assert_eq!(entry[11], 0x20);
    assert_eq!(u32le(&entry[28..32]), 8);
    let cluster = entry_cluster(entry);
    let fat = read(
        file,
        base + reserved * sector,
        (fat_sectors * sector) as usize,
    );
    assert_eq!(
        u32le(&fat[cluster as usize * 4..cluster as usize * 4 + 4]),
        0x0fff_ffff
    );
    (data + u64::from(cluster - 2) * sector, cluster, boot)
}

#[test]
fn power_preferences_are_independently_readable_in_both_boot_slots() {
    for (sector, size) in [(512, 256 << 20), (4096, 2 << 30)] {
        for mask in [0, 7] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("power.img");
            let plan = layout::plan(size, sector, false).unwrap();
            let payload = payload(5000);
            virtualdisk::create_bootable_configured(&path, &plan, &payload, mask).unwrap();
            virtualdisk::verify_bootable(&path, &payload).unwrap();
            let mut file = File::open(path).unwrap();
            for partition in &plan.partitions[1..3] {
                let (offset, _, boot) = power_location(&mut file, partition, sector);
                let config = read(&mut file, offset, sector as usize);
                assert_eq!(&config[..8], &[b'I', b'H', b'P', b'W', 1, mask, 0, 0]);
                assert!(config[8..].iter().all(|b| *b == 0));
                let total = u32le(&boot[32..36]);
                let reserved = u32::from(u16le(&boot[14..16]));
                let fats = u32le(&boot[36..40]);
                let clusters = total - reserved - 2 * fats;
                let info = read(
                    &mut file,
                    (partition.start_lba + 1) * sector,
                    sector as usize,
                );
                assert_eq!(
                    u32le(&info[488..492]),
                    clusters - 4 - payload.len().div_ceil(sector as usize) as u32
                );
            }
        }
    }
}

#[test]
fn reserved_power_mask_bits_fail_before_output_creation() {
    let directory = tempfile::tempdir().unwrap();
    let plan = layout::plan(256 << 20, 512, false).unwrap();
    for mask in [8, 128, 255] {
        let path = directory.path().join(format!("bad-{mask}.img"));
        assert!(
            virtualdisk::create_bootable_configured(&path, &plan, &payload(512), mask).is_err()
        );
        assert!(!path.exists());
    }
}

#[test]
fn power_file_corruption_and_slot_disagreement_are_rejected() {
    for (sector, size) in [(512, 256 << 20), (4096, 2 << 30)] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("power.img");
        let plan = layout::plan(size, sector, false).unwrap();
        let payload = payload(5000);
        virtualdisk::create_bootable(&path, &plan, &payload).unwrap();
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        for partition in &plan.partitions[1..3] {
            let (offset, _, _) = power_location(&mut file, partition, sector);
            let original = read(&mut file, offset, 8);
            assert_eq!(&original, b"IHPW\x01\x07\x00\x00");
            for (index, value) in [(0, b'X'), (4, 2), (5, 128), (6, 1), (7, 1), (5, 0)] {
                file.seek(SeekFrom::Start(offset + index)).unwrap();
                file.write_all(&[value]).unwrap();
                assert!(
                    virtualdisk::verify_bootable(&path, &payload).is_err(),
                    "sector={sector}, index={index}, value={value}"
                );
                file.seek(SeekFrom::Start(offset)).unwrap();
                file.write_all(&original).unwrap();
            }
        }
    }
}

#[test]
fn geometry_reserves_space_for_the_power_file() {
    for (bytes, sector) in [(64 << 20, 512), (512 << 20, 4096)] {
        let geometry = fat::geometry(bytes, sector, 512).unwrap();
        let maximum = u64::from(geometry.data_clusters - 4) * sector;
        assert!(fat::geometry(bytes, sector, maximum).is_ok());
        assert!(fat::geometry(bytes, sector, maximum + 1).is_err());
    }
}
