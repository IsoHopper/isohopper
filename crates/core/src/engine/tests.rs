// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{layout::DATA_TYPE_GUID, virtualdisk};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    sync::OnceLock,
};

fn payloads() -> Payloads<'static> {
    static BYTES: OnceLock<(Vec<u8>, Vec<u8>, Vec<u8>)> = OnceLock::new();
    let (boot, core, firmware) = BYTES.get_or_init(|| {
        let mut boot = vec![0x91; BOOT_BYTES];
        boot[444..446].fill(0);
        let mut core = vec![0x5a; CORE_BYTES];
        core[500] = 2;
        let mut firmware = vec![0x3c; FIRMWARE_BYTES];
        firmware[FIRMWARE_BYTES - 1] = 0xa7;
        (boot, core, firmware)
    });
    // Private unit-test seam only. Production callers cannot supply their own pins.
    Payloads {
        boot,
        core,
        firmware,
    }
}

fn read(path: &Path, offset: u64, bytes: usize) -> Vec<u8> {
    let mut file = File::open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut result = vec![0; bytes];
    file.read_exact(&mut result).unwrap();
    result
}

fn put(path: &Path, offset: u64, bytes: &[u8]) {
    let mut file = OpenOptions::new().write(true).open(path).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn crc(bytes: &[u8]) -> u32 {
    let mut value = !0_u32;
    for &byte in bytes {
        value ^= u32::from(byte);
        for _ in 0..8 {
            value = (value >> 1) ^ if value & 1 == 0 { 0 } else { 0xedb8_8320 };
        }
    }
    !value
}

fn checksum_header(header: &mut [u8]) {
    header[16..20].fill(0);
    let checksum = crc(&header[..92]);
    header[16..20].copy_from_slice(&checksum.to_le_bytes());
}

#[test]
fn engine_geometry_is_separate_and_bounded() {
    for (size, start) in [
        (256 << 20, 458_712),
        (2 << 30, 4_128_728),
        (64 << 30, 134_152_152),
    ] {
        let plan = Plan::new(size, 512).unwrap();
        let p = plan.layout();
        assert_eq!(p.partitions.len(), 2);
        assert_eq!(p.partitions[0].name, "Ventoy");
        assert_eq!(p.partitions[0].start_lba, 2048);
        assert_eq!(p.partitions[0].end_lba, start - 1);
        assert_eq!(p.partitions[1].name, "VTOYEFI");
        assert_eq!(p.partitions[1].start_lba, start);
        assert_eq!(p.partitions[1].end_lba, start + 65_535);
        assert!(
            p.partitions
                .iter()
                .all(|part| part.type_guid == DATA_TYPE_GUID)
        );
        assert_eq!(start % 8, 0);
        assert_eq!(p.first_usable_lba, 34);
        assert_eq!(p.last_usable_lba, size / 512 - 34);
        assert!(crate::layout::validate(p).is_err());
    }
    let minimum = (4096 + 65_536 + 33) * 512;
    assert!(Plan::new(minimum, 512).is_ok());
    for size in [
        0,
        512,
        minimum - 512,
        minimum + 1,
        u64::MAX,
        (i64::MAX as u64) + 1,
    ] {
        assert!(Plan::new(size, 512).is_err(), "size={size}");
    }
    for sector in [0, 1, 4096, u64::MAX] {
        assert!(Plan::new(256 << 20, sector).is_err());
    }
}

#[test]
fn production_payloads_reject_wrong_size_and_synthetic_hashes() {
    let p = payloads();
    for (boot, core, firmware) in [
        (&p.boot[..511], p.core, p.firmware),
        (p.boot, &p.core[..CORE_BYTES - 1], p.firmware),
        (p.boot, p.core, &p.firmware[..FIRMWARE_BYTES - 1]),
        (p.boot, p.core, p.firmware),
    ] {
        assert!(Payloads::verify(boot, core, firmware).is_err());
    }
}

#[test]
fn new_image_has_exact_profile_patches_full_firmware_and_blank_data() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.img");
    let plan = Plan::new(256 << 20, 512).unwrap();
    let p = payloads();
    let image = create(&path, &plan, &p).unwrap();
    assert_eq!(image.plan(), &plan);
    verify(&path, &image).unwrap();
    assert!(
        virtualdisk::verify(&path).is_err(),
        "A/B parser must not accept engine profile"
    );
    let mbr = read(&path, 0, 512);
    assert_eq!(mbr[92], 0x22);
    assert_eq!(&mbr[0..92], &p.boot[0..92]);
    assert_ne!(&mbr[384..400], &[0; 16]);
    assert_ne!(&mbr[440..444], &[0; 4]);
    assert_eq!(&mbr[444..448], &[0; 4]);
    assert_eq!(&mbr[448..454], &[2, 0, 0xee, 0xff, 0xff, 0xff]);
    assert_eq!(&mbr[454..458], &1_u32.to_le_bytes());
    assert_eq!(&mbr[510..512], &[0x55, 0xaa]);
    let entries = read(&path, 1024, 16_384);
    assert_eq!(u64::from_le_bytes(entries[48..56].try_into().unwrap()), 0);
    assert_eq!(
        u64::from_le_bytes(entries[176..184].try_into().unwrap()),
        FIRMWARE_ATTRIBUTES
    );
    assert!(entries[256..].iter().all(|byte| *byte == 0));
    assert_eq!(
        entries,
        read(&path, plan.layout().size_bytes - 33 * 512, 16_384)
    );
    let ids = image.identifiers();
    assert_ne!(ids.disk_guid, [0; 16]);
    assert_ne!(ids.partition_guids[0], ids.partition_guids[1]);
    for (index, id) in ids.partition_guids.iter().enumerate() {
        assert_ne!(id, &ids.disk_guid);
        assert_ne!(id, &[0; 16]);
        assert_eq!(&entries[index * 128 + 16..index * 128 + 32], id);
    }
    // Independently check both serialized headers/CRCs and exact Basic Data GUID.
    let basic_data = [
        0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99,
        0xc7,
    ];
    for index in 0..2 {
        assert_eq!(&entries[index * 128..index * 128 + 16], &basic_data);
    }
    let total = plan.layout().total_sectors;
    for (my, other, array) in [(1, total - 1, 2), (total - 1, 1, total - 33)] {
        let header = read(&path, my * 512, 512);
        assert_eq!(&header[..8], b"EFI PART");
        assert_eq!(&header[8..12], &0x10000_u32.to_le_bytes());
        assert_eq!(&header[12..16], &92_u32.to_le_bytes());
        assert_eq!(&header[24..32], &my.to_le_bytes());
        assert_eq!(&header[32..40], &other.to_le_bytes());
        assert_eq!(&header[40..48], &34_u64.to_le_bytes());
        assert_eq!(&header[48..56], &(total - 34).to_le_bytes());
        assert_eq!(&header[56..72], &ids.disk_guid);
        assert_eq!(&header[72..80], &array.to_le_bytes());
        assert_eq!(&header[80..84], &128_u32.to_le_bytes());
        assert_eq!(&header[84..88], &128_u32.to_le_bytes());
        assert_eq!(&header[88..92], &crc(&entries).to_le_bytes());
        assert!(
            header[20..24]
                .iter()
                .chain(&header[92..])
                .all(|byte| *byte == 0)
        );
        let mut checked = header.clone();
        checksum_header(&mut checked);
        assert_eq!(header, checked);
    }
    let mut expected_core = p.core[..CORE_PREFIX_BYTES].to_vec();
    expected_core[500] = 0x23;
    assert_eq!(read(&path, 34 * 512, CORE_PREFIX_BYTES), expected_core);
    assert_eq!(read(&path, 2048 * 512, 512), vec![0; 512]);
    let firmware_start = plan.layout().partitions[1].start_lba * 512;
    assert_eq!(read(&path, firmware_start, FIRMWARE_BYTES), p.firmware);
    let gap_start = firmware_start + FIRMWARE_BYTES as u64;
    assert_eq!(read(&path, gap_start, 7 * 512), vec![0; 7 * 512]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn repaired_crc_cannot_substitute_generated_identifiers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.img");
    let plan = Plan::new(256 << 20, 512).unwrap();
    let image = create(&path, &plan, &payloads()).unwrap();
    let mut entries = read(&path, 1024, 16_384);
    entries[16] ^= 0xff;
    let entry_crc = crc(&entries);
    put(&path, 1024, &entries);
    put(&path, plan.layout().size_bytes - 33 * 512, &entries);
    for offset in [512, plan.layout().size_bytes - 512] {
        let mut header = read(&path, offset, 512);
        header[56] ^= 0xff;
        header[88..92].copy_from_slice(&entry_crc.to_le_bytes());
        checksum_header(&mut header);
        put(&path, offset, &header);
    }
    assert!(verify(&path, &image).is_err());
}

#[test]
fn large_geometry_saturates_pmbr_and_aligns_without_large_allocation() {
    let plan = Plan::new(3 << 40, 512).unwrap();
    let encoded = gpt::encode_engine(&plan).unwrap();
    assert_eq!(&encoded.writes[0].1[458..462], &u32::MAX.to_le_bytes());
    assert_eq!(plan.layout().partitions[1].start_lba % 8, 0);
    let largest = Plan::new((i64::MAX as u64) / 512 * 512, 512).unwrap();
    assert!(largest.layout().partitions[1].end_lba <= largest.layout().last_usable_lba);
}

#[cfg(unix)]
#[test]
fn symlink_outputs_and_verification_aliases_are_rejected() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("target");
    fs::write(&target, b"preserve").unwrap();
    let link = dir.path().join("link");
    symlink(&target, &link).unwrap();
    let plan = Plan::new(256 << 20, 512).unwrap();
    assert!(create(&link, &plan, &payloads()).is_err());
    assert_eq!(fs::read(&target).unwrap(), b"preserve");
    let image_path = dir.path().join("image.img");
    let image = create(&image_path, &plan, &payloads()).unwrap();
    let alias = dir.path().join("alias");
    symlink(&image_path, &alias).unwrap();
    assert!(verify(&alias, &image).is_err());
}

#[test]
fn existing_output_is_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("existing");
    fs::write(&path, b"preserve existing bytes").unwrap();
    assert!(create(&path, &Plan::new(256 << 20, 512).unwrap(), &payloads()).is_err());
    assert_eq!(fs::read(path).unwrap(), b"preserve existing bytes");
}

#[test]
fn metadata_and_payload_changes_fail_saved_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("engine.img");
    let plan = Plan::new(256 << 20, 512).unwrap();
    let image = create(&path, &plan, &payloads()).unwrap();
    for offset in [
        92,
        384,
        440,
        512 + 16,
        1024 + 176,
        34 * 512 + 500,
        2048 * 512 - 1,
        (plan.layout().partitions[1].end_lba + 1) * 512 - 1,
        plan.layout().size_bytes - 512 + 56,
    ] {
        let byte = read(&path, offset, 1);
        put(&path, offset, &[byte[0] ^ 0xff]);
        assert!(verify(&path, &image).is_err(), "mutation at {offset}");
        put(&path, offset, &byte);
    }
    verify(&path, &image).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(plan.layout().size_bytes - 512)
        .unwrap();
    assert!(verify(&path, &image).is_err());
}
