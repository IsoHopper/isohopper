// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_media::iso::{MAX_CATALOG_RECORDS, MAX_DESCRIPTORS, inspect};
use std::io::{self, Cursor, Read, Seek, SeekFrom};

const SECTOR: usize = 2048;

fn descriptor(data: &mut [u8], sector: usize, kind: u8) -> &mut [u8] {
    let out = &mut data[sector * SECTOR..(sector + 1) * SECTOR];
    out.fill(0);
    out[0] = kind;
    out[1..6].copy_from_slice(b"CD001");
    out[6] = 1;
    out
}

fn both32(out: &mut [u8], n: u32) {
    out[..4].copy_from_slice(&n.to_le_bytes());
    out[4..8].copy_from_slice(&n.to_be_bytes());
}

fn image() -> Vec<u8> {
    let mut data = vec![0; 128 * SECTOR];
    let pvd = descriptor(&mut data, 16, 1);
    pvd[40..72].fill(b' ');
    pvd[40..48].copy_from_slice(b"TEST ISO");
    both32(&mut pvd[80..88], 128);
    pvd[128..130].copy_from_slice(&2048u16.to_le_bytes());
    pvd[130..132].copy_from_slice(&2048u16.to_be_bytes());
    pvd[156] = 34;
    both32(&mut pvd[158..166], 24);
    both32(&mut pvd[166..174], 2048);
    pvd[181] = 2;
    pvd[881] = 1;
    boot_record(&mut data, 17, 25);
    descriptor(&mut data, 18, 255);
    catalog(&mut data, 25, 0);
    entry(&mut data[25 * SECTOR + 32..][..32], 0x88, 30, 4);
    data
}

fn boot_record(data: &mut [u8], sector: usize, lba: u32) {
    let br = descriptor(data, sector, 0);
    br[7..30].copy_from_slice(b"EL TORITO SPECIFICATION");
    br[71..75].copy_from_slice(&lba.to_le_bytes());
}

fn catalog(data: &mut [u8], lba: usize, platform: u8) {
    let validation = &mut data[lba * SECTOR..][..32];
    validation[0] = 1;
    validation[1] = platform;
    validation[30] = 0x55;
    validation[31] = 0xaa;
    checksum(validation);
}

fn checksum(validation: &mut [u8]) {
    validation[28..30].fill(0);
    let sum = validation
        .as_chunks::<2>()
        .0
        .iter()
        .fold(0u16, |sum, word| {
            sum.wrapping_add(u16::from_le_bytes(*word))
        });
    validation[28..30].copy_from_slice(&sum.wrapping_neg().to_le_bytes());
}

fn entry(out: &mut [u8], indicator: u8, lba: u32, sectors: u16) {
    out[0] = indicator;
    out[6..8].copy_from_slice(&sectors.to_le_bytes());
    out[8..12].copy_from_slice(&lba.to_le_bytes());
}

fn check(data: &[u8]) -> isohopper_media::iso::BootInspection {
    inspect(&mut Cursor::new(data), data.len() as u64).unwrap()
}

#[test]
fn inspects_bios_and_efi_sections_without_claiming_a_boot_test() {
    let mut data = image();
    let section = &mut data[25 * SECTOR + 64..];
    section[0] = 0x91;
    section[1] = 0xef;
    section[2..4].copy_from_slice(&2u16.to_le_bytes());
    entry(&mut section[32..64], 0x88, 31, 8);
    entry(&mut section[64..96], 0, 0, 0);
    let result = check(&data);
    assert_eq!(result.status, "metadata-only");
    assert!(!result.boot_tested);
    assert_eq!(result.iso9660.as_ref().unwrap().volume_label, "TEST ISO");
    let cat = &result.catalogs[0];
    assert!(cat.validation_checksum_valid && cat.complete);
    assert_eq!(cat.entries.len(), 3);
    assert_eq!(cat.entries[0].platform, "bios-x86");
    assert_eq!(cat.entries[0].load_size, Some(2048));
    assert_eq!(cat.entries[1].platform, "efi");
    assert_eq!(cat.entries[1].load_size, Some(4096));
    assert!(!cat.entries[2].bootable);
    assert_eq!(cat.entries[2].load_size, None);
}

#[test]
fn supports_multiple_sections_and_catalog_records() {
    let mut data = image();
    boot_record(&mut data, 18, 26);
    descriptor(&mut data, 19, 255);
    catalog(&mut data, 26, 0xef);
    entry(&mut data[26 * SECTOR + 32..][..32], 0x88, 40, 8);
    let section = &mut data[25 * SECTOR + 64..];
    section[0] = 0x90;
    section[1] = 0x01;
    section[2] = 1;
    entry(&mut section[32..64], 0x88, 32, 4);
    section[64] = 0x91;
    section[65] = 0xef;
    section[66] = 1;
    entry(&mut section[96..128], 0x88, 35, 4);
    let result = check(&data);
    assert_eq!(result.status, "metadata-only", "{:?}", result.issues);
    assert_eq!(result.catalogs.len(), 2);
    assert_eq!(result.catalogs[0].entries[1].platform, "powerpc");
    assert_eq!(result.catalogs[0].entries[2].platform_id, 0xef);
}

#[test]
fn efi_zero_or_one_sector_uses_extent_to_end_without_reading_it() {
    for count in [0, 1] {
        let mut data = image();
        catalog(&mut data, 25, 0xef);
        entry(&mut data[25 * SECTOR + 32..][..32], 0x88, 30, count);
        let result = check(&data);
        assert_eq!(result.status, "metadata-only");
        let entry = &result.catalogs[0].entries[0];
        assert_eq!(entry.load_size, Some((128 - 30) * SECTOR as u64));
        assert_eq!(entry.size_interpretation, "efi-to-end-of-volume");
    }
}

#[test]
fn recognizes_udf_only_and_bridge_sequences_without_claiming_filesystem_validation() {
    for bridge in [false, true] {
        let mut data = if bridge {
            image()
        } else {
            vec![0; 24 * SECTOR]
        };
        let start = if bridge { 19 } else { 16 };
        for (index, id) in [b"BEA01", b"NSR03", b"TEA01"].into_iter().enumerate() {
            let d = &mut data[(start + index) * SECTOR..][..SECTOR];
            d[1..6].copy_from_slice(id);
            d[6] = 1;
        }
        let result = check(&data);
        assert_eq!(result.status, "metadata-only");
        assert_eq!(result.udf_identifiers, ["NSR03"]);
        assert!(result.udf_recognition_only);
        assert_eq!(result.iso9660.is_some(), bridge);
    }
}

#[test]
fn corrupt_validation_and_entries_never_supply_a_complete_catalog() {
    for (offset, value) in [
        (0, 2),
        (2, 1),
        (28, 4),
        (30, 0),
        (31, 0),
        (32, 0x89),
        (33, 5),
        (37, 1),
    ] {
        let mut data = image();
        data[25 * SECTOR + offset] = value;
        let result = check(&data);
        assert_eq!(
            result.status, "invalid",
            "offset {offset}: {:?}",
            result.issues
        );
        assert!(!result.catalogs[0].complete);
    }
    let mut data = image();
    catalog(&mut data, 25, 0xef);
    data[25 * SECTOR + 33] = 1;
    assert_eq!(check(&data).status, "invalid");
}

#[test]
fn rejects_out_of_file_and_out_of_volume_extents_without_offset_wrapping() {
    for lba in [128, u32::MAX] {
        let mut data = image();
        data[17 * SECTOR + 71..17 * SECTOR + 75].copy_from_slice(&lba.to_le_bytes());
        assert_eq!(check(&data).status, "invalid");
        let mut data = image();
        entry(&mut data[25 * SECTOR + 32..][..32], 0x88, lba, u16::MAX);
        assert_eq!(check(&data).status, "invalid");
    }
    let mut data = image();
    both32(&mut data[16 * SECTOR + 80..16 * SECTOR + 88], 32);
    entry(&mut data[25 * SECTOR + 32..][..32], 0x88, 31, 8);
    assert_eq!(check(&data).status, "invalid");
}

#[test]
fn rejects_truncated_primary_and_catalog_with_explicit_evidence() {
    let data = image();
    assert_eq!(check(&data[..16 * SECTOR + 100]).status, "invalid");
    for len in [25 * SECTOR + 20, 25 * SECTOR + 50] {
        let mut short = data[..len].to_vec();
        both32(&mut short[16 * SECTOR + 80..16 * SECTOR + 88], 25);
        assert_eq!(check(&short).status, "invalid");
    }
    // A read error after a caller's size snapshot is an I/O error, not metadata success.
    assert!(inspect(&mut Cursor::new(&data[..100]), data.len() as u64).is_err());
}

#[test]
fn rejects_ambiguous_primary_sizes_root_extents_and_missing_terminator() {
    for offset in [80, 84, 128, 130, 158, 162, 166, 170, 181, 881] {
        let mut data = image();
        data[16 * SECTOR + offset] ^= 0xff;
        assert_eq!(check(&data).status, "invalid", "offset {offset}");
    }
    let mut data = image();
    data[18 * SECTOR..19 * SECTOR].fill(0);
    assert_eq!(check(&data).status, "invalid");
}

#[test]
fn descriptors_must_fit_the_advertised_volume_even_when_the_file_is_larger() {
    let mut data = image();
    both32(&mut data[16 * SECTOR + 80..16 * SECTOR + 88], 17);
    both32(&mut data[16 * SECTOR + 158..16 * SECTOR + 166], 0);
    // No catalog: the descriptor sequence alone must invalidate the volume.
    data[17 * SECTOR + 7] = b'X';
    assert_eq!(check(&data).status, "invalid");
}

#[test]
fn el_torito_identifier_is_exact_with_only_nul_or_space_padding() {
    for padding in [0, b' '] {
        let mut data = image();
        data[17 * SECTOR + 30..17 * SECTOR + 39].fill(padding);
        assert_eq!(check(&data).catalogs.len(), 1);
    }
    for padding in *b"\t\nX" {
        let mut data = image();
        data[17 * SECTOR + 30..17 * SECTOR + 39].fill(padding);
        let result = check(&data);
        assert!(result.catalogs.is_empty(), "{:?}", result.catalogs);
    }
    let mut data = image();
    data[17 * SECTOR + 7..17 * SECTOR + 39].fill(0);
    data[17 * SECTOR + 7] = b' ';
    data[17 * SECTOR + 8..17 * SECTOR + 31].copy_from_slice(b"EL TORITO SPECIFICATION");
    assert!(check(&data).catalogs.is_empty());
}

#[test]
fn excessive_catalogs_and_incomplete_sections_fail_explicitly() {
    let mut data = image();
    for index in 0..9 {
        boot_record(&mut data, 17 + index, 40 + index as u32);
    }
    descriptor(&mut data, 26, 255);
    assert_eq!(check(&data).status, "limit-exceeded");
    let mut data = image();
    let section = &mut data[25 * SECTOR + 64..];
    section[0] = 0x90;
    section[2] = 1;
    entry(&mut section[32..64], 0x88, 32, 4);
    assert_eq!(check(&data).status, "invalid");
    let section = &mut data[25 * SECTOR + 64..];
    section[0] = 0x91;
    section[33] = 0x20;
    let result = check(&data);
    assert_eq!(result.status, "partial");
    assert!(!result.catalogs[0].complete);
}

struct Sparse {
    pieces: Vec<(u64, Vec<u8>)>,
    size: u64,
    position: u64,
    bytes: usize,
}
impl Read for Sparse {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let n = output
            .len()
            .min(self.size.saturating_sub(self.position) as usize);
        output[..n].fill(0);
        for (start, bytes) in &self.pieces {
            let from = self.position.max(*start);
            let to = (self.position + n as u64).min(*start + bytes.len() as u64);
            if from < to {
                output[(from - self.position) as usize..(to - self.position) as usize]
                    .copy_from_slice(&bytes[(from - start) as usize..(to - start) as usize]);
            }
        }
        self.bytes += n;
        self.position += n as u64;
        Ok(n)
    }
}
impl Seek for Sparse {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.position = match position {
            SeekFrom::Start(n) => n,
            _ => return Err(io::Error::other("test reader permits absolute seeks only")),
        };
        Ok(self.position)
    }
}

#[test]
fn catalog_and_boot_offsets_above_four_gib_keep_full_width_without_image_allocation() {
    let mut data = image();
    let catalog_lba = (1u32 << 21) + 5;
    let total_blocks = catalog_lba + 20;
    both32(&mut data[16 * SECTOR + 80..16 * SECTOR + 88], total_blocks);
    data[17 * SECTOR + 71..17 * SECTOR + 75].copy_from_slice(&catalog_lba.to_le_bytes());
    let mut catalog = data[25 * SECTOR..26 * SECTOR].to_vec();
    entry(&mut catalog[32..64], 0x88, catalog_lba + 2, 4);
    let size = u64::from(total_blocks) * SECTOR as u64;
    let mut reader = Sparse {
        pieces: vec![(0, data), (u64::from(catalog_lba) * SECTOR as u64, catalog)],
        size,
        position: 0,
        bytes: 0,
    };
    let result = inspect(&mut reader, size).unwrap();
    assert_eq!(result.status, "metadata-only", "{:?}", result.issues);
    assert!(result.catalogs[0].entries[0].load_offset > u64::from(u32::MAX));
    assert!(reader.bytes < 10 * SECTOR);
}

struct Counted {
    cursor: Cursor<Vec<u8>>,
    bytes: usize,
    furthest: u64,
}
impl Read for Counted {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.cursor.read(buf)?;
        self.bytes += n;
        Ok(n)
    }
}
impl Seek for Counted {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let n = self.cursor.seek(position)?;
        self.furthest = self.furthest.max(n);
        Ok(n)
    }
}

#[test]
fn descriptor_and_catalog_floods_have_fixed_io_and_allocation_budgets() {
    let mut data = image();
    for sector in 18..16 + MAX_DESCRIPTORS {
        descriptor(&mut data, sector, 2);
    }
    let mut counted = Counted {
        cursor: Cursor::new(data),
        bytes: 0,
        furthest: 0,
    };
    let result = inspect(&mut counted, u64::MAX).unwrap();
    assert_eq!(result.status, "limit-exceeded");
    assert!(counted.bytes <= MAX_DESCRIPTORS * SECTOR);
    assert!(counted.furthest < ((16 + MAX_DESCRIPTORS) * SECTOR) as u64);
    let mut data = image();
    let section = &mut data[25 * SECTOR + 64..];
    section[0] = 0x91;
    section[2..4].copy_from_slice(&u16::MAX.to_le_bytes());
    let result = check(&data);
    assert_eq!(result.status, "limit-exceeded");
    assert!(result.catalogs[0].entries.len() < MAX_CATALOG_RECORDS);
}

#[test]
fn unknown_platform_is_reported_without_inventing_architecture_support() {
    let mut data = image();
    catalog(&mut data, 25, 0x55);
    let result = check(&data);
    assert_eq!(result.status, "metadata-only");
    assert_eq!(result.catalogs[0].entries[0].platform, "unknown");
    assert!(!result.boot_tested);
}

#[test]
fn scan_exposes_boot_metadata_for_iso_and_preserves_nested_path() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory.path().join("Windows")).unwrap();
    std::fs::write(directory.path().join("Windows/Win11.iso"), image()).unwrap();
    std::fs::write(directory.path().join("other.img"), b"raw").unwrap();
    let report = isohopper_media::scan(directory.path()).unwrap();
    let iso = report.images.iter().find(|e| e.extension == "iso").unwrap();
    assert_eq!(iso.relative_path, "Windows/Win11.iso");
    assert_eq!(iso.size, 128 * SECTOR as u64);
    assert_eq!(iso.boot_status, "not-boot-tested");
    assert_eq!(
        iso.boot_inspection.as_ref().unwrap().status,
        "metadata-only"
    );
    assert_eq!(
        iso.boot_inspection.as_ref().unwrap().catalogs[0].entries[0].platform,
        "bios-x86"
    );
    assert!(
        report
            .images
            .iter()
            .find(|e| e.extension == "img")
            .unwrap()
            .boot_inspection
            .is_none()
    );
}
