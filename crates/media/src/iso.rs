// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded metadata inspection, not filesystem validation or a boot test.
//! Layout references: ECMA-119, El Torito 1.0, and UEFI 2.11 section 13.3.2.1.
//! No boot image is loaded, decompressed, mounted, or executed.
use serde::Serialize;
use std::io::{self, Read, Seek, SeekFrom};

const SECTOR: u64 = 2048;
pub const MAX_DESCRIPTORS: usize = 64;
pub const MAX_CATALOG_RECORDS: usize = 256;
pub const MAX_CATALOGS: usize = 8;

#[derive(Debug, Clone, Serialize)]
pub struct BootInspection {
    pub status: &'static str,
    pub iso9660: Option<Iso9660>,
    /// NSR signatures only. UDF anchors, files, and bootability are not validated.
    pub udf_identifiers: Vec<String>,
    pub udf_recognition_only: bool,
    pub catalogs: Vec<BootCatalog>,
    pub issues: Vec<String>,
    pub boot_tested: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Iso9660 {
    pub volume_label: String,
    pub volume_size: u64,
    pub logical_block_size: u16,
    pub descriptor_terminator_seen: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootCatalog {
    pub lba: u32,
    pub validation_platform_id: u8,
    pub validation_checksum_valid: bool,
    pub complete: bool,
    pub entries: Vec<BootEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BootEntry {
    pub platform_id: u8,
    pub platform: &'static str,
    pub bootable: bool,
    pub emulation: u8,
    pub load_rba: u32,
    pub load_offset: u64,
    /// BIOS initial load size or EFI extent, not a validated filesystem size.
    pub load_size: Option<u64>,
    pub size_interpretation: &'static str,
    pub selection_criteria_type: u8,
}

enum Problem {
    Io(io::Error),
    Invalid(String),
    Limit(&'static str),
    Unsupported(&'static str),
}
impl From<io::Error> for Problem {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
fn invalid(message: impl Into<String>) -> Problem {
    Problem::Invalid(message.into())
}

/// Inspect a retained read-only file using a size captured from that handle.
/// The caller must check the same handle's metadata again after inspection.
/// Malformed or unsupported metadata becomes explicit evidence; actual I/O
/// errors are returned. Reads are capped at 128 KiB of descriptors plus 8 KiB
/// of catalog records across all catalogs. Image-provided sizes never allocate.
pub fn inspect(reader: &mut (impl Read + Seek), file_size: u64) -> io::Result<BootInspection> {
    let mut result = BootInspection {
        status: "metadata-only",
        iso9660: None,
        udf_identifiers: Vec::new(),
        udf_recognition_only: true,
        catalogs: Vec::new(),
        issues: Vec::new(),
        boot_tested: false,
    };
    match inspect_inner(reader, file_size, &mut result) {
        Ok(()) => {
            if result.iso9660.is_none() && result.udf_identifiers.is_empty() {
                result.status = "unrecognized";
            }
        }
        Err(Problem::Io(error)) => return Err(error),
        Err(Problem::Invalid(message)) => {
            result.status = "invalid";
            result.issues.push(message);
        }
        Err(Problem::Limit(message)) => {
            result.status = "limit-exceeded";
            result.issues.push(message.into());
        }
        Err(Problem::Unsupported(message)) => {
            result.status = "partial";
            result.issues.push(message.into());
        }
    }
    Ok(result)
}

fn inspect_inner(
    reader: &mut (impl Read + Seek),
    file_size: u64,
    result: &mut BootInspection,
) -> Result<(), Problem> {
    let mut sector = [0; SECTOR as usize];
    let mut catalog_lbas = Vec::new();
    let mut seen_iso = false;
    let mut terminated = false;
    let mut ended = false;
    let mut iso_descriptor_end = 0;
    for index in 0..MAX_DESCRIPTORS {
        let offset = (16 + index as u64) * SECTOR;
        if offset >= file_size {
            ended = true;
            break;
        }
        read_at(reader, file_size, offset, &mut sector)?;
        let id = &sector[1..6];
        if id == b"CD001" {
            if terminated {
                return Err(invalid("ISO descriptor appears after the set terminator"));
            }
            seen_iso = true;
            iso_descriptor_end = offset + SECTOR;
            if sector[6] != 1 {
                return Err(invalid("unsupported ISO descriptor version"));
            }
            match sector[0] {
                0 => {
                    let system = &sector[7..39];
                    // El Torito uses NUL padding; accept space padding as well.
                    if system.starts_with(b"EL TORITO SPECIFICATION") {
                        if system[23..].iter().any(|&b| b != 0 && b != b' ') {
                            return Err(invalid("invalid El Torito identifier padding"));
                        }
                        let lba = le32(&sector[71..75]);
                        if !catalog_lbas.contains(&lba) {
                            if catalog_lbas.len() == MAX_CATALOGS {
                                return Err(Problem::Limit(
                                    "El Torito catalog count exceeds limit",
                                ));
                            }
                            catalog_lbas.push(lba);
                        }
                    }
                }
                1 => {
                    if result.iso9660.is_some() {
                        return Err(invalid("multiple ISO primary descriptors are ambiguous"));
                    }
                    result.iso9660 = Some(primary(&sector, file_size)?);
                }
                2 | 3 => {}
                255 => terminated = true,
                _ => return Err(invalid("unknown ISO volume descriptor type")),
            }
        } else if matches!(
            id,
            b"BEA01" | b"NSR02" | b"NSR03" | b"TEA01" | b"BOOT2" | b"CDW02"
        ) {
            if sector[0] != 0 || sector[6] != 1 {
                return Err(invalid("invalid UDF recognition descriptor header"));
            }
            if id == b"NSR02" || id == b"NSR03" {
                let id = String::from_utf8_lossy(id).into_owned();
                if !result.udf_identifiers.contains(&id) {
                    result.udf_identifiers.push(id);
                }
            }
        } else {
            ended = true;
            break;
        }
    }
    if !ended {
        return Err(Problem::Limit(
            "volume descriptor count exceeds inspection limit",
        ));
    }
    if seen_iso && (!terminated || result.iso9660.is_none()) {
        return Err(invalid(
            "ISO primary descriptor or set terminator is missing",
        ));
    }
    if let Some(primary) = result.iso9660.as_mut() {
        range(primary.volume_size, 0, iso_descriptor_end)?;
        primary.descriptor_terminator_seen = terminated;
        // A catalog cannot refer beyond either the advertised volume or file.
        let extent_limit = primary.volume_size.min(file_size);
        let mut records_read = 0;
        for lba in catalog_lbas {
            result.catalogs.push(BootCatalog {
                lba,
                validation_platform_id: 0,
                validation_checksum_valid: false,
                complete: false,
                entries: Vec::new(),
            });
            let catalog = result.catalogs.last_mut().expect("catalog just inserted");
            parse_catalog(reader, extent_limit, catalog, &mut records_read)?;
        }
    }
    Ok(())
}

fn primary(data: &[u8; 2048], file_size: u64) -> Result<Iso9660, Problem> {
    let blocks = both32(&data[80..88])?;
    let block_size = u16::from_le_bytes(data[128..130].try_into().unwrap());
    if block_size != u16::from_be_bytes(data[130..132].try_into().unwrap())
        || !matches!(block_size, 512 | 1024 | 2048)
    {
        return Err(invalid("invalid ISO logical block size"));
    }
    let volume_size = u64::from(blocks) * u64::from(block_size);
    if volume_size < 17 * SECTOR || volume_size > file_size || data[881] != 1 {
        return Err(invalid(
            "ISO volume size or file structure version is invalid",
        ));
    }
    if data[156] < 34 || data[181] & 2 == 0 {
        return Err(invalid("ISO root directory record is invalid"));
    }
    let root_lba = both32(&data[158..166])?;
    let root_size = both32(&data[166..174])?;
    let root_offset = (u64::from(root_lba) + u64::from(data[157])) * u64::from(block_size);
    if root_size == 0 {
        return Err(invalid("ISO root directory extent is empty"));
    }
    range(volume_size, root_offset, u64::from(root_size))?;
    let label = &data[40..72];
    if !label.iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err(invalid("ISO volume label contains invalid characters"));
    }
    Ok(Iso9660 {
        volume_label: String::from_utf8_lossy(label).trim_end().into(),
        volume_size,
        logical_block_size: block_size,
        descriptor_terminator_seen: false,
    })
}

fn parse_catalog(
    reader: &mut (impl Read + Seek),
    extent_limit: u64,
    catalog: &mut BootCatalog,
    records: &mut usize,
) -> Result<(), Problem> {
    let base = u64::from(catalog.lba) * SECTOR;
    let mut index = 0;
    let validation = catalog_record(reader, extent_limit, base, &mut index, records)?;
    catalog.validation_platform_id = validation[1];
    let sum = validation
        .as_chunks::<2>()
        .0
        .iter()
        .fold(0u16, |sum, word| {
            sum.wrapping_add(u16::from_le_bytes(*word))
        });
    catalog.validation_checksum_valid = sum == 0;
    if validation[0] != 1
        || validation[2..4] != [0, 0]
        || validation[30..32] != [0x55, 0xaa]
        || sum != 0
    {
        return Err(invalid(format!(
            "El Torito catalog {} validation entry is invalid",
            catalog.lba
        )));
    }
    let default = catalog_record(reader, extent_limit, base, &mut index, records)?;
    catalog
        .entries
        .push(boot_entry(&default, validation[1], true, extent_limit)?);
    let mut require_header = false;
    loop {
        let header = catalog_record(reader, extent_limit, base, &mut index, records)?;
        if header == [0; 32] && !require_header {
            catalog.complete = true;
            return Ok(());
        }
        if !matches!(header[0], 0x90 | 0x91) {
            return Err(invalid("El Torito section header is invalid or missing"));
        }
        let count = usize::from(u16::from_le_bytes(header[2..4].try_into().unwrap()));
        if count == 0 {
            return Err(invalid("El Torito section has no entries"));
        }
        if count > MAX_CATALOG_RECORDS - *records {
            return Err(Problem::Limit(
                "El Torito catalog record count exceeds limit",
            ));
        }
        for _ in 0..count {
            let record = catalog_record(reader, extent_limit, base, &mut index, records)?;
            catalog
                .entries
                .push(boot_entry(&record, header[1], false, extent_limit)?);
        }
        if header[0] == 0x91 {
            catalog.complete = true;
            return Ok(());
        }
        require_header = true;
    }
}

fn boot_entry(
    record: &[u8; 32],
    platform: u8,
    initial: bool,
    limit: u64,
) -> Result<BootEntry, Problem> {
    if !matches!(record[0], 0 | 0x88)
        || record[1] & 0x0f > 4
        || record[5] != 0
        || (initial && (record[1] & 0xf0 != 0 || record[12..].iter().any(|&b| b != 0)))
        || (!initial && record[1] & 0x10 != 0)
    {
        return Err(invalid("invalid El Torito boot entry"));
    }
    if !initial && record[1] & 0x20 != 0 {
        return Err(Problem::Unsupported(
            "El Torito selection-criteria extensions are not inspected",
        ));
    }
    let emulation = record[1] & 0x0f;
    if platform == 0xef && emulation != 0 {
        return Err(invalid("EFI El Torito entry must use no emulation"));
    }
    let bootable = record[0] == 0x88;
    let lba = le32(&record[8..12]);
    let offset = u64::from(lba) * SECTOR;
    let count = u16::from_le_bytes(record[6..8].try_into().unwrap());
    let (size, interpretation) = if !bootable && lba == 0 && count == 0 {
        (None, "not-advertised")
    } else {
        if lba == 0 {
            return Err(invalid("El Torito boot image has a zero load RBA"));
        }
        let (size, interpretation) = if platform == 0xef && count <= 1 {
            let size = limit
                .checked_sub(offset)
                .ok_or_else(|| invalid("EFI extent starts outside the volume"))?;
            (size, "efi-to-end-of-volume")
        } else {
            (
                u64::from(count) * 512,
                if platform == 0xef {
                    "efi-system-partition"
                } else {
                    "initial-load"
                },
            )
        };
        if size == 0 {
            return Err(invalid("El Torito boot image load extent is empty"));
        }
        range(limit, offset, size)?;
        (Some(size), interpretation)
    };
    Ok(BootEntry {
        platform_id: platform,
        platform: match platform {
            0 => "bios-x86",
            1 => "powerpc",
            2 => "mac",
            0xef => "efi",
            _ => "unknown",
        },
        bootable,
        emulation,
        load_rba: lba,
        load_offset: offset,
        load_size: size,
        size_interpretation: interpretation,
        selection_criteria_type: if initial { 0 } else { record[12] },
    })
}

fn catalog_record(
    reader: &mut (impl Read + Seek),
    limit: u64,
    base: u64,
    index: &mut u64,
    records: &mut usize,
) -> Result<[u8; 32], Problem> {
    if *records == MAX_CATALOG_RECORDS {
        return Err(Problem::Limit(
            "El Torito catalog record count exceeds limit",
        ));
    }
    let offset = index
        .checked_mul(32)
        .and_then(|n| base.checked_add(n))
        .ok_or_else(|| invalid("catalog offset overflow"))?;
    let mut data = [0; 32];
    read_at(reader, limit, offset, &mut data)?;
    *index += 1;
    *records += 1;
    Ok(data)
}

fn both32(bytes: &[u8]) -> Result<u32, Problem> {
    let value = le32(&bytes[..4]);
    if value != u32::from_be_bytes(bytes[4..8].try_into().unwrap()) {
        return Err(invalid("ISO little-endian and big-endian values disagree"));
    }
    Ok(value)
}
fn le32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}
fn range(limit: u64, offset: u64, size: u64) -> Result<(), Problem> {
    if offset.checked_add(size).is_none_or(|end| end > limit) {
        return Err(invalid(
            "metadata or boot extent exceeds the file or ISO volume",
        ));
    }
    Ok(())
}
fn read_at(
    reader: &mut (impl Read + Seek),
    limit: u64,
    offset: u64,
    data: &mut [u8],
) -> Result<(), Problem> {
    range(limit, offset, data.len() as u64)?;
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(data)?;
    Ok(())
}
