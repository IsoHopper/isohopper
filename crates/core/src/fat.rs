// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal FAT32 volumes containing the removable-media x64 EFI boot path.
use crate::layout::{self, Layout, Partition};
use std::io::{Read, Seek, SeekFrom, Write};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum FatError {
    #[error(transparent)]
    Layout(#[from] layout::LayoutError),
    #[error("invalid FAT32 geometry: {0}")]
    Geometry(String),
    #[error("invalid x64 EFI payload: {0}")]
    Payload(String),
    #[error("invalid firmware power configuration: {0}")]
    Configuration(String),
    #[error("FAT32 read-back mismatch: {0}")]
    Corrupt(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("volume identifier generation failed: {0}")]
    Entropy(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub sector_size: u64,
    pub total_sectors: u32,
    pub fat_sectors: u32,
    pub data_start_sector: u32,
    pub data_clusters: u32,
    pub file_clusters: u32,
}

const RESERVED: u64 = 32;
const END_OF_CHAIN: u32 = 0x0fff_ffff;
const POWER_CLUSTER: u32 = 5;
const PAYLOAD_CLUSTER: u32 = 6;
const METADATA_CLUSTERS: u32 = 4;
pub const DEFAULT_POWER_MASK: u8 = 7;

/// One logical sector per cluster. FAT32 is determined by the data-cluster
/// count, never merely the informational text in its boot sector.
pub fn geometry(
    volume_bytes: u64,
    sector_size: u64,
    payload_len: u64,
) -> Result<Geometry, FatError> {
    let bad = |text: &str| FatError::Geometry(text.into());
    if ![512, 4096].contains(&sector_size) {
        return Err(bad("logical sector size must be 512 or 4096"));
    }
    if volume_bytes == 0
        || volume_bytes > i64::MAX as u64
        || !volume_bytes.is_multiple_of(sector_size)
    {
        return Err(bad("invalid or unaligned volume size"));
    }
    if payload_len == 0 || payload_len > u64::from(u32::MAX) {
        return Err(bad(
            "payload must be nonempty and fit the FAT32 file-size field",
        ));
    }
    let total = volume_bytes / sector_size;
    if total <= RESERVED || total > u64::from(u32::MAX) {
        return Err(bad("volume sector count does not fit FAT32"));
    }
    let fat_sectors = (total - RESERVED + 2).div_ceil(sector_size / 4 + 2);
    let data_start = RESERVED + 2 * fat_sectors;
    let clusters = total
        .checked_sub(data_start)
        .ok_or_else(|| bad("volume is too small for metadata"))?;
    if !(65_525..=0x0fff_ffed).contains(&clusters) {
        return Err(bad("data-cluster count is outside the FAT32 range"));
    }
    let file_clusters = payload_len.div_ceil(sector_size);
    if file_clusters + u64::from(METADATA_CLUSTERS) > clusters {
        return Err(bad(
            "payload does not fit after directory and configuration allocation",
        ));
    }
    if (clusters + 2) * 4 > fat_sectors * sector_size {
        return Err(bad("allocation table is too short"));
    }
    Ok(Geometry {
        sector_size,
        total_sectors: total as u32,
        fat_sectors: fat_sectors as u32,
        data_start_sector: data_start as u32,
        data_clusters: clusters as u32,
        file_clusters: file_clusters as u32,
    })
}

/// Structural checks only; this is not signature validation or proof that the
/// entry point will execute successfully on firmware.
pub fn validate_efi_x64(payload: &[u8]) -> Result<(), FatError> {
    let bad = |text: &str| FatError::Payload(text.into());
    if payload.len() < 64 || &payload[..2] != b"MZ" {
        return Err(bad("missing DOS header"));
    }
    let pe = u32::from_le_bytes(payload[60..64].try_into().expect("checked header")) as usize;
    let coff_end = pe
        .checked_add(24)
        .ok_or_else(|| bad("PE header offset overflow"))?;
    if pe < 64 || coff_end > payload.len() || &payload[pe..pe + 4] != b"PE\0\0" {
        return Err(bad("missing or out-of-bounds PE header"));
    }
    if read16(&payload[pe + 4..pe + 6]) != 0x8664 {
        return Err(bad("machine is not x64"));
    }
    let sections = usize::from(read16(&payload[pe + 6..pe + 8]));
    let optional_len = usize::from(read16(&payload[pe + 20..pe + 22]));
    let optional_end = coff_end
        .checked_add(optional_len)
        .ok_or_else(|| bad("optional header overflow"))?;
    if optional_len < 112 || optional_end > payload.len() {
        return Err(bad("missing or truncated PE32+ optional header"));
    }
    if read16(&payload[coff_end..coff_end + 2]) != 0x20b
        || read16(&payload[coff_end + 68..coff_end + 70]) != 10
    {
        return Err(bad("expected PE32+ EFI application"));
    }
    let section_end = optional_end
        .checked_add(sections * 40)
        .ok_or_else(|| bad("section table overflow"))?;
    if sections == 0 || sections > 96 || section_end > payload.len() {
        return Err(bad("missing or truncated section table"));
    }
    let image_size = u64::from(read32(&payload[coff_end + 56..coff_end + 60]));
    let header_size = u64::from(read32(&payload[coff_end + 60..coff_end + 64]));
    let entry = u64::from(read32(&payload[coff_end + 16..coff_end + 20]));
    let directories = u64::from(read32(&payload[coff_end + 108..coff_end + 112]));
    let section_alignment = u64::from(read32(&payload[coff_end + 32..coff_end + 36]));
    let file_alignment = u64::from(read32(&payload[coff_end + 36..coff_end + 40]));
    if !file_alignment.is_power_of_two()
        || !section_alignment.is_power_of_two()
        || file_alignment > 65536
        || section_alignment < file_alignment
        || (section_alignment < 4096 && section_alignment != file_alignment)
        || (section_alignment >= 4096 && file_alignment < 512)
        || !image_size.is_multiple_of(section_alignment)
        || !header_size.is_multiple_of(file_alignment)
    {
        return Err(bad("invalid PE section or file alignment"));
    }
    if read16(&payload[pe + 22..pe + 24]) & 2 == 0
        || header_size < section_end as u64
        || header_size > payload.len() as u64
        || image_size < header_size
        || directories * 8 > (optional_len - 112) as u64
    {
        return Err(bad("invalid executable, image, header, or directory size"));
    }
    let mut entry_in_code = false;
    let mut raw_ranges = Vec::new();
    let mut virtual_ranges = Vec::new();
    for section in payload[optional_end..section_end].as_chunks::<40>().0 {
        let size = u64::from(read32(&section[16..20]));
        let start = u64::from(read32(&section[20..24]));
        let address = u64::from(read32(&section[12..16]));
        let mapped = size.max(u64::from(read32(&section[8..12])));
        if size != 0 {
            if start < header_size
                || start + size > payload.len() as u64
                || !start.is_multiple_of(file_alignment)
                || !size.is_multiple_of(file_alignment)
                || (section_alignment < 4096 && start != address)
            {
                return Err(bad("section contents overlap headers or exceed payload"));
            }
            raw_ranges.push((start, start + size));
        }
        if mapped != 0 {
            if address < header_size
                || address + mapped > image_size
                || !address.is_multiple_of(section_alignment)
            {
                return Err(bad("section virtual extent exceeds image"));
            }
            virtual_ranges.push((address, address + mapped));
        }
        if entry >= address && entry < address + size && read32(&section[36..40]) & 0x2000_0000 != 0
        {
            entry_in_code = true;
        }
    }
    for ranges in [&mut raw_ranges, &mut virtual_ranges] {
        ranges.sort_unstable();
        if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
            return Err(bad("section extents overlap"));
        }
    }
    if entry == 0 || !entry_in_code {
        return Err(bad(
            "entry point is outside file-backed executable sections",
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct Volume {
    offset: u64,
    start_lba: u64,
    label: [u8; 11],
    id: u32,
    geometry: Geometry,
    power_mask: u8,
    utility_clusters: u32,
}

fn power_bytes(mask: u8) -> Result<[u8; 8], FatError> {
    if mask & !DEFAULT_POWER_MASK != 0 {
        return Err(FatError::Configuration("reserved mask bits are set".into()));
    }
    Ok([b'I', b'H', b'P', b'W', 1, mask, 0, 0])
}

fn decode_power(bytes: &[u8; 8]) -> Result<u8, FatError> {
    if &bytes[..4] != b"IHPW" || bytes[4] != 1 || bytes[6..] != [0, 0] {
        return Err(FatError::Configuration(
            "invalid magic, version, or reserved bytes".into(),
        ));
    }
    power_bytes(bytes[5])?;
    Ok(bytes[5])
}

fn planned_volumes(
    p: &Layout,
    payload: &[u8],
    power_mask: u8,
    utility: Option<&[u8]>,
) -> Result<[Volume; 2], FatError> {
    power_bytes(power_mask)?;
    layout::validate(p)?;
    validate_efi_x64(payload)?;
    if let Some(utility) = utility {
        validate_efi_x64(utility)?;
    }
    let make = |part: &Partition| -> Result<Volume, FatError> {
        let bytes = (part.end_lba - part.start_lba + 1) * p.logical_sector_size;
        let offset = part.start_lba * p.logical_sector_size;
        if offset > p.size_bytes || bytes > p.size_bytes - offset {
            return Err(FatError::Geometry("partition exceeds image".into()));
        }
        let label = part
            .name
            .as_bytes()
            .try_into()
            .map_err(|_| FatError::Geometry("boot label must be 11 bytes".into()))?;
        let geometry = geometry(bytes, p.logical_sector_size, payload.len() as u64)?;
        let utility_clusters = utility.map_or(0, |bytes| {
            (bytes.len() as u64).div_ceil(p.logical_sector_size)
        });
        if utility.is_some_and(|bytes| bytes.len() > u32::MAX as usize)
            || u64::from(geometry.file_clusters) + utility_clusters + u64::from(METADATA_CLUSTERS)
                > u64::from(geometry.data_clusters)
        {
            return Err(FatError::Geometry(
                "launcher and utility do not fit boot volume".into(),
            ));
        }
        Ok(Volume {
            offset,
            start_lba: part.start_lba,
            label,
            id: 0,
            geometry,
            power_mask,
            utility_clusters: utility_clusters as u32,
        })
    };
    Ok([make(&p.partitions[1])?, make(&p.partitions[2])?])
}

pub(crate) fn prepare(
    p: &Layout,
    payload: &[u8],
    power_mask: u8,
    utility: Option<&[u8]>,
) -> Result<[Volume; 2], FatError> {
    let mut volumes = planned_volumes(p, payload, power_mask, utility)?;
    let mut ids = [0; 8];
    getrandom::fill(&mut ids).map_err(|e| FatError::Entropy(e.to_string()))?;
    volumes[0].id = read32(&ids[..4]);
    volumes[1].id = read32(&ids[4..]);
    if volumes[0].id == volumes[1].id {
        volumes[1].id ^= 1;
    }
    Ok(volumes)
}

pub(crate) fn write_volumes<W: Write + Seek>(
    file: &mut W,
    volumes: &[Volume; 2],
    payload: &[u8],
    utility: Option<&[u8]>,
) -> Result<(), FatError> {
    for volume in volumes {
        visit_regions(volume, payload, utility, |offset, bytes| {
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(bytes)?;
            Ok(())
        })?;
    }
    Ok(())
}

pub(crate) fn verify_volumes<R: Read + Seek>(
    file: &mut R,
    volumes: &[Volume; 2],
    payload: &[u8],
    utility: Option<&[u8]>,
) -> Result<(), FatError> {
    for volume in volumes {
        visit_regions(volume, payload, utility, |offset, bytes| {
            let mut actual = vec![0; bytes.len()];
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut actual)?;
            if actual != bytes {
                return Err(FatError::Corrupt(format!(
                    "volume {} at byte {offset}",
                    String::from_utf8_lossy(&volume.label)
                )));
            }
            Ok(())
        })?;
    }
    Ok(())
}

pub(crate) fn verify_existing<R: Read + Seek>(
    file: &mut R,
    p: &Layout,
    payload: &[u8],
    utility: Option<&[u8]>,
) -> Result<(), FatError> {
    let mut volumes = planned_volumes(p, payload, DEFAULT_POWER_MASK, utility)?;
    for volume in &mut volumes {
        let mut id = [0; 4];
        file.seek(SeekFrom::Start(volume.offset + 67))?;
        file.read_exact(&mut id)?;
        volume.id = read32(&id);
        let offset = volume.offset
            + (u64::from(volume.geometry.data_start_sector) + u64::from(POWER_CLUSTER - 2))
                * volume.geometry.sector_size;
        let mut power = [0; 8];
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut power)?;
        volume.power_mask = decode_power(&power)?;
    }
    if volumes[0].power_mask != volumes[1].power_mask {
        return Err(FatError::Configuration(
            "boot slots have different power preferences".into(),
        ));
    }
    verify_volumes(file, &volumes, payload, utility)
}

fn visit_regions(
    v: &Volume,
    payload: &[u8],
    utility: Option<&[u8]>,
    mut visit: impl FnMut(u64, &[u8]) -> Result<(), FatError>,
) -> Result<(), FatError> {
    let g = &v.geometry;
    let sector = g.sector_size as usize;
    let mut checked = |relative: u64, bytes: &[u8]| -> Result<(), FatError> {
        let volume_bytes = u64::from(g.total_sectors) * g.sector_size;
        if relative > volume_bytes || bytes.len() as u64 > volume_bytes - relative {
            return Err(FatError::Geometry("write exceeds boot volume".into()));
        }
        visit(v.offset + relative, bytes)
    };
    let boot = boot_sector(v);
    let info = fsinfo(g, v.utility_clusters);
    let mut reserved = vec![0; RESERVED as usize * sector];
    for at in [0, 6] {
        reserved[at * sector..(at + 1) * sector].copy_from_slice(&boot);
    }
    for at in [1, 7] {
        reserved[at * sector..(at + 1) * sector].copy_from_slice(&info);
    }
    checked(0, &reserved)?;
    let mut table = vec![0; g.fat_sectors as usize * sector];
    put32(&mut table, 0, 0x0fff_fff8);
    put32(&mut table, 4, END_OF_CHAIN);
    for cluster in 2..PAYLOAD_CLUSTER {
        put32(&mut table, cluster as usize * 4, END_OF_CHAIN);
    }
    for (start, count) in [
        (PAYLOAD_CLUSTER, g.file_clusters),
        (PAYLOAD_CLUSTER + g.file_clusters, v.utility_clusters),
    ] {
        for i in 0..count {
            let cluster = start + i;
            put32(
                &mut table,
                cluster as usize * 4,
                if i + 1 == count {
                    END_OF_CHAIN
                } else {
                    cluster + 1
                },
            );
        }
    }
    for i in 0..2 {
        checked(
            (RESERVED + u64::from(g.fat_sectors) * i) * g.sector_size,
            &table,
        )?;
    }
    let mut root = vec![0; sector];
    directory_entry(&mut root[..32], &v.label, 0x08, 0, 0);
    directory_entry(&mut root[32..64], b"EFI        ", 0x10, 3, 0);
    directory_entry(&mut root[64..96], b"IHPOWER CFG", 0x20, POWER_CLUSTER, 8);
    if let Some(utility) = utility {
        directory_entry(
            &mut root[96..128],
            b"IHUTIL  EFI",
            0x20,
            PAYLOAD_CLUSTER + g.file_clusters,
            utility.len() as u32,
        );
    }
    let mut efi = vec![0; sector];
    directory_entry(&mut efi[..32], b".          ", 0x10, 3, 0);
    directory_entry(&mut efi[32..64], b"..         ", 0x10, 0, 0);
    directory_entry(&mut efi[64..96], b"BOOT       ", 0x10, 4, 0);
    let mut boot_dir = vec![0; sector];
    directory_entry(&mut boot_dir[..32], b".          ", 0x10, 4, 0);
    directory_entry(&mut boot_dir[32..64], b"..         ", 0x10, 3, 0);
    directory_entry(
        &mut boot_dir[64..96],
        b"BOOTX64 EFI",
        0x20,
        PAYLOAD_CLUSTER,
        payload.len() as u32,
    );
    let data = u64::from(g.data_start_sector) * g.sector_size;
    for (i, bytes) in [root, efi, boot_dir].iter().enumerate() {
        checked(data + i as u64 * g.sector_size, bytes)?;
    }
    let mut block = vec![0; sector];
    block[..8].copy_from_slice(&power_bytes(v.power_mask)?);
    checked(data + u64::from(POWER_CLUSTER - 2) * g.sector_size, &block)?;
    for (i, chunk) in payload.chunks(sector).enumerate() {
        block.fill(0);
        block[..chunk.len()].copy_from_slice(chunk);
        checked(
            data + (u64::from(PAYLOAD_CLUSTER - 2) + i as u64) * g.sector_size,
            &block,
        )?;
    }
    if let Some(utility) = utility {
        for (i, chunk) in utility.chunks(sector).enumerate() {
            block.fill(0);
            block[..chunk.len()].copy_from_slice(chunk);
            checked(
                data + (u64::from(PAYLOAD_CLUSTER - 2 + g.file_clusters) + i as u64)
                    * g.sector_size,
                &block,
            )?;
        }
    }
    Ok(())
}

fn boot_sector(v: &Volume) -> Vec<u8> {
    let g = &v.geometry;
    let mut b = vec![0; g.sector_size as usize];
    b[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    b[3..11].copy_from_slice(b"ISOHOPPR");
    put16(&mut b, 11, g.sector_size as u16);
    b[13] = 1;
    put16(&mut b, 14, RESERVED as u16);
    b[16] = 2;
    b[21] = 0xf8;
    put16(&mut b, 24, 63);
    put16(&mut b, 26, 255);
    // This is a legacy BIOS hint. UEFI uses the GPT partition's block device;
    // a start beyond this 32-bit field has no representable BIOS hint.
    put32(&mut b, 28, u32::try_from(v.start_lba).unwrap_or(0));
    put32(&mut b, 32, g.total_sectors);
    put32(&mut b, 36, g.fat_sectors);
    put32(&mut b, 44, 2);
    put16(&mut b, 48, 1);
    put16(&mut b, 50, 6);
    b[64] = 0x80;
    b[66] = 0x29;
    put32(&mut b, 67, v.id);
    b[71..82].copy_from_slice(&v.label);
    b[82..90].copy_from_slice(b"FAT32   ");
    b[510] = 0x55;
    b[511] = 0xaa;
    b
}

fn fsinfo(g: &Geometry, utility_clusters: u32) -> Vec<u8> {
    let mut b = vec![0; g.sector_size as usize];
    put32(&mut b, 0, 0x4161_5252);
    put32(&mut b, 484, 0x6141_7272);
    let free = g.data_clusters - METADATA_CLUSTERS - g.file_clusters - utility_clusters;
    put32(&mut b, 488, free);
    put32(
        &mut b,
        492,
        if free == 0 {
            u32::MAX
        } else {
            PAYLOAD_CLUSTER + g.file_clusters + utility_clusters
        },
    );
    put32(&mut b, 508, 0xaa55_0000);
    b
}

fn directory_entry(b: &mut [u8], name: &[u8; 11], attributes: u8, cluster: u32, size: u32) {
    b[..11].copy_from_slice(name);
    b[11] = attributes;
    put16(b, 16, 0x21);
    put16(b, 18, 0x21);
    put16(b, 24, 0x21);
    put16(b, 20, (cluster >> 16) as u16);
    put16(b, 26, cluster as u16);
    put32(b, 28, size);
}
fn read16(b: &[u8]) -> u16 {
    u16::from_le_bytes(b.try_into().expect("fixed-width field"))
}
fn read32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().expect("fixed-width field"))
}
fn put16(b: &mut [u8], at: usize, value: u16) {
    b[at..at + 2].copy_from_slice(&value.to_le_bytes());
}
fn put32(b: &mut [u8], at: usize, value: u32) {
    b[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::File, io};

    struct FaultIo {
        file: File,
        operation: &'static str,
        fail_at: usize,
        calls: usize,
    }

    impl FaultIo {
        fn fails(&mut self, operation: &str) -> bool {
            if self.operation != operation {
                return false;
            }
            let fails = self.calls == self.fail_at;
            self.calls += 1;
            fails
        }
    }

    impl Read for FaultIo {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.fails("read") {
                return Err(io::Error::other("injected read"));
            }
            self.file.read(bytes)
        }
    }

    impl Write for FaultIo {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fails("write") {
                return Err(io::Error::other("injected write"));
            }
            if self.fails("short") {
                return Ok(0);
            }
            self.file.write(bytes)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }

    impl Seek for FaultIo {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            if self.fails("seek") {
                return Err(io::Error::other("injected seek"));
            }
            self.file.seek(position)
        }
    }

    #[test]
    fn volume_io_failures_propagate_at_both_slots() {
        let p = layout::plan(256 << 20, 512, false).unwrap();
        let payload = vec![0; 1536];
        let volume = |part: &Partition| Volume {
            offset: part.start_lba * 512,
            start_lba: part.start_lba,
            label: part.name.as_bytes().try_into().unwrap(),
            id: part.number,
            geometry: geometry(64 << 20, 512, payload.len() as u64).unwrap(),
            power_mask: DEFAULT_POWER_MASK,
            utility_clusters: 0,
        };
        let volumes = [volume(&p.partitions[1]), volume(&p.partitions[2])];
        for operation in ["seek", "write", "short", "read"] {
            for fail_at in [0, 4, 10, 19] {
                let mut file = tempfile::tempfile().unwrap();
                file.set_len(p.size_bytes).unwrap();
                if operation == "read" {
                    write_volumes(&mut file, &volumes, &payload, None).unwrap();
                }
                let mut faulty = FaultIo {
                    file,
                    operation,
                    fail_at,
                    calls: 0,
                };
                let result = if operation == "read" {
                    verify_volumes(&mut faulty, &volumes, &payload, None)
                } else {
                    write_volumes(&mut faulty, &volumes, &payload, None)
                };
                assert!(
                    matches!(result, Err(FatError::Io(_))),
                    "{operation} at {fail_at}: {result:?}"
                );
            }
        }
    }
}
