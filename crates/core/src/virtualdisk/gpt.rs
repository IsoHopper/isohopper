// SPDX-License-Identifier: GPL-3.0-or-later
use super::{VirtualDiskError, invalid};
use crate::layout::{
    self, BIOS_TYPE_GUID, DATA_TYPE_GUID, EFI_TYPE_GUID, ENTRY_COUNT, ENTRY_SIZE, Layout, Partition,
};
use std::{
    collections::HashSet,
    io::{Read, Seek, SeekFrom},
};

const HEADER_SIZE: usize = 92;
type Segment = (u64, Vec<u8>);

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().expect("fixed-width GPT field"))
}
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().expect("fixed-width GPT field"))
}
fn put32(b: &mut [u8], offset: usize, value: u32) {
    b[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(b: &mut [u8], offset: usize, value: u64) {
    b[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn zero(b: &[u8]) -> bool {
    b.iter().all(|v| *v == 0)
}

fn crc32(b: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in b {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
        }
    }
    !crc
}

fn new_guid() -> Result<[u8; 16], VirtualDiskError> {
    let mut id = [0; 16];
    getrandom::fill(&mut id).map_err(|err| VirtualDiskError::Entropy(err.to_string()))?;
    id[7] = (id[7] & 15) | 0x40;
    id[8] = (id[8] & 63) | 0x80;
    Ok(id)
}

fn guid_bytes(text: &str) -> Result<[u8; 16], VirtualDiskError> {
    let bytes = hex::decode(text.replace('-', "")).map_err(|_| invalid("invalid type GUID"))?;
    let mut id: [u8; 16] = bytes
        .try_into()
        .map_err(|_| invalid("invalid type GUID length"))?;
    id[..4].reverse();
    id[4..6].reverse();
    id[6..8].reverse();
    Ok(id)
}

pub(super) fn encode(p: &Layout) -> Result<Vec<Segment>, VirtualDiskError> {
    let mut entries = vec![0; ENTRY_COUNT as usize * ENTRY_SIZE as usize];
    let disk = new_guid()?;
    for (i, part) in p.partitions.iter().enumerate() {
        let e = &mut entries[i * 128..(i + 1) * 128];
        e[..16].copy_from_slice(&guid_bytes(&part.type_guid)?);
        e[16..32].copy_from_slice(&new_guid()?);
        put64(e, 32, part.start_lba);
        put64(e, 40, part.end_lba);
        for (j, unit) in part.name.encode_utf16().enumerate() {
            e[56 + j * 2..58 + j * 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    let tail = p.total_sectors - 1 - entries.len() as u64 / p.logical_sector_size;
    let crc = crc32(&entries);
    let primary = header(p, 1, p.total_sectors - 1, 2, &disk, crc);
    let backup = header(p, p.total_sectors - 1, 1, tail, &disk, crc);
    Ok(vec![
        (0, protective_mbr(p)),
        (2 * p.logical_sector_size, entries.clone()),
        (tail * p.logical_sector_size, entries),
        ((p.total_sectors - 1) * p.logical_sector_size, backup),
        (p.logical_sector_size, primary),
    ])
}

fn protective_mbr(p: &Layout) -> Vec<u8> {
    let mut b = vec![0; p.logical_sector_size as usize];
    b[448] = 2;
    b[450] = 0xee;
    b[451..454].fill(0xff);
    put32(&mut b, 454, 1);
    put32(
        &mut b,
        458,
        (p.total_sectors - 1).min(u64::from(u32::MAX)) as u32,
    );
    b[510] = 0x55;
    b[511] = 0xaa;
    b
}

fn header(p: &Layout, my: u64, alternate: u64, entries: u64, id: &[u8; 16], crc: u32) -> Vec<u8> {
    let mut b = vec![0; p.logical_sector_size as usize];
    b[..8].copy_from_slice(b"EFI PART");
    put32(&mut b, 8, 0x10000);
    put32(&mut b, 12, HEADER_SIZE as u32);
    put64(&mut b, 24, my);
    put64(&mut b, 32, alternate);
    put64(&mut b, 40, p.first_usable_lba);
    put64(&mut b, 48, p.last_usable_lba);
    b[56..72].copy_from_slice(id);
    put64(&mut b, 72, entries);
    put32(&mut b, 80, ENTRY_COUNT);
    put32(&mut b, 84, ENTRY_SIZE);
    put32(&mut b, 88, crc);
    let sum = crc32(&b[..HEADER_SIZE]);
    put32(&mut b, 16, sum);
    b
}

pub(super) fn verify_reader<R: Read + Seek>(r: &mut R, size: u64) -> Result<(), VirtualDiskError> {
    inspect_reader(r, size).map(|_| ())
}

pub(super) fn inspect_reader<R: Read + Seek>(
    r: &mut R,
    size: u64,
) -> Result<Layout, VirtualDiskError> {
    let mut found = None;
    let mut failures = Vec::new();
    for sector in [512, 4096] {
        match verify_sector(r, size, sector) {
            Ok(p) => {
                if found.is_some() {
                    return Err(invalid("ambiguous logical sector size"));
                }
                found = Some(p);
            }
            Err(e @ VirtualDiskError::Io(_)) => return Err(e),
            Err(e) => failures.push(format!("{sector}-byte sectors: {e}")),
        }
    }
    found.ok_or_else(|| invalid(failures.join("; ")))
}

fn read_at<R: Read + Seek>(
    r: &mut R,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>, VirtualDiskError> {
    if offset > i64::MAX as u64 || len as u64 > i64::MAX as u64 - offset {
        return Err(invalid("read offset overflow"));
    }
    let mut b = vec![0; len];
    r.seek(SeekFrom::Start(offset))?;
    r.read_exact(&mut b)?;
    Ok(b)
}

fn verify_sector<R: Read + Seek>(
    r: &mut R,
    size: u64,
    sector: u64,
) -> Result<Layout, VirtualDiskError> {
    if size > i64::MAX as u64 || !size.is_multiple_of(sector) || size < sector * 6 {
        return Err(invalid("invalid image size"));
    }
    let total = size / sector;
    let entry_bytes = ENTRY_COUNT as usize * ENTRY_SIZE as usize;
    let entry_sectors = entry_bytes as u64 / sector;
    if total < 2 * entry_sectors + 4 {
        return Err(invalid("image too small for GPT"));
    }
    let primary = read_at(r, sector, sector as usize)?;
    let backup = read_at(r, size - sector, sector as usize)?;
    check_header(&primary, 1, total - 1, 2, total, sector)?;
    check_header(
        &backup,
        total - 1,
        1,
        total - 1 - entry_sectors,
        total,
        sector,
    )?;
    if primary[56..72] != backup[56..72] {
        return Err(invalid("disk GUID differs between headers"));
    }
    let entries = read_at(r, 2 * sector, entry_bytes)?;
    let mirror = read_at(r, (total - 1 - entry_sectors) * sector, entry_bytes)?;
    if entries != mirror {
        return Err(invalid("partition arrays differ"));
    }
    let crc = crc32(&entries);
    if crc != le32(&primary[88..92]) || crc != le32(&backup[88..92]) {
        return Err(invalid("partition checksum mismatch"));
    }
    let parts = check_entries(&entries, &primary[56..72])?;
    let mut p = layout::plan(size, sector, parts.len() == 4)?;
    p.partitions = parts;
    layout::validate(&p)?;
    if read_at(r, 0, sector as usize)? != protective_mbr(&p) {
        return Err(invalid("invalid protective MBR"));
    }
    Ok(p)
}

fn check_header(
    b: &[u8],
    my: u64,
    alternate: u64,
    entries: u64,
    total: u64,
    sector: u64,
) -> Result<(), VirtualDiskError> {
    if &b[..8] != b"EFI PART"
        || le32(&b[8..12]) != 0x10000
        || le32(&b[12..16]) != HEADER_SIZE as u32
    {
        return Err(invalid(
            "unsupported GPT signature, revision or header size",
        ));
    }
    let mut copy = b[..HEADER_SIZE].to_vec();
    copy[16..20].fill(0);
    if crc32(&copy) != le32(&b[16..20]) {
        return Err(invalid("header checksum mismatch"));
    }
    if !zero(&b[20..24]) || !zero(&b[HEADER_SIZE..]) {
        return Err(invalid("reserved header bytes are nonzero"));
    }
    if le64(&b[24..32]) != my || le64(&b[32..40]) != alternate || le64(&b[72..80]) != entries {
        return Err(invalid("invalid header locations"));
    }
    let entry_sectors = u64::from(ENTRY_COUNT) * u64::from(ENTRY_SIZE) / sector;
    if le64(&b[40..48]) != 2 + entry_sectors || le64(&b[48..56]) != total - entry_sectors - 2 {
        return Err(invalid("invalid usable range"));
    }
    if le32(&b[80..84]) != ENTRY_COUNT || le32(&b[84..88]) != ENTRY_SIZE {
        return Err(invalid("unsupported entry geometry"));
    }
    if zero(&b[56..72]) {
        return Err(invalid("missing disk GUID"));
    }
    Ok(())
}

fn check_entries(entries: &[u8], disk: &[u8]) -> Result<Vec<Partition>, VirtualDiskError> {
    let mut parts = Vec::new();
    let mut seen = HashSet::new();
    seen.insert(disk.to_vec());
    let mut ended = false;
    for (i, e) in entries.as_chunks::<128>().0.iter().enumerate() {
        if zero(e) {
            ended = true;
            continue;
        }
        if ended || i >= 4 {
            return Err(invalid("unexpected or noncontiguous partitions"));
        }
        if zero(&e[16..32]) || !seen.insert(e[16..32].to_vec()) {
            return Err(invalid("missing or duplicate partition GUID"));
        }
        let mut kind = None;
        for candidate in [DATA_TYPE_GUID, EFI_TYPE_GUID, BIOS_TYPE_GUID] {
            if e[..16] == guid_bytes(candidate)? {
                kind = Some(candidate);
                break;
            }
        }
        let kind = kind.ok_or_else(|| invalid("unsupported partition type"))?;
        if !zero(&e[48..56]) {
            return Err(invalid("unsupported partition attributes"));
        }
        let mut units = Vec::new();
        let mut name_ended = false;
        for unit in e[56..].as_chunks::<2>().0 {
            let unit = u16::from_le_bytes([unit[0], unit[1]]);
            if unit == 0 {
                name_ended = true;
                continue;
            }
            if name_ended {
                return Err(invalid("nonzero data after partition name"));
            }
            units.push(unit);
        }
        let name = String::from_utf16(&units).map_err(|_| invalid("invalid partition name"))?;
        parts.push(Partition {
            number: (i + 1) as u32,
            name,
            type_guid: kind.into(),
            start_lba: le64(&e[32..40]),
            end_lba: le64(&e[40..48]),
        });
    }
    if parts.len() != 3 && parts.len() != 4 {
        return Err(invalid("unexpected partition count"));
    }
    Ok(parts)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_standard_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }

    #[derive(Clone)]
    struct SparseMetadata {
        bytes: Vec<u8>,
        position: u64,
        size: u64,
    }
    impl Read for SparseMetadata {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            let count = (self.size.saturating_sub(self.position) as usize).min(out.len());
            for (i, byte) in out[..count].iter_mut().enumerate() {
                let pos = self.position + i as u64;
                *byte = if pos < 32768 {
                    self.bytes[pos as usize]
                } else if pos >= self.size - 32768 {
                    self.bytes[(32768 + pos - (self.size - 32768)) as usize]
                } else {
                    0
                };
            }
            self.position += count as u64;
            Ok(count)
        }
    }
    impl Seek for SparseMetadata {
        fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
            let next = match pos {
                SeekFrom::Start(v) => i128::from(v),
                SeekFrom::End(v) => i128::from(self.size) + i128::from(v),
                SeekFrom::Current(v) => i128::from(self.position) + i128::from(v),
            };
            self.position = u64::try_from(next).map_err(|_| std::io::Error::other("bad seek"))?;
            Ok(self.position)
        }
    }

    #[test]
    fn generated_metadata_mutations_are_rejected_without_panics() {
        for sector in [512, 4096] {
            let size = 2 << 30;
            let p = layout::plan(size, sector, false).unwrap();
            let segments = encode(&p).unwrap();
            let mut base = SparseMetadata {
                bytes: vec![0; 65536],
                position: 0,
                size,
            };
            let mut regions = Vec::new();
            for (offset, data) in segments {
                let packed = if offset >= size - 32768 {
                    32768 + offset - (size - 32768)
                } else {
                    offset
                } as usize;
                base.bytes[packed..packed + data.len()].copy_from_slice(&data);
                regions.push((packed, data.len()));
            }
            verify_reader(&mut base, size).unwrap();
            let mut state = 0x7182_9812_u64;
            for i in 0..500 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let (start, len) = regions[i % regions.len()];
                let mut broken = base.clone();
                broken.bytes[start + (state as usize % len)] ^= 1;
                assert!(verify_reader(&mut broken, size).is_err());
            }
        }
    }
}
