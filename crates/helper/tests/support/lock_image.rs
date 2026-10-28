// SPDX-License-Identifier: GPL-3.0-or-later
//! A test-only GPT adaptation of real core-generated FAT32 volumes.
//! This never changes production layout rules or formats an attached device.
use isohopper_core::{
    layout::{self, Layout},
    virtualdisk,
};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

pub const CAPACITY: u64 = 256 * 1024 * 1024;
const BASIC_DATA: [u8; 16] = [
    0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
];
const ENTRIES_BYTES: usize = 128 * 128;

pub fn payload() -> Vec<u8> {
    let mut bytes = vec![0x41; 1536];
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

pub fn create(path: &Path) -> Result<Layout, Box<dyn std::error::Error>> {
    let plan = layout::plan(CAPACITY, 512, false)?;
    virtualdisk::create_bootable(path, &plan, &payload())?;
    virtualdisk::verify_bootable(path, &payload())?;
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    // Expose two normal data volumes so this test exercises filesystem locks,
    // independent of Windows' ESP access policy. Remove the unformatted data
    // partition and preserve both FAT32 byte ranges exactly.
    let mut entries = read(&mut file, 1024, ENTRIES_BYTES)?;
    entries[..128].fill(0);
    for i in [1, 2] {
        entries[i * 128..i * 128 + 16].copy_from_slice(&BASIC_DATA);
    }
    for (header_lba, entries_lba) in [(1, 2), (plan.total_sectors - 1, plan.total_sectors - 33)] {
        let mut header = read(&mut file, header_lba * 512, 512)?;
        header[88..92].copy_from_slice(&crc32(&entries).to_le_bytes());
        header[16..20].fill(0);
        let crc = crc32(&header[..92]);
        header[16..20].copy_from_slice(&crc.to_le_bytes());
        file.seek(SeekFrom::Start(entries_lba * 512))?;
        file.write_all(&entries)?;
        file.seek(SeekFrom::Start(header_lba * 512))?;
        file.write_all(&header)?;
    }
    file.sync_all()?;
    verify(&mut file, &plan)?;
    Ok(plan)
}

pub fn verify(file: &mut File, plan: &Layout) -> io::Result<()> {
    let bad = || io::Error::other("invalid adapted test GPT");
    if !file.metadata()?.is_file() || file.metadata()?.len() != CAPACITY {
        return Err(bad());
    }
    let mut previous = None;
    for (header_lba, entries_lba, other) in [
        (1, 2, plan.total_sectors - 1),
        (plan.total_sectors - 1, plan.total_sectors - 33, 1),
    ] {
        let mut header = read(file, header_lba * 512, 512)?;
        if &header[..8] != b"EFI PART"
            || number32(&header[12..16]) != 92
            || number64(&header[24..32]) != header_lba
            || number64(&header[32..40]) != other
            || number64(&header[72..80]) != entries_lba
            || number32(&header[80..84]) != 128
            || number32(&header[84..88]) != 128
        {
            return Err(bad());
        }
        let expected_crc = number32(&header[16..20]);
        header[16..20].fill(0);
        if crc32(&header[..92]) != expected_crc {
            return Err(bad());
        }
        let entries = read(file, entries_lba * 512, ENTRIES_BYTES)?;
        if crc32(&entries) != number32(&header[88..92])
            || entries[..128].iter().any(|byte| *byte != 0)
            || entries[384..].iter().any(|byte| *byte != 0)
        {
            return Err(bad());
        }
        for i in [1, 2] {
            let entry = &entries[i * 128..(i + 1) * 128];
            if entry[..16] != BASIC_DATA
                || number64(&entry[32..40]) != plan.partitions[i].start_lba
                || number64(&entry[40..48]) != plan.partitions[i].end_lba
                || entry[48..56] != [0; 8]
            {
                return Err(bad());
            }
        }
        if previous.as_ref().is_some_and(|bytes| bytes != &entries) {
            return Err(bad());
        }
        previous = Some(entries);
    }
    Ok(())
}

fn number32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}
fn number64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}
fn read(file: &mut File, offset: u64, count: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0; count];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
        }
    }
    !crc
}
