// SPDX-License-Identifier: GPL-3.0-or-later
//! In-memory import of the pinned upstream Linux release archive. No archive
//! member is written to the filesystem or executed. Callers supply the archive;
//! this module performs no download and does not authenticate a publisher.

use super::{CORE_BYTES, FIRMWARE_BYTES, Payloads};
use crate::virtualdisk::{VirtualDiskError, invalid};
use lzma_rust2::{Action, CheckType, Status, XzStream};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read};

mod member;

pub const ARCHIVE_BYTES: usize = 20_320_548;
pub const ARCHIVE_SHA256: &str = "d86ff9de63d94c8b8f1f6b14d23c55af4b88e8207bf2893890892a6a97b1ad54";
const TAR_BYTES: usize = 24_207_360;
const XZ_MEMORY_KIB: u32 = 64 * 1024;
const XZ_SHA256: [&str; 2] = [
    "97d70bf738a6e8d72fae6eb1a8993ceb4ac8bdc92570f2ff87bcd9aef3723431",
    "19174f133c4df8acda4423b1bc40ae69961773ef54e286ffd8c42fefaf6f174f",
];

/// Owned decoded buffers accepted through both the archive and payload pins.
/// The only view is the existing builder's verified, borrowed payload type.
pub struct Imported {
    boot: Vec<u8>,
    core: Vec<u8>,
    firmware: Vec<u8>,
}

impl Imported {
    pub fn payloads(&self) -> Payloads<'_> {
        Payloads {
            boot: &self.boot,
            core: &self.core,
            firmware: &self.firmware,
        }
    }
}

/// Verify the complete exact-size archive before parsing any compressed data,
/// then import only the fixed regular members into bounded owned buffers.
pub fn import(archive: &[u8]) -> Result<Imported, VirtualDiskError> {
    if archive.len() != ARCHIVE_BYTES {
        return Err(invalid("engine archive size differs from release pin"));
    }
    if hex::encode(Sha256::digest(archive)) != ARCHIVE_SHA256 {
        return Err(invalid("engine archive SHA256 differs from release pin"));
    }
    let tar = decode_gzip(archive, TAR_BYTES)?;
    if tar.len() != TAR_BYTES {
        return Err(invalid("engine tar size differs from release profile"));
    }
    let [boot, core_xz, firmware_xz] = selected_members(&tar)?;
    drop(tar);
    for (bytes, expected) in [(&core_xz, XZ_SHA256[0]), (&firmware_xz, XZ_SHA256[1])] {
        if hex::encode(Sha256::digest(bytes)) != expected {
            return Err(invalid(
                "compressed engine payload SHA256 differs from release pin",
            ));
        }
    }
    let core = decode_xz(&core_xz, CORE_BYTES, XZ_MEMORY_KIB)?;
    drop(core_xz);
    let firmware = decode_xz(&firmware_xz, FIRMWARE_BYTES, XZ_MEMORY_KIB)?;
    Payloads::verify(&boot, &core, &firmware)?;
    Ok(Imported {
        boot,
        core,
        firmware,
    })
}

fn decode_gzip(input: &[u8], limit: usize) -> Result<Vec<u8>, VirtualDiskError> {
    // BufRead retains bytes past the first member, unlike the Read adapter.
    let mut decoder = flate2::bufread::GzDecoder::new(input);
    let mut output = Vec::with_capacity(limit);
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = decoder.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if count > limit - output.len() {
            return Err(invalid("gzip output exceeds engine tar bound"));
        }
        output.extend_from_slice(&buffer[..count]);
    }
    if !decoder.into_inner().is_empty() {
        return Err(invalid("trailing gzip data or additional member"));
    }
    Ok(output)
}

fn selected_members(input: &[u8]) -> Result<[Vec<u8>; 3], VirtualDiskError> {
    if input.len() > TAR_BYTES || !input.len().is_multiple_of(512) {
        return Err(invalid("tar input exceeds bound or is not block aligned"));
    }
    let mut archive = tar::Archive::new(input);
    let mut selected: [Option<Vec<u8>>; 3] = [None, None, None];
    let mut names = BTreeSet::new();
    let mut end_of_members = 0;
    // Raw mode makes GNU/PAX extension records visible so we can reject them
    // rather than interpreting alternate names, sizes or sparse extents.
    for (index, entry) in archive.entries()?.raw(true).enumerate() {
        if index >= 256 {
            return Err(invalid("too many engine archive members"));
        }
        let mut entry = entry?;
        let header = entry.header();
        if header.as_gnu().is_none() || header.as_bytes()[157..257].iter().any(|b| *b != 0) {
            return Err(invalid("unsupported tar header or link target"));
        }
        let (name, payload) =
            member::validate(&header.path_bytes(), header.as_bytes()[156], entry.size())
                .map_err(invalid)?;
        if !names.insert(name) {
            return Err(invalid("duplicate engine archive member"));
        }
        let start = entry.raw_file_position();
        if entry.raw_header_position() != end_of_members || entry.size() > TAR_BYTES as u64 {
            return Err(invalid("tar member position or size exceeds bound"));
        }
        let end = start
            .checked_add(entry.size())
            .ok_or_else(|| invalid("tar member range overflow"))?;
        let padded = end
            .checked_add(511)
            .ok_or_else(|| invalid("tar padding overflow"))?
            / 512
            * 512;
        if padded > input.len() as u64
            || input[end as usize..padded as usize].iter().any(|b| *b != 0)
        {
            return Err(invalid("truncated tar member or nonzero padding"));
        }
        end_of_members = padded;
        if let Some(payload) = payload {
            let mut data = vec![0; member::SELECTED[payload].1 as usize];
            entry.read_exact(&mut data)?;
            selected[payload] = Some(data);
        }
    }
    let tail = &input[end_of_members as usize..];
    if tail.len() < 1024 || tail.iter().any(|b| *b != 0) {
        return Err(invalid(
            "missing tar terminator or nonzero trailing records",
        ));
    }
    let [boot, core, firmware] = selected;
    let missing = || invalid("engine archive is missing a required payload");
    Ok([
        boot.ok_or_else(missing)?,
        core.ok_or_else(missing)?,
        firmware.ok_or_else(missing)?,
    ])
}

fn decode_xz(input: &[u8], expected: usize, memory_kib: u32) -> Result<Vec<u8>, VirtualDiskError> {
    let mut decoder = XzStream::new_mem_limit(false, memory_kib);
    let mut output = Vec::with_capacity(expected);
    let mut consumed = 0;
    let mut buffer = [0; 64 * 1024];
    loop {
        let result = decoder.process(&input[consumed..], &mut buffer, Action::Finish)?;
        consumed += result.bytes_consumed;
        if result.bytes_produced > expected - output.len() {
            return Err(invalid("XZ output exceeds decoded payload bound"));
        }
        output.extend_from_slice(&buffer[..result.bytes_produced]);
        if result.status == Status::StreamEnd {
            if consumed != input.len()
                || output.len() != expected
                || decoder.check_type() != Some(CheckType::Crc32)
            {
                return Err(invalid(
                    "XZ stream length, completion or integrity-check type differs from profile",
                ));
            }
            return Ok(output);
        }
        if result.bytes_consumed == 0 && result.bytes_produced == 0 {
            return Err(invalid("XZ decoder made no progress"));
        }
    }
}

#[cfg(test)]
mod tests;
