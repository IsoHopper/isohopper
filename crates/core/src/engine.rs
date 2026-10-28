// SPDX-License-Identifier: GPL-3.0-or-later
//! New regular-file images for one pinned, externally supplied boot engine.
//!
//! This is separate from the A/B profile in [`crate::virtualdisk`]. The data
//! partition is left unformatted. Hash and readback success are not proof of OS
//! boot compatibility or Secure Boot support. No installer or formatter runs.
//! The fixed profile follows upstream commit
//! `6116894ab8abdf3ef8d43411a6732d34ee19214e`, specifically
//! `INSTALL/tool/ventoy_lib.sh` (GPT geometry) and
//! `INSTALL/tool/VentoyWorker.sh` (boot-region writes). No vendor bytes are embedded.

use crate::{
    layout::{DATA_TYPE_GUID, Layout, Partition},
    virtualdisk::{ImageIo, VirtualDiskError, check_identity, gpt, invalid, open_regular_read},
};
use same_file::Handle;
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

pub mod archive;

pub const VERSION: &str = "1.1.18";
pub const BOOT_BYTES: usize = 512;
pub const CORE_BYTES: usize = 1_048_064;
pub const FIRMWARE_BYTES: usize = 33_554_432;
pub const BOOT_SHA256: &str = "85b4b080765738ca96620c32d8182edddbaf6a36149162946d12aa1f9802bc44";
pub const CORE_SHA256: &str = "183f3d54be2d87ff1e149ef3de63cc71701d4129c134cabac3d9a76f1c5293da";
pub const FIRMWARE_SHA256: &str =
    "f56c3cabafc7560dbe164d5c67fe39181a302776d037a210a86239482d14ce88";
const CORE_PREFIX_BYTES: usize = 1_031_168;
const FIRMWARE_ATTRIBUTES: u64 = 0x8000_0000_0000_0000;
const SECTOR: u64 = 512;

/// A sealed, two-partition, 512-byte-sector GPT plan. Both partitions use the
/// Basic Data type; firmware has the NO_DRIVE_LETTER attribute. Geometry follows
/// Ventoy 1.1.18's aligned GPT profile, not this crate's A/B layout policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    layout: Layout,
}

impl Plan {
    pub fn new(size_bytes: u64, logical_sector_size: u64) -> Result<Self, VirtualDiskError> {
        if logical_sector_size != SECTOR {
            return Err(invalid("engine profile requires 512-byte logical sectors"));
        }
        if size_bytes == 0 || size_bytes > i64::MAX as u64 || !size_bytes.is_multiple_of(SECTOR) {
            return Err(invalid(
                "engine size must fit a signed offset and contain whole sectors",
            ));
        }
        let total_sectors = size_bytes / SECTOR;
        let firmware_sectors = FIRMWARE_BYTES as u64 / SECTOR;
        let start = total_sectors
            .checked_sub(firmware_sectors + 33)
            .ok_or_else(|| invalid("engine image too small"))?
            / 8
            * 8;
        if start < 4096 {
            return Err(invalid(
                "engine image requires at least 1 MiB of data space",
            ));
        }
        Ok(Self {
            layout: Layout {
                size_bytes,
                logical_sector_size: SECTOR,
                total_sectors,
                first_usable_lba: 34,
                last_usable_lba: total_sectors - 34,
                legacy: false,
                partitions: vec![
                    Partition {
                        number: 1,
                        name: "Ventoy".into(),
                        type_guid: DATA_TYPE_GUID.into(),
                        start_lba: 2048,
                        end_lba: start - 1,
                    },
                    Partition {
                        number: 2,
                        name: "VTOYEFI".into(),
                        type_guid: DATA_TYPE_GUID.into(),
                        start_lba: start,
                        end_lba: start + firmware_sectors - 1,
                    },
                ],
            },
        })
    }

    /// Read-only geometry for downstream staging. This is deliberately rejected
    /// by [`crate::layout::validate`], which accepts only the A/B profile.
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

    pub fn partition_attributes(&self) -> [u64; 2] {
        [0, FIRMWARE_ATTRIBUTES]
    }
}

/// Borrowed decoded bytes, accepted only at the compiled release sizes/hashes.
/// No caller-supplied digest or path can substitute a different engine. Matching
/// a release pin identifies bytes; it is not a publisher-signature assertion.
pub struct Payloads<'a> {
    boot: &'a [u8],
    core: &'a [u8],
    firmware: &'a [u8],
}

impl<'a> Payloads<'a> {
    pub fn verify(
        boot: &'a [u8],
        core: &'a [u8],
        firmware: &'a [u8],
    ) -> Result<Self, VirtualDiskError> {
        // Validate every length before hashing even the first payload.
        if boot.len() != BOOT_BYTES || core.len() != CORE_BYTES || firmware.len() != FIRMWARE_BYTES
        {
            return Err(invalid(
                "decoded engine payload size differs from release pin",
            ));
        }
        for (name, bytes, expected) in [
            ("boot", boot, BOOT_SHA256),
            ("core", core, CORE_SHA256),
            ("firmware", firmware, FIRMWARE_SHA256),
        ] {
            if hex::encode(Sha256::digest(bytes)) != expected {
                return Err(invalid(format!(
                    "{name} payload SHA256 differs from engine {VERSION} pin"
                )));
            }
        }
        Ok(Self {
            boot,
            core,
            firmware,
        })
    }
}

/// GPT identifiers use their 16-byte on-disk, mixed-endian representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifiers {
    pub disk_guid: [u8; 16],
    pub partition_guids: [[u8; 16]; 2],
    pub private_identity: [u8; 16],
    pub mbr_signature: [u8; 4],
}

#[derive(Debug)]
struct Region {
    offset: u64,
    bytes: u64,
    sha256: [u8; 32],
}

/// Builder-owned expected state for later readback. It cannot be deserialized or
/// constructed from renderer-supplied hashes. The receipt covers GPT, boot code,
/// the full firmware payload and the short unused tail; it does not describe a
/// formatted data partition or authorize any physical-device operation.
#[derive(Debug)]
pub struct Image {
    plan: Plan,
    identifiers: Identifiers,
    metadata: Vec<(u64, Vec<u8>)>,
    payload_regions: [Region; 2],
}

impl Image {
    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub fn identifiers(&self) -> &Identifiers {
        &self.identifiers
    }
}

/// Create exclusively, write through the retained new regular-file handle,
/// flush, and read back all initialized bytes. An error may leave an incomplete
/// new file. Existing paths are never overwritten. Data space remains sparse
/// and unformatted; a later formatter/copy stage must be separately verified.
pub fn create(
    path: impl AsRef<Path>,
    plan: &Plan,
    payloads: &Payloads<'_>,
) -> Result<Image, VirtualDiskError> {
    let path = path.as_ref();
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("engine image must be a regular file"));
    }
    let identity = Handle::from_file(file.try_clone()?)?;
    let image = initialize_empty_file(&mut file, plan, payloads)?;
    check_identity(path, &identity, plan.layout.size_bytes)?;
    Ok(image)
}

/// Compare a regular file against the exact saved builder receipt, including
/// generated identifiers, canonical entry fields and complete payload hashes.
/// This deliberately cannot infer an engine profile from arbitrary disk bytes.
/// It permits later data-partition formatting; data contents are outside this
/// metadata/payload check. External writes cannot be frozen by this observation.
pub fn verify(path: impl AsRef<Path>, expected: &Image) -> Result<(), VirtualDiskError> {
    let path = path.as_ref();
    let mut file = open_regular_read(path)?;
    let identity = Handle::from_file(file.try_clone()?)?;
    check_identity(path, &identity, expected.plan.layout.size_bytes)?;
    let before = file.metadata()?;
    verify_reader(&mut file, expected)?;
    let after = file.metadata()?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return Err(invalid("engine image changed during verification"));
    }
    check_identity(path, &identity, expected.plan.layout.size_bytes)
}

/// Initialize a caller-owned empty regular file through its retained handle.
/// The caller must supply exclusive creation provenance and access control;
/// this API cannot establish those properties from a handle. It never opens a
/// path or raw device, and refuses any nonempty or non-regular file before
/// mutation. On error, the caller owns cleanup of the incomplete file.
pub fn initialize_empty_file(
    file: &mut std::fs::File,
    plan: &Plan,
    payloads: &Payloads<'_>,
) -> Result<Image, VirtualDiskError> {
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() != 0 {
        return Err(invalid(
            "engine initialization requires an empty regular file",
        ));
    }
    let mut encoded = gpt::encode_engine(plan)?;
    let private_identity = gpt::new_guid()?;
    let mbr_signature = new_signature()?;
    let mbr = &mut encoded.writes[0].1;
    mbr[..446].copy_from_slice(&payloads.boot[..446]);
    mbr[92] = 0x22;
    mbr[384..400].copy_from_slice(&private_identity);
    mbr[440..444].copy_from_slice(&mbr_signature);
    let mut core = payloads.core[..CORE_PREFIX_BYTES].to_vec();
    core[500] = 0x23;
    let firmware_offset = plan.layout.partitions[1].start_lba * SECTOR;
    let tail_start = firmware_offset + FIRMWARE_BYTES as u64;
    let tail_bytes = (plan.layout.total_sectors - 33) * SECTOR - tail_start;
    encoded
        .writes
        .push((tail_start, vec![0; tail_bytes as usize]));
    let image = Image {
        plan: plan.clone(),
        identifiers: Identifiers {
            disk_guid: encoded.disk_guid,
            partition_guids: encoded
                .partition_guids
                .try_into()
                .map_err(|_| invalid("unexpected engine partition count"))?,
            private_identity,
            mbr_signature,
        },
        metadata: encoded.writes,
        payload_regions: [
            region(34 * SECTOR, &core),
            region(firmware_offset, payloads.firmware),
        ],
    };
    file.make_sparse()?;
    file.set_len(plan.layout.size_bytes)?;
    for (offset, data) in &image.metadata {
        write_at(file, *offset, data, plan.layout.size_bytes)?;
    }
    write_at(file, 34 * SECTOR, &core, plan.layout.size_bytes)?;
    write_at(
        file,
        firmware_offset,
        payloads.firmware,
        plan.layout.size_bytes,
    )?;
    file.sync_all()?;
    let before = file.metadata()?;
    verify_reader(file, &image)?;
    let after = file.metadata()?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return Err(invalid("engine image changed during readback"));
    }
    Ok(image)
}

fn new_signature() -> Result<[u8; 4], VirtualDiskError> {
    for _ in 0..8 {
        let mut signature = [0; 4];
        getrandom::fill(&mut signature)
            .map_err(|err| VirtualDiskError::Entropy(err.to_string()))?;
        if signature != [0; 4] {
            return Ok(signature);
        }
    }
    Err(invalid("could not generate nonzero MBR signature"))
}

fn region(offset: u64, bytes: &[u8]) -> Region {
    Region {
        offset,
        bytes: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}

fn write_at(
    file: &mut (impl Write + Seek),
    offset: u64,
    data: &[u8],
    size: u64,
) -> Result<(), VirtualDiskError> {
    if offset > size || data.len() as u64 > size - offset {
        return Err(invalid("engine write exceeds image bounds"));
    }
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)?;
    Ok(())
}

fn verify_reader(file: &mut (impl Read + Seek), expected: &Image) -> Result<(), VirtualDiskError> {
    for (offset, bytes) in &expected.metadata {
        let mut actual = vec![0; bytes.len()];
        file.seek(SeekFrom::Start(*offset))?;
        file.read_exact(&mut actual)?;
        if actual != *bytes {
            return Err(invalid(format!(
                "engine metadata differs at offset {offset}"
            )));
        }
    }
    let mut buffer = [0; 64 * 1024];
    for region in &expected.payload_regions {
        file.seek(SeekFrom::Start(region.offset))?;
        let mut remaining = region.bytes;
        let mut hash = Sha256::new();
        while remaining > 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            remaining -= count as u64;
        }
        let actual: [u8; 32] = hash.finalize().into();
        if actual != region.sha256 {
            return Err(invalid(format!(
                "engine payload differs at offset {}",
                region.offset
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
