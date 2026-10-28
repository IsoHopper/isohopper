// SPDX-License-Identifier: GPL-3.0-or-later
//! Immutable preparation descriptions and one-shot description confirmation.
//!
//! Fingerprints come from the caller except configuration bytes, which are
//! hashed here. This does not verify source handles, configuration semantics,
//! publisher authenticity, OS peers, target freshness or device safety. No
//! receipt grants write permission. A future coordinator must establish those
//! independently and retain the exact sources/target represented here.
use crate::writer::DeviceSnapshot;
use isohopper_core::layout::{self, Layout};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_SOURCES: usize = 128;
const MAX_PAYLOADS: usize = 32;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigurationFormat {
    Yaml,
    Toml,
}

#[derive(Clone, Debug)]
pub struct Configuration {
    pub format: ConfigurationFormat,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationFingerprint {
    pub format: ConfigurationFormat,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceMetadata {
    /// Session-local catalogue ID, never a path or OS handle value.
    pub source_id: String,
    /// Exact relative destination on the data volume. Ordering is significant.
    pub destination: String,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PayloadFingerprint {
    /// Unique logical role, not an executable command or a filesystem path.
    pub role: String,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

/// Input to one preparation description, not a generic operation envelope.
/// Other operations require their own domain/version; this cannot express eject.
#[derive(Clone, Debug)]
pub struct JobDescription {
    pub target: DeviceSnapshot,
    pub layout: Layout,
    pub sources: Vec<SourceMetadata>,
    pub configuration: Configuration,
    pub payloads: Vec<PayloadFingerprint>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum JobError {
    #[error("invalid job description: {0}")]
    InvalidDescription(&'static str),
    #[error("job digest changed")]
    DigestMismatch,
    #[error("target changed")]
    TargetMismatch,
    #[error("target confirmation does not match")]
    ChallengeMismatch,
    #[error("this job description was already confirmed")]
    AlreadyConfirmed,
}

/// Validated immutable description. No public mutation, deserialization or
/// cloning can alter an existing pending confirmation's meaning.
#[derive(Debug)]
pub struct PreparedJob {
    target: DeviceSnapshot,
    layout: Layout,
    sources: Vec<SourceMetadata>,
    configuration: ConfigurationFingerprint,
    payloads: Vec<PayloadFingerprint>,
    digest: [u8; 32],
    challenge: String,
}

impl PreparedJob {
    pub fn new(description: JobDescription) -> Result<Self, JobError> {
        validate(&description)?;
        let configuration = ConfigurationFingerprint {
            format: description.configuration.format,
            bytes: description.configuration.bytes.len() as u64,
            sha256: Sha256::digest(&description.configuration.bytes).into(),
        };
        let challenge = if description.target.serial.is_empty() {
            format!(
                "WIPE NAA:{}",
                hex::encode(
                    description
                        .target
                        .device_id
                        .as_ref()
                        .expect("validated identity")
                        .as_bytes()
                )
            )
        } else {
            format!("WIPE {}", description.target.serial)
        };
        let mut job = Self {
            target: description.target,
            layout: description.layout,
            sources: description.sources,
            configuration,
            payloads: description.payloads,
            digest: [0; 32],
            challenge,
        };
        job.digest = digest(&job);
        Ok(job)
    }

    pub fn target(&self) -> &DeviceSnapshot {
        &self.target
    }
    pub fn layout(&self) -> &Layout {
        &self.layout
    }
    pub fn sources(&self) -> &[SourceMetadata] {
        &self.sources
    }
    pub fn payloads(&self) -> &[PayloadFingerprint] {
        &self.payloads
    }
    pub fn configuration(&self) -> &ConfigurationFingerprint {
        &self.configuration
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn challenge(&self) -> &str {
        &self.challenge
    }

    pub fn into_confirmation(self) -> PendingConfirmation {
        PendingConfirmation { job: Some(self) }
    }
}

/// One-shot state for this backend instance only. Reconstructing an identical
/// description creates a separate instance; there is no global replay defence.
#[derive(Debug)]
pub struct PendingConfirmation {
    job: Option<PreparedJob>,
}

impl PendingConfirmation {
    /// Confirm the exact description and supplied target snapshot. This does
    /// not read the target or prove that a human supplied the challenge. Failed
    /// comparisons leave the instance pending; success consumes it once.
    pub fn confirm(
        &mut self,
        expected_digest: &[u8; 32],
        target: &DeviceSnapshot,
        challenge: &str,
    ) -> Result<ConfirmationReceipt, JobError> {
        let job = self.job.as_ref().ok_or(JobError::AlreadyConfirmed)?;
        if expected_digest != &job.digest {
            return Err(JobError::DigestMismatch);
        }
        if target != &job.target {
            return Err(JobError::TargetMismatch);
        }
        if challenge != job.challenge {
            return Err(JobError::ChallengeMismatch);
        }
        Ok(ConfirmationReceipt {
            job: self.job.take().expect("pending job"),
        })
    }
}

/// Receipt for matching description confirmation only. It establishes no OS
/// authentication, source verification, safety checks or authority to write.
#[derive(Debug)]
pub struct ConfirmationReceipt {
    job: PreparedJob,
}

impl ConfirmationReceipt {
    pub fn description(&self) -> &PreparedJob {
        &self.job
    }
}

fn invalid(reason: &'static str) -> JobError {
    JobError::InvalidDescription(reason)
}

fn validate(description: &JobDescription) -> Result<(), JobError> {
    let target = &description.target;
    target
        .validate_identity()
        .map_err(|_| invalid("target identity"))?;
    target
        .geometry
        .validate()
        .map_err(|_| invalid("target geometry"))?;
    if target.device_number == u32::MAX {
        return Err(invalid("target device number"));
    }
    layout::validate(&description.layout).map_err(|_| invalid("noncanonical layout"))?;
    if description.layout.size_bytes != target.geometry.size_bytes
        || description.layout.logical_sector_size != u64::from(target.geometry.logical_sector_size)
    {
        return Err(invalid("layout does not match target geometry"));
    }
    if description.sources.len() > MAX_SOURCES
        || description.payloads.len() > MAX_PAYLOADS
        || description.configuration.bytes.len() > MAX_CONFIG_BYTES
        || (description.sources.is_empty() && description.payloads.is_empty())
    {
        return Err(invalid("empty job or resource limit"));
    }
    let mut ids = BTreeSet::new();
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut source_bytes = 0u64;
    for source in &description.sources {
        if !source.source_id.strip_prefix("src_").is_some_and(|id| {
            id.len() == 64
                && id
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        }) || !ids.insert(&source.source_id)
        {
            return Err(invalid("invalid or duplicate source ID"));
        }
        validate_path(&source.destination)?;
        // Conservative portable collision check; filesystem-specific checks
        // and create-new destination opens are still required at copy time.
        let path = source.destination.to_uppercase();
        if directories.contains(&path) || !files.insert(path.clone()) {
            return Err(invalid("duplicate or conflicting destination"));
        }
        for (offset, _) in path.match_indices('/') {
            let parent = &path[..offset];
            if files.contains(parent) {
                return Err(invalid("destination conflicts with a file"));
            }
            directories.insert(parent.to_owned());
        }
        source_bytes = add_size(source_bytes, source.bytes)?;
    }
    let mut roles = BTreeSet::new();
    let mut payload_bytes = 0u64;
    for payload in &description.payloads {
        if payload.role.is_empty()
            || payload.role.len() > 64
            || !payload.role.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
            || !roles.insert(&payload.role)
        {
            return Err(invalid("invalid or duplicate payload role"));
        }
        payload_bytes = add_size(payload_bytes, payload.bytes)?;
    }
    // The canonical layout always has data, boot A and boot B in this order.
    // These are necessary byte bounds, not a claim about free filesystem space.
    let capacity = |index: usize| {
        let partition = &description.layout.partitions[index];
        (partition.end_lba - partition.start_lba + 1) * description.layout.logical_sector_size
    };
    if source_bytes > capacity(0) || payload_bytes > capacity(1).min(capacity(2)) {
        return Err(invalid("described bytes exceed partition capacity"));
    }
    Ok(())
}

fn add_size(total: u64, bytes: u64) -> Result<u64, JobError> {
    if bytes == 0 || bytes > i64::MAX as u64 {
        return Err(invalid("invalid file size"));
    }
    total
        .checked_add(bytes)
        .ok_or(invalid("file size overflow"))
}

fn validate_path(path: &str) -> Result<(), JobError> {
    if path.is_empty()
        || path.len() > 4096
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path.split('/').count() > 33
    {
        return Err(invalid("invalid relative destination"));
    }
    for part in path.split('/') {
        let stem = part
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end()
            .to_uppercase();
        let port = ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
        if part.is_empty()
            || matches!(part, "." | "..")
            || part.encode_utf16().count() > 255
            || part.ends_with(['.', ' '])
            || part.contains(['<', '>', '"', '|', '?', '*'])
            || matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            || port
        {
            return Err(invalid("destination is not a portable file path"));
        }
    }
    Ok(())
}

// v1: domain bytes + u32 version; target (u32 number, string serial, optional
// NAA, u32 bus, u64 size, u32 logical/physical); layout (five u64 fields, bool,
// partitions); sources; configuration (u8 format, u64 length, SHA-256); payloads.
// Integers are little endian, strings are u64 UTF-8 byte length + exact bytes,
// vectors start with u64 count, optionals start with u8 presence. Digests/NAA
// are fixed 32/16 bytes; bool is u8 0/1. Vector order is preserved, never sorted.
fn digest(job: &PreparedJob) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"isohopper-preparation-job\0");
    hash.update(1u32.to_le_bytes());
    hash.update(job.target.device_number.to_le_bytes());
    string(&mut hash, &job.target.serial);
    hash.update([u8::from(job.target.device_id.is_some())]);
    if let Some(id) = &job.target.device_id {
        hash.update(id.as_bytes());
    }
    hash.update(job.target.bus_type.to_le_bytes());
    hash.update(job.target.geometry.size_bytes.to_le_bytes());
    hash.update(job.target.geometry.logical_sector_size.to_le_bytes());
    hash.update(job.target.geometry.physical_sector_size.to_le_bytes());
    for field in [
        job.layout.size_bytes,
        job.layout.logical_sector_size,
        job.layout.total_sectors,
        job.layout.first_usable_lba,
        job.layout.last_usable_lba,
    ] {
        hash.update(field.to_le_bytes());
    }
    hash.update([u8::from(job.layout.legacy)]);
    hash.update((job.layout.partitions.len() as u64).to_le_bytes());
    for partition in &job.layout.partitions {
        hash.update(partition.number.to_le_bytes());
        string(&mut hash, &partition.name);
        string(&mut hash, &partition.type_guid);
        hash.update(partition.start_lba.to_le_bytes());
        hash.update(partition.end_lba.to_le_bytes());
    }
    hash.update((job.sources.len() as u64).to_le_bytes());
    for source in &job.sources {
        string(&mut hash, &source.source_id);
        string(&mut hash, &source.destination);
        hash.update(source.bytes.to_le_bytes());
        hash.update(source.sha256);
    }
    hash.update([match job.configuration.format {
        ConfigurationFormat::Yaml => 1,
        ConfigurationFormat::Toml => 2,
    }]);
    hash.update(job.configuration.bytes.to_le_bytes());
    hash.update(job.configuration.sha256);
    hash.update((job.payloads.len() as u64).to_le_bytes());
    for payload in &job.payloads {
        string(&mut hash, &payload.role);
        hash.update(payload.bytes.to_le_bytes());
        hash.update(payload.sha256);
    }
    hash.finalize().into()
}

fn string(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value.as_bytes());
}
