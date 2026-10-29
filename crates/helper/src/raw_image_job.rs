// SPDX-License-Identifier: GPL-3.0-or-later
//! Immutable whole-device image descriptions and one-shot confirmation.
//!
//! Fingerprints are supplied by the caller. Structural validation here does
//! not read files or devices, verify bootability or publisher authenticity,
//! check image layout/configuration, establish OS authentication, or prove
//! source/target freshness or device safety. A receipt grants no write authority.
//! A coordinator must establish those independently and retain the exact image
//! and target represented here.
use crate::writer::DeviceSnapshot;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

const MAX_BOOT_ARTIFACTS: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageFingerprint {
    /// Exact complete image length, including padding; must equal target size.
    pub bytes: u64,
    pub sha256: [u8; 32],
}

/// Provenance of one input used to build the image, not an embedded byte range.
/// An input may be transformed or compressed, so these sizes are not summed as
/// image capacity. Hashes and versions are recorded without authenticating them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootArtifactFingerprint {
    /// Unique lowercase ASCII role, never an executable command or path.
    pub role: String,
    /// Exact producer version if known. Unknown versions remain absent.
    pub version: Option<String>,
    pub bytes: u64,
    pub sha256: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct RawImageDescription {
    pub target: DeviceSnapshot,
    pub image: ImageFingerprint,
    /// Ordered provenance: order is significant in the description digest.
    pub boot_artifacts: Vec<BootArtifactFingerprint>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RawImageError {
    #[error("invalid raw-image description: {0}")]
    InvalidDescription(&'static str),
    #[error("raw-image digest changed")]
    DigestMismatch,
    #[error("target changed")]
    TargetMismatch,
    #[error("target confirmation does not match")]
    ChallengeMismatch,
    #[error("this raw-image description was already confirmed")]
    AlreadyConfirmed,
}

/// Structurally validated immutable description. Its private fields cannot be
/// modified, cloned or deserialized to change an existing pending confirmation.
#[derive(Debug)]
pub struct PreparedRawImage {
    description: RawImageDescription,
    digest: [u8; 32],
    challenge: String,
}

impl PreparedRawImage {
    pub fn new(description: RawImageDescription) -> Result<Self, RawImageError> {
        validate(&description)?;
        let digest = digest(&description);
        Ok(Self {
            description,
            digest,
            // The phrase is an explicit acknowledgement; the immutable
            // description/digest and one-shot receipt bind the actual target.
            challenge: "ENABLE_WRITE".into(),
        })
    }
    pub fn target(&self) -> &DeviceSnapshot {
        &self.description.target
    }
    pub fn image(&self) -> &ImageFingerprint {
        &self.description.image
    }
    pub fn boot_artifacts(&self) -> &[BootArtifactFingerprint] {
        &self.description.boot_artifacts
    }
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn challenge(&self) -> &str {
        &self.challenge
    }
    pub fn into_confirmation(self) -> PendingConfirmation {
        PendingConfirmation { image: Some(self) }
    }
}

/// One-shot state for this backend instance only. Reconstructing an identical
/// description creates a separate instance; there is no global replay defence.
#[derive(Debug)]
pub struct PendingConfirmation {
    image: Option<PreparedRawImage>,
}

impl PendingConfirmation {
    /// Match the exact digest, supplied target snapshot and acknowledgement.
    /// This does not inspect the target or prove a human supplied the challenge.
    /// Failed comparisons leave the instance pending; success consumes it once.
    pub fn confirm(
        &mut self,
        expected_digest: &[u8; 32],
        target: &DeviceSnapshot,
        challenge: &str,
    ) -> Result<ConfirmationReceipt, RawImageError> {
        let image = self.image.as_ref().ok_or(RawImageError::AlreadyConfirmed)?;
        if expected_digest != &image.digest {
            return Err(RawImageError::DigestMismatch);
        }
        if target != &image.description.target {
            return Err(RawImageError::TargetMismatch);
        }
        if challenge != image.challenge {
            return Err(RawImageError::ChallengeMismatch);
        }
        Ok(ConfirmationReceipt {
            image: self.image.take().expect("pending image"),
        })
    }
}

/// Receipt of description confirmation only, not an authentication result,
/// source verification, device safety check or authority to write.
#[derive(Debug)]
pub struct ConfirmationReceipt {
    image: PreparedRawImage,
}

impl ConfirmationReceipt {
    pub fn description(&self) -> &PreparedRawImage {
        &self.image
    }
}

fn invalid(reason: &'static str) -> RawImageError {
    RawImageError::InvalidDescription(reason)
}

fn validate(description: &RawImageDescription) -> Result<(), RawImageError> {
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
    if description.image.bytes != target.geometry.size_bytes {
        return Err(invalid("image length does not equal target capacity"));
    }
    if description.boot_artifacts.is_empty()
        || description.boot_artifacts.len() > MAX_BOOT_ARTIFACTS
    {
        return Err(invalid("empty provenance or artifact limit"));
    }
    let mut roles = BTreeSet::new();
    for artifact in &description.boot_artifacts {
        if artifact.role.is_empty()
            || artifact.role.len() > 64
            || !artifact.role.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
            || !roles.insert(&artifact.role)
        {
            return Err(invalid("invalid or duplicate artifact role"));
        }
        if artifact.version.as_ref().is_some_and(|version| {
            version.is_empty()
                || version.len() > 128
                || version.trim() != version
                || version.chars().any(char::is_control)
        }) {
            return Err(invalid("invalid artifact version"));
        }
        if artifact.bytes == 0 || artifact.bytes > i64::MAX as u64 {
            return Err(invalid("invalid artifact size"));
        }
    }
    Ok(())
}

// v1 encoding: domain + u32 version; target number, serial, optional NAA,
// bus, size, logical/physical sectors; image size/hash; ordered artifact count
// and each role, optional version, size/hash. Integers use fixed-width LE;
// counts and UTF-8 byte lengths use u64, options use u8 (0 absent, 1 present).
// Hashes and present NAAs use their fixed raw byte arrays. Future meaning or
// field changes require a new version; other operations need another domain.
fn digest(description: &RawImageDescription) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"isohopper-raw-image-job\0");
    hash.update(1u32.to_le_bytes());
    let target = &description.target;
    hash.update(target.device_number.to_le_bytes());
    string(&mut hash, &target.serial);
    hash.update([u8::from(target.device_id.is_some())]);
    if let Some(id) = &target.device_id {
        hash.update(id.as_bytes());
    }
    hash.update(target.bus_type.to_le_bytes());
    hash.update(target.geometry.size_bytes.to_le_bytes());
    hash.update(target.geometry.logical_sector_size.to_le_bytes());
    hash.update(target.geometry.physical_sector_size.to_le_bytes());
    hash.update(description.image.bytes.to_le_bytes());
    hash.update(description.image.sha256);
    hash.update((description.boot_artifacts.len() as u64).to_le_bytes());
    for artifact in &description.boot_artifacts {
        string(&mut hash, &artifact.role);
        hash.update([u8::from(artifact.version.is_some())]);
        if let Some(version) = &artifact.version {
            string(&mut hash, version);
        }
        hash.update(artifact.bytes.to_le_bytes());
        hash.update(artifact.sha256);
    }
    hash.finalize().into()
}

fn string(hash: &mut Sha256, value: &str) {
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value.as_bytes());
}
