// SPDX-License-Identifier: GPL-3.0-or-later
//! Volume-lock ownership, not a complete physical-disk safety preflight.
//! Target authorization, source binding, encryption/container checks, device
//! arrival coordination and elevation remain the caller's responsibility.

/// Read-only diagnostic coverage, not authorization to write or an encryption
/// verdict. All ranges refer to the retained device in `device`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetCoverage {
    pub device: crate::writer::DeviceSnapshot,
    /// Windows partition style: 0 = MBR, 1 = GPT, 2 = RAW.
    pub partition_style: u32,
    /// GPT disk GUID, or MBR signature in the first four bytes.
    pub layout_identity: [u8; 16],
    pub partitions: Vec<PartitionCoverage>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionCoverage {
    pub partition_number: u32,
    pub start_offset: u64,
    pub length_bytes: u64,
    /// GPT type in Windows GUID byte order, or MBR type in the first byte.
    pub partition_type: [u8; 16],
    pub partition_identity: [u8; 16],
    /// None is allowed only for the exact GPT BIOS Boot and MSR types.
    pub volume_guid: Option<String>,
    pub volume_required: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum LockError {
    #[error("missing volume-lock evidence: {0}")]
    MissingEvidence(&'static str),
    #[error("volume-lock evidence unavailable during {stage}: {source}")]
    Io {
        stage: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("retained device identity or geometry changed")]
    DeviceChanged,
    #[error("volume membership or disk layout changed while locking")]
    VolumeChanged,
    #[error("dynamic, shared, overlapping or unsupported disk layout")]
    UnsupportedLayout,
    #[error(transparent)]
    Identity(#[from] crate::windows_identity::IdentityError),
}

/// A failed observation-to-lock handoff grants no device capability.
#[derive(Debug, thiserror::Error)]
pub enum ObservedLockError {
    #[error(transparent)]
    Target(#[from] crate::windows_target::TargetError),
    #[error(transparent)]
    Lock(#[from] LockError),
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{LockedWindowsDevice, TargetVolumeProbe, lock, lock_observed};

#[cfg(any(windows, test))]
mod state;
