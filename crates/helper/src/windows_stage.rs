// SPDX-License-Identifier: GPL-3.0-or-later
//! Private, newly created Windows staging disks. No caller path or target disk.
//! Builds a pinned engine image through a private VHD, verifies persisted data,
//! then exports and retains exact read-only raw bytes. No physical-target open,
//! authentication, target authorization, or storage-independence verdict.

#[derive(Debug, thiserror::Error)]
pub enum StageError {
    #[error("unsupported staging geometry")]
    Geometry,
    #[error("SeManageVolumePrivilege must already be enabled before peer authentication")]
    Privilege,
    #[error("invalid staging evidence: {0}")]
    Invalid(&'static str),
    #[error("owned-volume provider refused format: return_code={0}")]
    FormatProvider(u32),
    #[error(
        "owned-volume formatter failed: exit={exit_code:?}; overdue={overdue}; stdout_bytes={stdout_bytes}; stderr_bytes={stderr_bytes}; stage={script_stage:?}; hresult={hresult:?}"
    )]
    FormatProcess {
        exit_code: Option<i32>,
        overdue: bool,
        stdout_bytes: usize,
        stderr_bytes: usize,
        script_stage: Option<u8>,
        hresult: Option<i32>,
    },
    #[error("protected installation changed: {0}")]
    Installation(String),
    #[error("staging operation {operation} failed: {source}")]
    Io {
        operation: &'static str,
        source: std::io::Error,
    },
}

#[cfg(windows)]
mod native;
#[cfg(any(windows, test))]
mod policy;
#[cfg(windows)]
pub use native::{OwnedStageDisk, SealedStage, build};

#[cfg(any(windows, test))]
mod build_policy;

/// One backend-owned source, including optional generated config.
/// Construction does not authenticate its origin; the caller supplies that boundary.
/// A path in this manifest is a destination only, never opened as a host source.
pub struct StageInput {
    pub file: std::fs::File,
    pub entry: isohopper_media::copy::CopyEntry,
}
#[derive(Clone, Debug)]
pub struct StageProgress {
    pub phase: &'static str,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub file_index: Option<usize>,
}
#[cfg(windows)]
mod format;
