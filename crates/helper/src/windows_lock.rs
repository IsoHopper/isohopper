// SPDX-License-Identifier: GPL-3.0-or-later
//! Volume-lock ownership, not a complete physical-disk safety preflight.
//! Target authorization, source binding, encryption/container checks, device
//! arrival coordination and elevation remain the caller's responsibility.

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
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{LockedWindowsDevice, lock};

#[cfg(any(windows, test))]
mod state;
