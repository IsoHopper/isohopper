// SPDX-License-Identifier: GPL-3.0-or-later
//! Private, newly created Windows staging disks. No caller path or target disk.
//! This is only the protected directory/VHD lifetime boundary: no formatting,
//! source copy, sealed-image guarantee, target authorization or physical write.

#[derive(Debug, thiserror::Error)]
pub enum StageError {
    #[error("unsupported staging geometry")]
    Geometry,
    #[error("SeManageVolumePrivilege must already be enabled before peer authentication")]
    Privilege,
    #[error("invalid staging evidence: {0}")]
    Invalid(&'static str),
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
pub use native::OwnedStageDisk;
