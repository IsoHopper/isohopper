// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained mappings for the running Windows directory and executable files.
//! These bindings only exclude their observed storage from a candidate target.
//! They do not authenticate an application, identify boot partitions, resolve
//! Storage Spaces/RAID, or establish complete target safety. Active pagefile
//! mapping is unsupported: a pathname or its nearest existing parent alone is
//! not evidence that the active pagefile belongs to that volume.
use crate::windows_sources::SourceError;
#[cfg(any(windows, test))]
use crate::windows_sources::SourceExtent;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageRole {
    Helper,
    Caller,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtectedError {
    #[error("protected storage evidence is unavailable: {0}")]
    MissingEvidence(&'static str),
    #[error("protected storage mapping failed: {0}")]
    Source(#[from] SourceError),
    #[error("protected storage query failed during {stage}: {source}")]
    Io {
        stage: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("protected directory or candidate evidence changed")]
    Changed,
}

#[cfg(any(windows, test))]
mod state;

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{ProtectedFileBinding, SystemDirectoryBinding, bind_file, bind_system_directory};
