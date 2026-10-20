// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded image inspection, candidate boot recipes and signed manifest validation.
pub mod iso;
mod library;
pub mod manifest;
pub mod recipes;
pub use library::{ImageEntry, ScanLimits, ScanReport, open_image, scan, scan_with_limits};

#[derive(Debug, thiserror::Error)]
pub enum MediaError {
    #[error("{0}")]
    Invalid(String),
    #[error("manifest signature verification failed")]
    Signature,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

fn invalid(message: impl Into<String>) -> MediaError {
    MediaError::Invalid(message.into())
}

fn relative_path(path: &str) -> Result<(), MediaError> {
    if path.is_empty()
        || path.len() > 4096
        || path.contains(['\\', ':'])
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(invalid(
            "image path must stay relative to the library without traversal or control characters",
        ));
    }
    Ok(())
}
