// SPDX-License-Identifier: GPL-3.0-or-later
//! One-connection local Windows pipes with bounded frames and retained process
//! observations. This is not UAC, role authorization or trusted-code proof.
//! Kernel peer PIDs identify pipe endpoints, not every thread or process that
//! may later use a duplicated pipe handle. A supplied ProcessPeer is evidence
//! chosen by the caller, not an independently authenticated application.
//!
//! A deadline covers a whole operation. Cancellation always drains outstanding
//! I/O before releasing buffers; that drain can exceed the requested deadline.
use std::io;

#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    #[error("invalid local pipe endpoint")]
    Endpoint,
    #[error("invalid pipe security descriptor: {0}")]
    Security(&'static str),
    #[error("pipe endpoint belongs to a different process")]
    WrongPeer,
    #[error(transparent)]
    Peer(#[from] crate::windows_peer::PeerError),
    #[error("pipe operation timed out")]
    TimedOut,
    #[error("pipe operation cancelled")]
    Cancelled,
    #[error("pipe connection is closed after an earlier error")]
    Closed,
    #[error("pipe operation failed at {stage}: {source}")]
    Io {
        stage: &'static str,
        #[source]
        source: io::Error,
    },
}

/// Public routing nonce, never a secret or an authorization credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endpoint(String);
impl Endpoint {
    pub fn from_nonce(nonce: &str) -> Result<Self, PipeError> {
        if nonce.len() != 64
            || !nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(PipeError::Endpoint);
        }
        Ok(Self(nonce.to_owned()))
    }
    pub fn nonce(&self) -> &str {
        &self.0
    }
    pub fn local_name(&self) -> String {
        format!(r"\\.\pipe\IsoHopper.v1.{}", self.0)
    }
}

#[cfg(any(windows, test))]
mod security;

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{Connection, Server, connect};
