// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
//! Job-bound authorization protocol. OS elevation and peer verification are separate gates.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;

pub mod job;
pub mod windows_encryption_check;
pub mod windows_identity;
pub mod windows_lock;
pub mod windows_protected;
pub mod windows_sources;
pub mod writer;

type HmacSha256 = Hmac<Sha256>;
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    WritePlan,
    CopyFiles,
    Eject,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub sequence: u64,
    pub plan_hash: String,
    pub disk_id: String,
    pub operation: Operation,
}
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid job identity, digest or session key")]
    InvalidJob,
    #[error("request does not belong to this job")]
    WrongJob,
    #[error("replayed or out-of-order request")]
    Replay,
    #[error("request authentication failed")]
    Authentication,
    #[error("request cannot be encoded")]
    Encoding,
}
pub struct Session {
    key: [u8; 32],
    disk_id: String,
    plan_hash: String,
    next_sequence: u64,
}
impl Session {
    pub fn new(key: [u8; 32], disk_id: String, plan_hash: String) -> Result<Self, Error> {
        if key.iter().all(|b| *b == 0)
            || disk_id.trim().is_empty()
            || disk_id.len() > 4096
            || plan_hash.len() != 64
            || !plan_hash
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(Error::InvalidJob);
        }
        Ok(Self {
            key,
            disk_id,
            plan_hash,
            next_sequence: 0,
        })
    }
    fn mac(&self, request: &Request) -> Result<HmacSha256, Error> {
        let mut mac = HmacSha256::new_from_slice(&self.key).map_err(|_| Error::InvalidJob)?;
        mac.update(b"isohopper-helper-v1\0");
        mac.update(&serde_json::to_vec(request).map_err(|_| Error::Encoding)?);
        Ok(mac)
    }
    pub fn sign(&self, request: &Request) -> Result<[u8; 32], Error> {
        Ok(self.mac(request)?.finalize().into_bytes().into())
    }
    pub fn accept(&mut self, request: &Request, tag: &[u8]) -> Result<(), Error> {
        if request.disk_id != self.disk_id || request.plan_hash != self.plan_hash {
            return Err(Error::WrongJob);
        }
        if request.sequence != self.next_sequence {
            return Err(Error::Replay);
        }
        self.mac(request)?
            .verify_slice(tag)
            .map_err(|_| Error::Authentication)?;
        self.next_sequence = self.next_sequence.checked_add(1).ok_or(Error::Replay)?;
        Ok(())
    }
}
/// Protocol frame bounds are checked before JSON allocation.
pub fn decode_frame(bytes: &[u8]) -> Result<Request, Error> {
    if bytes.len() > 65_536 {
        return Err(Error::Encoding);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::Encoding)
}
