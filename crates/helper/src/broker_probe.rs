// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
//! Read-only connection diagnostics. This protocol cannot authorize disk operations.
use crate::windows_peer::{ElevationType, IntegrityLevel, PeerEvidence};
use serde::{Deserialize, Serialize};

const MAX_BYTES: usize = 4096;
const PURPOSE: &str = "read_only_probe";

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("invalid read-only helper probe arguments")]
    Arguments,
    #[error("invalid read-only helper probe message")]
    Message,
    #[error("helper probe already completed")]
    Completed,
    #[error(
        "helper probe requires Studio running normally under a split-token administrator account"
    )]
    StudioRole,
    #[error("helper probe requires a high-integrity elevated helper")]
    HelperRole,
    #[error("helper must belong to the same user, logon and desktop session")]
    Principal,
}

fn nonce(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Public launch routing fields. These are not authentication credentials.
pub struct ProbeArgs {
    nonce: String,
    studio_pid: u32,
    studio_created: u64,
}
impl ProbeArgs {
    pub fn new(
        nonce_value: &str,
        studio_pid: u32,
        studio_created: u64,
    ) -> Result<Self, ProbeError> {
        if !nonce(nonce_value) || studio_pid == 0 || studio_created == 0 {
            return Err(ProbeError::Arguments);
        }
        Ok(Self {
            nonce: nonce_value.into(),
            studio_pid,
            studio_created,
        })
    }
    pub fn parse(args: &[String]) -> Result<Self, ProbeError> {
        if args.len() != 7
            || args.iter().any(|s| s.len() > 128)
            || args[0] != "--probe-broker-v1"
            || args[1] != "--pipe-nonce"
            || args[3] != "--studio-pid"
            || args[5] != "--studio-created"
        {
            return Err(ProbeError::Arguments);
        }
        let pid: u32 = args[4].parse().map_err(|_| ProbeError::Arguments)?;
        let created: u64 = args[6].parse().map_err(|_| ProbeError::Arguments)?;
        if pid.to_string() != args[4] || created.to_string() != args[6] {
            return Err(ProbeError::Arguments);
        }
        Self::new(&args[2], pid, created)
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn studio_pid(&self) -> u32 {
        self.studio_pid
    }
    pub fn studio_created(&self) -> u64 {
        self.studio_created
    }
    pub fn launch_arguments(&self) -> String {
        format!(
            "--probe-broker-v1 --pipe-nonce {} --studio-pid {} --studio-created {}",
            self.nonce, self.studio_pid, self.studio_created
        )
    }
}

pub fn check_studio(studio: &PeerEvidence) -> Result<(), ProbeError> {
    let token = &studio.token;
    if studio.process_id == 0
        || studio.creation_time == 0
        || token.is_app_container
        || token.elevated
        || token.integrity != IntegrityLevel::Medium
        || token.elevation_type != ElevationType::Limited
    {
        return Err(ProbeError::StudioRole);
    }
    Ok(())
}
pub fn check_pair(studio: &PeerEvidence, helper: &PeerEvidence) -> Result<(), ProbeError> {
    check_studio(studio)?;
    let token = &helper.token;
    if helper.process_id == 0
        || helper.process_id == studio.process_id
        || helper.creation_time == 0
        || token.is_app_container
        || !token.elevated
        || token.integrity != IntegrityLevel::High
        || token.elevation_type != ElevationType::Full
    {
        return Err(ProbeError::HelperRole);
    }
    if token.user != studio.token.user
        || token.logon != studio.token.logon
        || token.session_id != studio.token.session_id
    {
        return Err(ProbeError::Principal);
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    protocol: u32,
    purpose: String,
    nonce: String,
}
impl ProbeRequest {
    pub fn decode(bytes: &[u8]) -> Result<Self, ProbeError> {
        let value: Self = decode(bytes)?;
        if value.protocol != 1 || value.purpose != PURPOSE || !nonce(&value.nonce) {
            return Err(ProbeError::Message);
        }
        Ok(value)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeReply {
    protocol: u32,
    purpose: String,
    nonce: String,
    helper_version: String,
    physical_preparation: bool,
}
impl ProbeReply {
    pub fn for_request(request: &ProbeRequest) -> Self {
        Self {
            protocol: 1,
            purpose: PURPOSE.into(),
            nonce: request.nonce.clone(),
            helper_version: env!("CARGO_PKG_VERSION").into(),
            physical_preparation: false,
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, ProbeError> {
        encode(self)
    }
}

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub protocol: u32,
    pub helper_version: String,
    pub physical_preparation: bool,
}

/// One diagnostic exchange; it creates no Session, pending job or disk authority.
pub struct ProbeSession {
    request: ProbeRequest,
    completed: bool,
}
impl ProbeSession {
    pub fn new(nonce_value: &str) -> Result<Self, ProbeError> {
        if !nonce(nonce_value) {
            return Err(ProbeError::Message);
        }
        Ok(Self {
            request: ProbeRequest {
                protocol: 1,
                purpose: PURPOSE.into(),
                nonce: nonce_value.into(),
            },
            completed: false,
        })
    }
    pub fn request(&self) -> Result<Vec<u8>, ProbeError> {
        if self.completed {
            return Err(ProbeError::Completed);
        }
        encode(&self.request)
    }
    pub fn complete(&mut self, bytes: &[u8]) -> Result<ProbeReport, ProbeError> {
        if self.completed {
            return Err(ProbeError::Completed);
        }
        let reply: ProbeReply = decode(bytes)?;
        if reply.protocol != 1
            || reply.purpose != PURPOSE
            || reply.nonce != self.request.nonce
            || reply.physical_preparation
            || reply.helper_version != env!("CARGO_PKG_VERSION")
        {
            return Err(ProbeError::Message);
        }
        self.completed = true;
        Ok(ProbeReport {
            protocol: 1,
            helper_version: reply.helper_version,
            physical_preparation: false,
        })
    }
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ProbeError> {
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(ProbeError::Message);
    }
    serde_json::from_slice(bytes).map_err(|_| ProbeError::Message)
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, ProbeError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ProbeError::Message)?;
    if bytes.len() > MAX_BYTES {
        return Err(ProbeError::Message);
    }
    Ok(bytes)
}
