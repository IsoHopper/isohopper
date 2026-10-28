// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded messages for one preparation job on an authenticated local channel.
//! These descriptions neither authenticate peers nor authorize device writes.
use crate::{
    framing::MAX_FRAME_BYTES,
    writer::{DeviceSnapshot, Geometry, StableDeviceId},
};
use isohopper_media::copy::{CopyEntry, validate_manifest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const VERSION: u32 = 1;
pub const MAX_SOURCES: u16 = 128;
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid preparation message: {0}")]
pub struct ProtocolError(pub &'static str);

/// Public routing fields for the fixed preparation entry, never credentials.
pub struct PrepareArgs(crate::broker_probe::ProbeArgs);
impl PrepareArgs {
    pub fn new(nonce: &str, studio_pid: u32, studio_created: u64) -> Result<Self, ProtocolError> {
        crate::broker_probe::ProbeArgs::new(nonce, studio_pid, studio_created)
            .map(Self)
            .map_err(|_| ProtocolError("launch arguments"))
    }
    pub fn parse(args: &[String]) -> Result<Self, ProtocolError> {
        if args.len() != 7
            || args.iter().any(|arg| arg.len() > 128)
            || args.first().map(String::as_str) != Some("--prepare-broker-v1")
        {
            return Err(ProtocolError("launch mode"));
        }
        let mut probe = args.to_vec();
        probe[0] = "--probe-broker-v1".into();
        crate::broker_probe::ProbeArgs::parse(&probe)
            .map(Self)
            .map_err(|_| ProtocolError("launch arguments"))
    }
    pub fn nonce(&self) -> &str {
        self.0.nonce()
    }
    pub fn studio_pid(&self) -> u32 {
        self.0.studio_pid()
    }
    pub fn studio_created(&self) -> u64 {
        self.0.studio_created()
    }
    pub fn launch_arguments(&self) -> String {
        format!(
            "--prepare-broker-v1 --pipe-nonce {} --studio-pid {} --studio-created {}",
            self.nonce(),
            self.studio_pid(),
            self.studio_created()
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerFrame {
    pub version: u32,
    pub job_id: String,
    pub sequence: u64,
    pub body: ServerMessage,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientFrame {
    pub version: u32,
    pub job_id: String,
    pub reply_to: u64,
    pub body: ClientMessage,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Receiving,
    CheckingTarget,
    CheckingSources,
    BuildingSeed,
    WritingSeed,
    VerifyingSeed,
    FormattingData,
    CopyingSources,
    VerifyingSources,
    ExportingRaw,
    Sealed,
    AwaitingConfirmation,
    CheckingReadiness,
    LockingTarget,
    WritingTarget,
    VerifyingTarget,
    FlushingTarget,
    Complete,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Succeeded,
    Cancelled,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServerMessage {
    Hello,
    NeedArchive,
    NeedSource {
        index: u16,
    },
    InputsReady,
    Progress {
        phase: Phase,
        completed_bytes: u64,
        total_bytes: u64,
        file_index: Option<u16>,
    },
    Prepared {
        target: TargetSummary,
        image_bytes: u64,
        image_sha256: String,
        description_digest: String,
        challenge: String,
        source_count: u16,
        original_handles_closed: bool,
    },
    AwaitConfirmation,
    Terminal {
        outcome: Outcome,
        phase: Phase,
        message: String,
        bytes_written: u64,
        bytes_verified: u64,
        target_may_be_incomplete: bool,
        sha256: Option<String>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClientMessage {
    Begin {
        target_selector: String,
        source_count: u16,
    },
    Archive {
        remote_handle: u64,
        bytes: u64,
        sha256: String,
    },
    Source {
        index: u16,
        source_id: String,
        relative_path: String,
        bytes: u64,
        sha256: String,
        remote_handle: u64,
    },
    SourcesComplete,
    Continue,
    Cancel,
    SourcesReleased,
    Confirm {
        description_digest: String,
        challenge: String,
    },
    FinishAck,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetSummary {
    pub device_number: u32,
    pub serial: String,
    pub device_id: Option<String>,
    pub bus_type: u32,
    pub size_bytes: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
}
impl From<&DeviceSnapshot> for TargetSummary {
    fn from(v: &DeviceSnapshot) -> Self {
        Self {
            device_number: v.device_number,
            serial: v.serial.clone(),
            device_id: v.device_id.as_ref().map(|v| hex::encode(v.as_bytes())),
            bus_type: v.bus_type,
            size_bytes: v.geometry.size_bytes,
            logical_sector_size: v.geometry.logical_sector_size,
            physical_sector_size: v.geometry.physical_sector_size,
        }
    }
}
impl TargetSummary {
    /// A reported description only; conversion supplies no fresh device evidence.
    pub fn snapshot(&self) -> Result<DeviceSnapshot, ProtocolError> {
        let device_id = self
            .device_id
            .as_ref()
            .map(|v| {
                if !is_hex(v, 32) {
                    return Err(ProtocolError("device identifier"));
                }
                let mut bytes = [0; 16];
                hex::decode_to_slice(v, &mut bytes)
                    .map_err(|_| ProtocolError("device identifier"))?;
                StableDeviceId::from_naa128(bytes).map_err(|_| ProtocolError("device identifier"))
            })
            .transpose()?;
        let result = DeviceSnapshot {
            device_number: self.device_number,
            serial: self.serial.clone(),
            device_id,
            bus_type: self.bus_type,
            geometry: Geometry {
                size_bytes: self.size_bytes,
                logical_sector_size: self.logical_sector_size,
                physical_sector_size: self.physical_sector_size,
            },
        };
        result
            .validate_identity()
            .map_err(|_| ProtocolError("target identity"))?;
        result
            .geometry
            .validate()
            .map_err(|_| ProtocolError("target geometry"))?;
        if result.device_number == u32::MAX {
            return Err(ProtocolError("target number"));
        }
        Ok(result)
    }
}
fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}
fn text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}
fn handle(v: u64) -> bool {
    v > 0 && v <= i64::MAX as u64
}
pub fn decode_sha256(s: &str) -> Result<[u8; 32], ProtocolError> {
    if !is_hex(s, 64) {
        return Err(ProtocolError("SHA-256"));
    }
    let mut value = [0; 32];
    hex::decode_to_slice(s, &mut value).map_err(|_| ProtocolError("SHA-256"))?;
    Ok(value)
}
fn header(version: u32, job: &str) -> Result<(), ProtocolError> {
    if version != VERSION || !is_hex(job, 64) {
        Err(ProtocolError("version or job identifier"))
    } else {
        Ok(())
    }
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, ProtocolError> {
    let bytes = serde_json::to_vec(v).map_err(|_| ProtocolError("JSON"))?;
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError("frame limit"));
    }
    Ok(bytes)
}
fn decode<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(ProtocolError("frame limit"));
    }
    serde_json::from_slice(bytes).map_err(|_| ProtocolError("JSON"))
}
impl ClientFrame {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        encode(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let v: Self = decode(bytes)?;
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<(), ProtocolError> {
        header(self.version, &self.job_id)?;
        self.body.validate()
    }
}
impl ClientMessage {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::Begin {
                target_selector,
                source_count,
            } if !text(target_selector, 32768) || *source_count > MAX_SOURCES => {
                return Err(ProtocolError("target selector or source count"));
            }
            Self::Archive {
                remote_handle,
                bytes,
                sha256,
            } => {
                if !handle(*remote_handle)
                    || *bytes != isohopper_core::engine::archive::ARCHIVE_BYTES as u64
                {
                    return Err(ProtocolError("archive handle or length"));
                }
                decode_sha256(sha256)?;
            }
            Self::Source {
                index,
                source_id,
                relative_path,
                bytes,
                sha256,
                remote_handle,
            } => {
                if *index >= MAX_SOURCES
                    || !text(source_id, 128)
                    || relative_path.len() > 4096
                    || !handle(*remote_handle)
                {
                    return Err(ProtocolError("source fields"));
                }
                let entry = CopyEntry {
                    relative_path: relative_path.clone(),
                    bytes: *bytes,
                    sha256: decode_sha256(sha256)?,
                };
                validate_manifest(&[entry], i64::MAX as u64, 512)
                    .map_err(|_| ProtocolError("source path or length"))?;
            }
            Self::Confirm {
                description_digest,
                challenge,
            } => {
                decode_sha256(description_digest)?;
                if !text(challenge, 4128) {
                    return Err(ProtocolError("challenge"));
                }
            }
            _ => (),
        }
        Ok(())
    }
}
impl ServerFrame {
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        self.validate()?;
        encode(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let v: Self = decode(bytes)?;
        v.validate()?;
        Ok(v)
    }
    pub fn validate(&self) -> Result<(), ProtocolError> {
        header(self.version, &self.job_id)?;
        self.body.validate()
    }
    /// Checks one response. Caller owns the monotonic sequence and job state.
    pub fn validate_reply(&self, reply: &ClientFrame) -> Result<(), ProtocolError> {
        self.validate()?;
        reply.validate()?;
        if self.job_id != reply.job_id || self.sequence != reply.reply_to {
            return Err(ProtocolError("job or sequence mismatch"));
        }
        let okay = match (&self.body, &reply.body) {
            (ServerMessage::Terminal { .. }, ClientMessage::FinishAck) => true,
            (ServerMessage::Terminal { .. }, _) => false,
            (_, ClientMessage::Cancel) => true,
            (ServerMessage::Hello, ClientMessage::Begin { .. })
            | (ServerMessage::NeedArchive, ClientMessage::Archive { .. })
            | (ServerMessage::InputsReady, ClientMessage::SourcesComplete)
            | (ServerMessage::Progress { .. }, ClientMessage::Continue)
            | (ServerMessage::Prepared { .. }, ClientMessage::SourcesReleased)
            | (
                ServerMessage::AwaitConfirmation,
                ClientMessage::Continue | ClientMessage::Confirm { .. },
            ) => true,
            (ServerMessage::NeedSource { index: a }, ClientMessage::Source { index: b, .. }) => {
                a == b
            }
            _ => false,
        };
        if okay {
            Ok(())
        } else {
            Err(ProtocolError("response is not valid in this phase"))
        }
    }
}
impl ServerMessage {
    fn validate(&self) -> Result<(), ProtocolError> {
        match self {
            Self::NeedSource { index } if *index >= MAX_SOURCES => {
                return Err(ProtocolError("source index"));
            }
            Self::Progress {
                completed_bytes,
                total_bytes,
                file_index,
                ..
            } if completed_bytes > total_bytes || file_index.is_some_and(|i| i >= MAX_SOURCES) => {
                return Err(ProtocolError("progress counts"));
            }
            Self::Prepared {
                target,
                image_bytes,
                image_sha256,
                description_digest,
                challenge,
                source_count,
                original_handles_closed,
            } => {
                target.snapshot()?;
                decode_sha256(image_sha256)?;
                decode_sha256(description_digest)?;
                if *image_bytes != target.size_bytes
                    || !text(challenge, 4128)
                    || *source_count > MAX_SOURCES
                    || !*original_handles_closed
                {
                    return Err(ProtocolError("prepared description"));
                }
            }
            Self::Terminal {
                outcome,
                phase,
                message,
                bytes_written,
                bytes_verified,
                target_may_be_incomplete,
                sha256,
            } => {
                if !text(message, 2048) || bytes_verified > bytes_written {
                    return Err(ProtocolError("terminal report"));
                }
                if let Some(v) = sha256 {
                    decode_sha256(v)?;
                }
                if *outcome == Outcome::Succeeded
                    && (*phase != Phase::Complete
                        || *bytes_written == 0
                        || bytes_written != bytes_verified
                        || *target_may_be_incomplete
                        || sha256.is_none())
                {
                    return Err(ProtocolError("success report"));
                }
            }
            _ => (),
        }
        Ok(())
    }
}
/// Ordered input validation before the worker can receive any source files.
pub struct SourceList {
    expected: u16,
    ids: BTreeSet<String>,
    entries: Vec<CopyEntry>,
}
impl SourceList {
    pub fn new(expected: u16) -> Result<Self, ProtocolError> {
        if expected > MAX_SOURCES {
            return Err(ProtocolError("source count"));
        }
        Ok(Self {
            expected,
            ids: BTreeSet::new(),
            entries: Vec::new(),
        })
    }
    pub fn push(&mut self, message: &ClientMessage) -> Result<(), ProtocolError> {
        message.validate()?;
        let ClientMessage::Source {
            index,
            source_id,
            relative_path,
            bytes,
            sha256,
            ..
        } = message
        else {
            return Err(ProtocolError("expected source"));
        };
        if usize::from(*index) != self.entries.len()
            || *index >= self.expected
            || self.ids.contains(source_id)
        {
            return Err(ProtocolError("source order or duplicate identifier"));
        }
        let mut next = self.entries.clone();
        next.push(CopyEntry {
            relative_path: relative_path.clone(),
            bytes: *bytes,
            sha256: decode_sha256(sha256)?,
        });
        validate_manifest(&next, i64::MAX as u64, 512)
            .map_err(|_| ProtocolError("source destinations or length"))?;
        self.ids.insert(source_id.clone());
        self.entries = next;
        Ok(())
    }
    pub fn finish(&self) -> Result<(), ProtocolError> {
        if self.entries.len() != usize::from(self.expected) {
            Err(ProtocolError("incomplete source collection"))
        } else {
            Ok(())
        }
    }
}
