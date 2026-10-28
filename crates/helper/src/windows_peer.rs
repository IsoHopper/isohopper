// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only observations of a caller-retained Windows process and its primary
//! token. Optional protected-installation binding correlates its native image
//! name with a retained installed file, without proving mapped code identity.
//! Neither observation establishes pipe ownership, publisher trust, elevation
//! policy or permission to perform an operation.
//!
//! Token fields are queried from one token with a stable modification stamp,
//! then compared with the process's freshly reopened primary token. A retained
//! process handle prevents this module from reopening a recycled PID.
use std::{fmt, io};

#[derive(Debug, thiserror::Error)]
pub enum PeerError {
    #[error("invalid Windows peer evidence: {0}")]
    Invalid(&'static str),
    #[error("unsupported Windows peer evidence: {0}")]
    Unsupported(&'static str),
    #[error("peer process has exited")]
    Exited,
    #[error("peer process or primary token changed")]
    Changed,
    #[error("protected Windows installation check failed: {0}")]
    Installation(String),
    #[error("Windows peer query failed at {stage}: {source}")]
    Io {
        stage: &'static str,
        #[source]
        source: io::Error,
    },
}

/// Validated binary SID. It is not an authenticated principal by itself.
#[derive(Clone, PartialEq, Eq)]
pub struct Sid(Vec<u8>);

impl Sid {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PeerError> {
        if bytes.len() < 8 || bytes[0] != 1 || bytes[1] > 15 {
            return Err(PeerError::Invalid("SID header"));
        }
        if bytes.len() != 8 + usize::from(bytes[1]) * 4 {
            return Err(PeerError::Invalid("SID length"));
        }
        Ok(Self(bytes.to_vec()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sid(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElevationType {
    Default,
    Full,
    Limited,
}

/// Known mandatory integrity RID. This is an observation, not a role policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegrityLevel {
    Untrusted,
    Low,
    Medium,
    MediumPlus,
    High,
    System,
    ProtectedProcess,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenEvidence {
    pub user: Sid,
    pub logon: Sid,
    pub session_id: u32,
    pub integrity: IntegrityLevel,
    pub elevated: bool,
    pub elevation_type: ElevationType,
    pub is_app_container: bool,
    /// Opaque LUID bit patterns, meaningful only on this running Windows host.
    pub token_id: u64,
    pub authentication_id: u64,
    pub modified_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerEvidence {
    pub process_id: u32,
    /// Raw Windows FILETIME bit pattern, not a wall-clock freshness guarantee.
    pub creation_time: u64,
    pub token: TokenEvidence,
}

#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::ProcessPeer;

#[cfg(any(windows, test))]
mod decode {
    use super::*;

    pub(super) const MAX_TOKEN_BYTES: usize = 65_536;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) struct Stamp {
        pub token: u64,
        pub authentication: u64,
        pub modified: u64,
    }

    pub(super) fn word(bytes: &[u8], offset: usize) -> Result<u32, PeerError> {
        let value = bytes
            .get(
                offset
                    ..offset
                        .checked_add(4)
                        .ok_or(PeerError::Invalid("field offset"))?,
            )
            .ok_or(PeerError::Invalid("truncated token field"))?;
        Ok(u32::from_le_bytes(value.try_into().unwrap()))
    }

    fn wide(bytes: &[u8], offset: usize) -> Result<u64, PeerError> {
        let value = bytes
            .get(
                offset
                    ..offset
                        .checked_add(8)
                        .ok_or(PeerError::Invalid("field offset"))?,
            )
            .ok_or(PeerError::Invalid("truncated token field"))?;
        Ok(u64::from_le_bytes(value.try_into().unwrap()))
    }

    pub(super) fn scalar(bytes: &[u8]) -> Result<u32, PeerError> {
        if bytes.len() != 4 {
            return Err(PeerError::Invalid("token scalar size"));
        }
        word(bytes, 0)
    }

    pub(super) fn boolean(bytes: &[u8]) -> Result<bool, PeerError> {
        match scalar(bytes)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(PeerError::Invalid("token boolean")),
        }
    }

    pub(super) fn elevation(bytes: &[u8]) -> Result<ElevationType, PeerError> {
        match scalar(bytes)? {
            1 => Ok(ElevationType::Default),
            2 => Ok(ElevationType::Full),
            3 => Ok(ElevationType::Limited),
            _ => Err(PeerError::Unsupported("elevation type")),
        }
    }

    pub(super) fn statistics(bytes: &[u8]) -> Result<Stamp, PeerError> {
        if bytes.len() != 56 {
            return Err(PeerError::Invalid("token statistics size"));
        }
        if word(bytes, 24)? != 1 {
            return Err(PeerError::Unsupported("non-primary token"));
        }
        Ok(Stamp {
            token: wide(bytes, 0)?,
            authentication: wide(bytes, 8)?,
            modified: wide(bytes, 48)?,
        })
    }

    /// Absolute SID pointers are converted to checked slice offsets. No
    /// caller-supplied address is dereferenced. Both Windows pointer widths
    /// are supported, independent of the host running portable parser tests.
    pub(super) struct Buffer<'a> {
        pub bytes: &'a [u8],
        pub base: u64,
        pub pointer_bytes: usize,
    }

    impl Buffer<'_> {
        fn entry_size(&self) -> Result<usize, PeerError> {
            match self.pointer_bytes {
                4 => Ok(8),
                8 => Ok(16),
                _ => Err(PeerError::Unsupported("token pointer width")),
            }
        }

        fn entry(&self, offset: usize, header_end: usize) -> Result<(Sid, u32), PeerError> {
            let entry_size = self.entry_size()?;
            if self.bytes.len() > MAX_TOKEN_BYTES
                || self.bytes.len() < header_end
                || self.base.checked_add(self.bytes.len() as u64).is_none()
                || offset
                    .checked_add(entry_size)
                    .is_none_or(|end| end > header_end)
            {
                return Err(PeerError::Invalid("token SID structure size"));
            }
            let pointer = if self.pointer_bytes == 4 {
                u64::from(word(self.bytes, offset)?)
            } else {
                wide(self.bytes, offset)?
            };
            let sid_offset = pointer
                .checked_sub(self.base)
                .and_then(|value| usize::try_from(value).ok())
                .filter(|&value| pointer != 0 && value >= header_end)
                .ok_or(PeerError::Invalid("token SID pointer"))?;
            let sid_header = self
                .bytes
                .get(
                    sid_offset
                        ..sid_offset
                            .checked_add(8)
                            .ok_or(PeerError::Invalid("SID offset"))?,
                )
                .ok_or(PeerError::Invalid("truncated SID"))?;
            if sid_header[0] != 1 || sid_header[1] > 15 {
                return Err(PeerError::Invalid("SID header"));
            }
            let sid_end = sid_offset
                .checked_add(8 + usize::from(sid_header[1]) * 4)
                .ok_or(PeerError::Invalid("SID offset"))?;
            let sid = Sid::from_bytes(
                self.bytes
                    .get(sid_offset..sid_end)
                    .ok_or(PeerError::Invalid("truncated SID"))?,
            )?;
            Ok((sid, word(self.bytes, offset + self.pointer_bytes)?))
        }

        pub(super) fn user(&self) -> Result<Sid, PeerError> {
            Ok(self.entry(0, self.entry_size()?)?.0)
        }

        pub(super) fn logon(&self) -> Result<Sid, PeerError> {
            if word(self.bytes, 0)? != 1 {
                return Err(PeerError::Unsupported("missing or multiple logon SIDs"));
            }
            let offset = self.pointer_bytes;
            let (sid, attributes) = self.entry(offset, offset + self.entry_size()?)?;
            if attributes & 0xc000_0000 != 0xc000_0000
                || sid.0.len() != 20
                || sid.0[2..8] != [0, 0, 0, 0, 0, 5]
                || word(&sid.0, 8)? != 5
            {
                return Err(PeerError::Invalid("logon SID"));
            }
            Ok(sid)
        }

        pub(super) fn integrity(&self) -> Result<IntegrityLevel, PeerError> {
            let (sid, attributes) = self.entry(0, self.entry_size()?)?;
            if attributes & 0x20 == 0 || sid.0.len() != 12 || sid.0[2..8] != [0, 0, 0, 0, 0, 16] {
                return Err(PeerError::Invalid("integrity SID"));
            }
            match word(&sid.0, 8)? {
                0 => Ok(IntegrityLevel::Untrusted),
                0x1000 => Ok(IntegrityLevel::Low),
                0x2000 => Ok(IntegrityLevel::Medium),
                0x2100 => Ok(IntegrityLevel::MediumPlus),
                0x3000 => Ok(IntegrityLevel::High),
                0x4000 => Ok(IntegrityLevel::System),
                0x5000 => Ok(IntegrityLevel::ProtectedProcess),
                _ => Err(PeerError::Unsupported("integrity RID")),
            }
        }
    }

    pub(super) fn stable_token(
        before: Stamp,
        after: Stamp,
        reopened: Stamp,
    ) -> Result<(), PeerError> {
        if before != after || before != reopened {
            return Err(PeerError::Changed);
        }
        Ok(())
    }

    pub(super) fn unchanged(
        expected: &PeerEvidence,
        actual: &PeerEvidence,
    ) -> Result<(), PeerError> {
        if expected != actual {
            return Err(PeerError::Changed);
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn sid(authority: u8, sub: &[u32]) -> Vec<u8> {
            let mut bytes = vec![1, sub.len() as u8, 0, 0, 0, 0, 0, authority];
            for value in sub {
                bytes.extend(value.to_le_bytes());
            }
            bytes
        }

        fn record(width: usize, groups: bool, bytes: &[u8], attributes: u32) -> Vec<u8> {
            let offset = if groups { width } else { 0 };
            let header = offset + width * 2;
            let mut output = vec![0; header];
            if groups {
                output[..4].copy_from_slice(&1u32.to_le_bytes());
            }
            let pointer = (0x1000 + header as u64).to_le_bytes();
            output[offset..offset + width].copy_from_slice(&pointer[..width]);
            output[offset + width..offset + width + 4].copy_from_slice(&attributes.to_le_bytes());
            output.extend(bytes);
            output
        }

        fn buffer(bytes: &[u8], width: usize) -> Buffer<'_> {
            Buffer {
                bytes,
                base: 0x1000,
                pointer_bytes: width,
            }
        }

        #[test]
        fn peer_parsers_read_both_pointer_widths_and_exact_sid_kinds() {
            for width in [4, 8] {
                let user = sid(5, &[21, 100, 200, 300, 1000]);
                let bytes = record(width, false, &user, 0);
                assert_eq!(buffer(&bytes, width).user().unwrap().as_bytes(), user);
                let logon = sid(5, &[5, 10, 20]);
                let bytes = record(width, true, &logon, 0xc000_0007);
                assert_eq!(buffer(&bytes, width).logon().unwrap().as_bytes(), logon);
                for (rid, expected) in [
                    (0, IntegrityLevel::Untrusted),
                    (0x1000, IntegrityLevel::Low),
                    (0x2000, IntegrityLevel::Medium),
                    (0x2100, IntegrityLevel::MediumPlus),
                    (0x3000, IntegrityLevel::High),
                    (0x4000, IntegrityLevel::System),
                    (0x5000, IntegrityLevel::ProtectedProcess),
                ] {
                    let bytes = record(width, false, &sid(16, &[rid]), 0x60);
                    assert_eq!(buffer(&bytes, width).integrity().unwrap(), expected);
                }
            }
        }

        #[test]
        fn peer_sid_pointers_never_escape_or_alias_headers() {
            for width in [4, 8] {
                let valid = record(width, false, &sid(5, &[21]), 0);
                for length in 0..valid.len() {
                    assert!(buffer(&valid[..length], width).user().is_err());
                }
                for pointer in [
                    0,
                    0xfff,
                    0x1000,
                    0x1001,
                    0x1000 + valid.len() as u64 - 7,
                    0x1000 + valid.len() as u64,
                    u64::MAX,
                ] {
                    let mut bytes = valid.clone();
                    bytes[..width].copy_from_slice(&pointer.to_le_bytes()[..width]);
                    assert!(buffer(&bytes, width).user().is_err(), "width {width}");
                }
                let mut oversized = valid.clone();
                oversized.resize(MAX_TOKEN_BYTES + 1, 0);
                assert!(buffer(&oversized, width).user().is_err());
            }
            let bytes = record(8, false, &sid(5, &[21]), 0);
            assert!(buffer(&bytes, 3).user().is_err());
        }

        #[test]
        fn peer_buffer_address_range_overflow_is_rejected() {
            let mut bytes = record(8, false, &sid(5, &[21]), 0);
            let base = u64::MAX - 24;
            bytes[..8].copy_from_slice(&(base + 16).to_le_bytes());
            assert!(
                Buffer {
                    bytes: &bytes,
                    base,
                    pointer_bytes: 8
                }
                .user()
                .is_err()
            );
        }

        #[test]
        fn peer_logon_and_integrity_require_the_expected_structure() {
            for count in [0u32, 2, u32::MAX] {
                let mut bytes = record(8, true, &sid(5, &[5, 10, 20]), 0xc000_0007);
                bytes[..4].copy_from_slice(&count.to_le_bytes());
                assert!(buffer(&bytes, 8).logon().is_err());
            }
            for (authority, sub, flags) in [
                (6, vec![5, 10, 20], 0xc000_0007),
                (5, vec![21, 10, 20], 0xc000_0007),
                (5, vec![5, 10], 0xc000_0007),
                (5, vec![5, 10, 20], 7),
            ] {
                assert!(
                    buffer(&record(8, true, &sid(authority, &sub), flags), 8)
                        .logon()
                        .is_err()
                );
            }
            for (authority, sub, flags) in [
                (5, vec![0x2000], 0x60),
                (16, vec![0x2000, 1], 0x60),
                (16, vec![0x2000], 0),
                (16, vec![0xffff], 0x60),
            ] {
                assert!(
                    buffer(&record(8, false, &sid(authority, &sub), flags), 8)
                        .integrity()
                        .is_err()
                );
            }
        }

        fn stats() -> Vec<u8> {
            let mut bytes = vec![0; 56];
            bytes[0..8].copy_from_slice(&11u64.to_le_bytes());
            bytes[8..16].copy_from_slice(&12u64.to_le_bytes());
            bytes[24..28].copy_from_slice(&1u32.to_le_bytes());
            bytes[48..56].copy_from_slice(&13u64.to_le_bytes());
            bytes
        }

        #[test]
        fn peer_scalar_and_statistics_outputs_are_strict() {
            for length in [0, 1, 3, 5, 55, 57] {
                assert!(scalar(&vec![0; length]).is_err());
                assert!(statistics(&vec![0; length]).is_err());
            }
            assert!(!boolean(&0u32.to_le_bytes()).unwrap());
            assert!(boolean(&1u32.to_le_bytes()).unwrap());
            for value in [2u32, u32::MAX] {
                assert!(boolean(&value.to_le_bytes()).is_err());
            }
            for (value, expected) in [
                (1u32, ElevationType::Default),
                (2, ElevationType::Full),
                (3, ElevationType::Limited),
            ] {
                assert_eq!(elevation(&value.to_le_bytes()).unwrap(), expected);
            }
            for value in [0u32, 4, u32::MAX] {
                assert!(elevation(&value.to_le_bytes()).is_err());
            }
            assert_eq!(
                statistics(&stats()).unwrap(),
                Stamp {
                    token: 11,
                    authentication: 12,
                    modified: 13
                }
            );
            for kind in [0u32, 2, 3, u32::MAX] {
                let mut bytes = stats();
                bytes[24..28].copy_from_slice(&kind.to_le_bytes());
                assert!(statistics(&bytes).is_err());
            }
        }

        #[test]
        fn peer_token_mutation_and_primary_token_replacement_both_fail() {
            let original = statistics(&stats()).unwrap();
            stable_token(original, original, original).unwrap();
            for offset in [0, 8, 48] {
                let mut bytes = stats();
                bytes[offset] ^= 1;
                let changed = statistics(&bytes).unwrap();
                assert!(stable_token(original, changed, original).is_err());
                assert!(stable_token(original, original, changed).is_err());
            }
        }

        #[test]
        fn peer_revalidation_compares_every_observed_identity_and_state_field() {
            let expected = PeerEvidence {
                process_id: 42,
                creation_time: 100,
                token: TokenEvidence {
                    user: Sid::from_bytes(&sid(5, &[21, 1])).unwrap(),
                    logon: Sid::from_bytes(&sid(5, &[5, 1, 2])).unwrap(),
                    session_id: 1,
                    integrity: IntegrityLevel::Medium,
                    elevated: false,
                    elevation_type: ElevationType::Limited,
                    is_app_container: false,
                    token_id: 1,
                    authentication_id: 2,
                    modified_id: 3,
                },
            };
            unchanged(&expected, &expected).unwrap();
            for field in 0..12 {
                let mut actual = expected.clone();
                match field {
                    0 => actual.process_id += 1,
                    1 => actual.creation_time += 1,
                    2 => actual.token.user = Sid::from_bytes(&sid(5, &[21, 2])).unwrap(),
                    3 => actual.token.logon = Sid::from_bytes(&sid(5, &[5, 1, 3])).unwrap(),
                    4 => actual.token.session_id += 1,
                    5 => actual.token.integrity = IntegrityLevel::High,
                    6 => actual.token.elevated = true,
                    7 => actual.token.elevation_type = ElevationType::Full,
                    8 => actual.token.is_app_container = true,
                    9 => actual.token.token_id += 1,
                    10 => actual.token.authentication_id += 1,
                    11 => actual.token.modified_id += 1,
                    _ => unreachable!(),
                }
                assert!(
                    matches!(unchanged(&expected, &actual), Err(PeerError::Changed)),
                    "field {field}"
                );
            }
        }
    }
}
