// SPDX-License-Identifier: GPL-3.0-or-later
//! Streaming integrity checks. A supplied checksum does not authenticate its publisher.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::{
    fs::File,
    io::{self, Read, Seek},
    path::Path,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verification {
    pub algorithm: String,
    pub digest: String,
    pub expected: Option<String>,
    pub bytes: u64,
    pub status: String,
    pub publisher_verified: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("checksum mismatch")]
    Mismatch(Box<Verification>),
}

/// Hash a stream using a fixed 128 KiB buffer, with optional expected checksum.
pub fn stream(
    reader: &mut impl Read,
    algorithm: &str,
    expected: Option<&str>,
) -> Result<Verification, VerifyError> {
    let algorithm = algorithm.to_ascii_lowercase().replace('-', "");
    let digits = match algorithm.as_str() {
        "sha256" => 64,
        "sha512" => 128,
        _ => return Err(VerifyError::Invalid("use sha256 or sha512".into())),
    };
    let expected = expected
        .map(|value| {
            if value.len() != digits || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(VerifyError::Invalid(format!(
                    "expected checksum must contain {digits} hexadecimal characters"
                )));
            }
            Ok(value.to_ascii_lowercase())
        })
        .transpose()?;
    let (digest, bytes) = if algorithm == "sha256" {
        hash::<Sha256>(reader)?
    } else {
        hash::<Sha512>(reader)?
    };
    let status = match &expected {
        None => "hash-only",
        Some(expected) if expected == &digest => "checksum-match",
        Some(_) => "checksum-mismatch",
    };
    let result = Verification {
        algorithm,
        digest,
        expected,
        bytes,
        status: status.into(),
        publisher_verified: false,
    };
    if status == "checksum-mismatch" {
        Err(VerifyError::Mismatch(Box::new(result)))
    } else {
        Ok(result)
    }
}

/// Hash a regular file. Devices, sockets and named pipes are rejected.
pub fn file(
    path: impl AsRef<Path>,
    algorithm: &str,
    expected: Option<&str>,
) -> Result<Verification, VerifyError> {
    let path = path.as_ref();
    let mut file = crate::regular::open(path)?;
    let before = file.metadata()?;
    let identity = crate::regular::identity(&file)?;
    let result = opened_file(&mut file, algorithm, expected)?;
    crate::regular::unchanged(path, &file, &before, &identity, result.bytes)?;
    Ok(result)
}

/// Hash the complete contents of a retained regular-file handle, from byte zero.
/// Bounds work to its initial length plus one byte; concurrent growth, shrinkage,
/// or a changed modification time fails. This does not attest a pathname.
pub fn opened_file(
    file: &mut File,
    algorithm: &str,
    expected: Option<&str>,
) -> Result<Verification, VerifyError> {
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(VerifyError::Invalid(
            "checksum input must be a regular file".into(),
        ));
    }
    file.rewind()?;
    let result = exact_length(file, before.len(), algorithm, expected)?;
    let after = file.metadata()?;
    if before.len() != after.len() || before.modified()? != after.modified()? {
        return Err(VerifyError::Invalid(
            "checksum input changed while reading".into(),
        ));
    }
    Ok(result)
}

fn exact_length(
    reader: &mut impl Read,
    length: u64,
    algorithm: &str,
    expected: Option<&str>,
) -> Result<Verification, VerifyError> {
    let limit = length
        .checked_add(1)
        .ok_or_else(|| VerifyError::Invalid("checksum input length overflow".into()))?;
    let result = stream(&mut reader.take(limit), algorithm, expected)?;
    if result.bytes != length {
        return Err(VerifyError::Invalid(
            "checksum input grew or shrank while reading".into(),
        ));
    }
    Ok(result)
}

fn hash<D: Digest + Default>(reader: &mut impl Read) -> Result<(String, u64), VerifyError> {
    let mut hash = D::default();
    let mut buffer = vec![0u8; 128 * 1024];
    let mut bytes = 0u64;
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => count,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        };
        hash.update(&buffer[..count]);
        bytes = bytes
            .checked_add(count as u64)
            .ok_or_else(|| VerifyError::Invalid("checksum input length overflow".into()))?;
    }
    Ok((hex::encode(hash.finalize()), bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    struct Endless {
        bytes: usize,
    }
    impl Read for Endless {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            buffer.fill(b'x');
            self.bytes += buffer.len();
            Ok(buffer.len())
        }
    }

    #[test]
    fn growing_input_stops_at_the_original_length_plus_one() {
        let mut growing = Endless { bytes: 0 };
        assert!(exact_length(&mut growing, 250_000, "sha256", None).is_err());
        assert_eq!(growing.bytes, 250_001);
        assert!(exact_length(&mut Cursor::new(b"short"), 6, "sha256", None).is_err());
    }

    #[test]
    fn opened_file_rewinds_and_reads_the_complete_retained_file() {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"abc").unwrap();
        let result = opened_file(&mut file, "sha256", None).unwrap();
        assert_eq!(result.bytes, 3);
        assert_eq!(
            result.digest,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
