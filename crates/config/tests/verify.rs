// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_config::verify::{self, VerifyError};
use std::io::{self, Cursor, Read};

#[test]
fn known_vectors_report_integrity_evidence_only() {
    for (algorithm, expected) in [
        (
            "sha256",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            "sha512",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        ),
    ] {
        let r = verify::stream(&mut Cursor::new(b"abc"), algorithm, None).unwrap();
        assert_eq!(r.digest, expected);
        assert_eq!(r.bytes, 3);
        assert_eq!(r.status, "hash-only");
        assert!(!r.publisher_verified);
        let r = verify::stream(
            &mut Cursor::new(b"abc"),
            algorithm,
            Some(&expected.to_uppercase()),
        )
        .unwrap();
        assert_eq!(r.status, "checksum-match");
        assert!(!r.publisher_verified);
        let err =
            verify::stream(&mut Cursor::new(b"changed"), algorithm, Some(expected)).unwrap_err();
        let VerifyError::Mismatch(result) = err else {
            panic!("wrong error: {err}")
        };
        assert_eq!(result.status, "checksum-mismatch");
        assert!(!result.digest.is_empty());
        assert!(!result.publisher_verified);
    }
}

#[test]
fn invalid_parameters_do_not_read_input() {
    for (algorithm, expected) in [
        ("md5", None),
        ("sha256", Some("abc")),
        ("sha256", Some("zz")),
    ] {
        let mut reader = Cursor::new(b"abc");
        assert!(verify::stream(&mut reader, algorithm, expected).is_err());
        assert_eq!(reader.position(), 0);
    }
}

struct Broken;
impl Read for Broken {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("broken input"))
    }
}

#[test]
fn incomplete_input_never_produces_success() {
    assert!(matches!(
        verify::stream(&mut Cursor::new(b"prefix").chain(Broken), "sha256", None),
        Err(VerifyError::Io(_))
    ));
}

struct RepeatedA {
    left: usize,
    max: usize,
}
impl Read for RepeatedA {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.max = self.max.max(buf.len());
        let n = buf.len().min(self.left);
        buf[..n].fill(b'a');
        self.left -= n;
        Ok(n)
    }
}

#[test]
fn large_input_streams_with_bounded_buffer() {
    let mut input = RepeatedA {
        left: 1000000,
        max: 0,
    };
    let r = verify::stream(&mut input, "SHA-256", None).unwrap();
    assert_eq!(
        r.digest,
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
    assert_eq!(r.bytes, 1000000);
    assert!(input.max <= 128 * 1024);
}

#[test]
fn file_hashes_regular_inputs_and_rejects_missing_or_directory() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("image.iso");
    std::fs::write(&file, b"abc").unwrap();
    assert_eq!(verify::file(&file, "sha256", None).unwrap().bytes, 3);
    assert!(verify::file(dir.path(), "sha256", None).is_err());
    assert!(verify::file(dir.path().join("missing"), "sha256", None).is_err());
}

#[cfg(unix)]
#[test]
fn file_verification_rejects_symlink_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("real.iso");
    let alias = directory.path().join("alias.iso");
    std::fs::write(&source, b"abc").unwrap();
    std::os::unix::fs::symlink(&source, &alias).unwrap();
    assert!(verify::file(alias, "sha256", None).is_err());
}
