// SPDX-License-Identifier: GPL-3.0-or-later
//! Non-mutating disk readiness policy; this does not authorize a target.
use std::io;

pub(super) const ATTRIBUTES_BYTES: usize = 16;

pub(super) fn check(
    mut attributes: impl FnMut() -> io::Result<[u8; ATTRIBUTES_BYTES]>,
    mut writable: impl FnMut() -> io::Result<()>,
) -> io::Result<()> {
    validate_attributes(&attributes().map_err(|e| context("disk attributes query", e))?)?;
    writable().map_err(|error| {
        // ERROR_WRITE_PROTECT is a known refusal. All other errors still fail
        // closed, without mistaking unsupported/absent media for writability.
        if error.raw_os_error() == Some(19) {
            io::Error::new(io::ErrorKind::PermissionDenied, "disk is write protected")
        } else {
            context("disk writability query", error)
        }
    })?;
    validate_attributes(&attributes().map_err(|e| context("disk attributes recheck", e))?)
}

pub(super) fn complete_attributes(
    bytes: [u8; ATTRIBUTES_BYTES],
    returned: usize,
) -> io::Result<[u8; ATTRIBUTES_BYTES]> {
    if returned != ATTRIBUTES_BYTES {
        return Err(invalid("disk attributes query returned an invalid size"));
    }
    Ok(bytes)
}

fn validate_attributes(bytes: &[u8; ATTRIBUTES_BYTES]) -> io::Result<()> {
    let version = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let reserved = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let flags = u64::from_le_bytes(bytes[8..].try_into().unwrap());
    if version as usize != ATTRIBUTES_BYTES || reserved != 0 || flags & !3 != 0 {
        return Err(invalid(
            "disk attributes contain unsupported fields or flags",
        ));
    }
    if flags & 1 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "disk is offline",
        ));
    }
    if flags & 2 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "disk is read-only",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn context(stage: &'static str, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("{stage}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn attributes(flags: u64) -> [u8; ATTRIBUTES_BYTES] {
        let mut bytes = [0; ATTRIBUTES_BYTES];
        bytes[..4].copy_from_slice(&(ATTRIBUTES_BYTES as u32).to_le_bytes());
        bytes[8..].copy_from_slice(&flags.to_le_bytes());
        bytes
    }

    #[test]
    fn online_writable_disk_requires_both_queries_and_a_final_attribute_check() {
        let calls = Cell::new(0);
        check(
            || {
                assert!([0, 2].contains(&calls.get()));
                calls.set(calls.get() + 1);
                Ok(attributes(0))
            },
            || {
                assert_eq!(calls.get(), 1);
                calls.set(2);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn offline_read_only_or_unknown_attributes_never_probe_writability() {
        for flags in [1, 2, 3, 4, 1 << 63, u64::MAX] {
            let error = check(
                || Ok(attributes(flags)),
                || panic!("unexpected writable query"),
            )
            .unwrap_err();
            assert_eq!(
                error.kind(),
                if flags & !3 == 0 {
                    io::ErrorKind::PermissionDenied
                } else {
                    io::ErrorKind::InvalidData
                }
            );
        }
    }

    #[test]
    fn malformed_attribute_structure_fails_without_writable_query() {
        for (offset, value) in [(0, 0), (0, 15), (0, 17), (0, u32::MAX), (4, 1)] {
            let mut bytes = attributes(0);
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                check(|| Ok(bytes), || panic!("unexpected writable query"))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        for returned in (0..ATTRIBUTES_BYTES).chain([ATTRIBUTES_BYTES + 1, usize::MAX]) {
            assert!(complete_attributes(attributes(0), returned).is_err());
        }
        assert_eq!(
            complete_attributes(attributes(0), ATTRIBUTES_BYTES).unwrap(),
            attributes(0)
        );
    }

    #[test]
    fn write_protection_and_unknown_query_failures_never_pass() {
        for code in [1, 5, 19, 21, 50, 87, 1167] {
            assert!(
                check(
                    || Err(io::Error::from_raw_os_error(code)),
                    || panic!("unexpected writable query"),
                )
                .is_err()
            );
            let calls = Cell::new(0);
            assert!(
                check(
                    || {
                        calls.set(calls.get() + 1);
                        Ok(attributes(0))
                    },
                    || Err(io::Error::from_raw_os_error(code)),
                )
                .is_err()
            );
            assert_eq!(calls.get(), 1);
        }
        assert_eq!(
            check(
                || Ok(attributes(0)),
                || Err(io::Error::from_raw_os_error(19))
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn changed_attributes_or_lost_device_during_query_fail_closed() {
        for flags in [1, 2, 4] {
            let mut calls = 0;
            assert!(
                check(
                    || {
                        calls += 1;
                        Ok(attributes(if calls == 1 { 0 } else { flags }))
                    },
                    || Ok(()),
                )
                .is_err()
            );
            assert_eq!(calls, 2);
        }
        let mut calls = 0;
        assert!(
            check(
                || {
                    calls += 1;
                    if calls == 1 {
                        Ok(attributes(0))
                    } else {
                        Err(io::Error::from_raw_os_error(1167))
                    }
                },
                || Ok(()),
            )
            .is_err()
        );
        assert_eq!(calls, 2);
    }
}
