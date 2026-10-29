// SPDX-License-Identifier: GPL-3.0-or-later
use super::StableDeviceId;
use std::io;

pub(super) const MAX_DESCRIPTOR: usize = 65_536;
const DESCRIPTOR_PREFIX: usize = 36;

#[derive(Debug, thiserror::Error)]
#[error("{query}: {source}")]
struct QueryError {
    query: &'static str,
    #[source]
    source: io::Error,
}

/// Add the failed request without discarding its native error or error kind.
/// Call after any operation-specific unsupported-status handling.
pub(super) fn query_error(query: &'static str, source: io::Error) -> io::Error {
    io::Error::new(source.kind(), QueryError { query, source })
}

/// Resolve only a failed device-ID header query. Some USB storage drivers use
/// ERROR_INVALID_PARAMETER for an unavailable optional ID property; require a
/// separate PropertyExistsQuery to reject that property before accepting it as
/// absent. Successful headers and all body/parse failures bypass this policy.
pub(super) fn device_id_header_failure(
    error: io::Error,
    exists: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    match error.raw_os_error() {
        // Win32 ERROR_INVALID_FUNCTION / ERROR_NOT_SUPPORTED: existing policy.
        Some(1 | 50) => Ok(()),
        // Win32 ERROR_INVALID_PARAMETER. A supported property must still fail
        // with the original header error, not silently lose its identifier.
        Some(87) => match exists() {
            Err(unavailable) if matches!(unavailable.raw_os_error(), Some(1 | 50 | 87)) => Ok(()),
            Err(other) => Err(query_error("StorageDeviceIdProperty/exists", other)),
            Ok(()) => Err(query_error("StorageDeviceIdProperty/header", error)),
        },
        _ => Err(query_error("StorageDeviceIdProperty/header", error)),
    }
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid storage device descriptor",
    )
}

fn number(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let value = bytes.get(offset..offset + 4).ok_or_else(invalid)?;
    Ok(u32::from_le_bytes(value.try_into().map_err(|_| invalid())?))
}

pub(super) fn descriptor_size(header: &[u8]) -> io::Result<usize> {
    let version = number(header, 0)? as usize;
    let size = number(header, 4)? as usize;
    if !(DESCRIPTOR_PREFIX..=MAX_DESCRIPTOR).contains(&size)
        || !(DESCRIPTOR_PREFIX..=size).contains(&version)
    {
        return Err(invalid());
    }
    Ok(size)
}

pub(super) fn parse_descriptor(bytes: &[u8]) -> io::Result<(String, u32)> {
    let size = descriptor_size(bytes)?;
    let bytes = bytes.get(..size).ok_or_else(invalid)?;
    if bytes[8] != 0 || number(bytes, 32)? as usize > size - DESCRIPTOR_PREFIX {
        return Err(invalid());
    }
    let offset = number(bytes, 24)? as usize;
    if offset == 0 {
        return Ok((String::new(), number(bytes, 28)?));
    }
    if !(DESCRIPTOR_PREFIX..size).contains(&offset) {
        return Err(invalid());
    }
    let serial = &bytes[offset..];
    let end = serial
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(invalid)?;
    if end == 0 || end > 4096 || !serial[..end].iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err(invalid());
    }
    let serial = std::str::from_utf8(&serial[..end])
        .map_err(|_| invalid())?
        .trim()
        .to_owned();
    if serial.is_empty() {
        return Err(invalid());
    }
    Ok((serial, number(bytes, 28)?))
}

fn invalid_id() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid storage device ID descriptor",
    )
}

pub(super) fn id_descriptor_size(header: &[u8]) -> io::Result<usize> {
    let version = number(header, 0).map_err(|_| invalid_id())?;
    let size = number(header, 4).map_err(|_| invalid_id())? as usize;
    // The known structure is 16 bytes including its one-byte trailing array.
    // Unknown versions require a separate parser, not guessed field offsets.
    if version != 16 || !(16..=MAX_DESCRIPTOR).contains(&size) {
        return Err(invalid_id());
    }
    Ok(size)
}

pub(super) fn parse_device_ids(bytes: &[u8]) -> io::Result<Option<StableDeviceId>> {
    let size = id_descriptor_size(bytes)?;
    if size != bytes.len() {
        return Err(invalid_id());
    }
    let count = number(bytes, 8).map_err(|_| invalid_id())? as usize;
    if count == 0 {
        return if size == 16 {
            Ok(None)
        } else {
            Err(invalid_id())
        };
    }
    if count > 64 {
        return Err(invalid_id());
    }
    let mut offset = 12;
    let mut result = None;
    for index in 0..count {
        let record = bytes.get(offset..).ok_or_else(invalid_id)?;
        let header = record.get(..16).ok_or_else(invalid_id)?;
        let code_set = number(header, 0).map_err(|_| invalid_id())?;
        let kind = number(header, 4).map_err(|_| invalid_id())?;
        let length = u16::from_le_bytes([header[8], header[9]]) as usize;
        let next = u16::from_le_bytes([header[10], header[11]]) as usize;
        let association = number(header, 12).map_err(|_| invalid_id())?;
        let end = 16 + length;
        let identifier = record.get(16..end).ok_or_else(invalid_id)?;
        if length == 0 || !(1..=3).contains(&code_set) || association > 2 {
            return Err(invalid_id());
        }
        // At most seven bytes of structure/alignment padding are supported.
        // Validate the complete chain even when an earlier record supplied ID.
        let span = if index + 1 == count {
            if next != 0 && next != record.len() {
                return Err(invalid_id());
            }
            record.len()
        } else {
            if next == 0 || next >= record.len() {
                return Err(invalid_id());
            }
            next
        };
        if span < end || span - end > 7 {
            return Err(invalid_id());
        }
        if kind == 3 {
            if code_set != 1 {
                return Err(invalid_id());
            }
            // NAA 2/3/5 are defined 64-bit forms but are not accepted as the
            // fallback identity here. Reserved types and wrong lengths fail.
            match (identifier[0] >> 4, identifier.len()) {
                (2 | 3 | 5, 8) => {}
                (6, 16) => {
                    if association == 0 {
                        let id = StableDeviceId::from_naa128(
                            identifier.try_into().map_err(|_| invalid_id())?,
                        )
                        .map_err(|_| invalid_id())?;
                        if result.as_ref().is_some_and(|previous| *previous != id) {
                            return Err(invalid_id());
                        }
                        result = Some(id);
                    }
                }
                _ => return Err(invalid_id()),
            }
        }
        offset += span;
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn original_os_error(error: &io::Error) -> Option<i32> {
        error
            .get_ref()
            .and_then(std::error::Error::source)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .and_then(io::Error::raw_os_error)
    }

    #[test]
    fn device_id_header_invalid_parameter_accepts_only_confirmed_unavailability() {
        for status in [1, 50, 87] {
            let result = device_id_header_failure(io::Error::from_raw_os_error(87), || {
                Err(io::Error::from_raw_os_error(status))
            });
            assert!(
                result.is_ok(),
                "negative existence status {status}: {result:?}"
            );
        }
    }

    #[test]
    fn device_id_header_invalid_parameter_keeps_failure_when_property_exists() {
        let error =
            device_id_header_failure(io::Error::from_raw_os_error(87), || Ok(())).unwrap_err();
        assert_eq!(original_os_error(&error), Some(87));
        assert!(error.to_string().contains("StorageDeviceIdProperty/header"));
    }

    #[test]
    fn device_id_header_existence_errors_keep_their_native_cause() {
        for status in [2, 5, 13, 21, 31, 122, 1117, 1460] {
            let error = device_id_header_failure(io::Error::from_raw_os_error(87), || {
                Err(io::Error::from_raw_os_error(status))
            })
            .unwrap_err();
            assert_eq!(original_os_error(&error), Some(status));
            assert!(error.to_string().contains("StorageDeviceIdProperty/exists"));
        }
    }

    #[test]
    fn device_id_header_other_errors_never_probe_or_become_absence() {
        for status in [1, 50, 2, 5, 13, 21, 31, 122, 1117, 1460] {
            let result = device_id_header_failure(io::Error::from_raw_os_error(status), || {
                panic!("existence query is only valid after header error 87")
            });
            if [1, 50].contains(&status) {
                assert!(result.is_ok());
            } else {
                let error = result.unwrap_err();
                assert_eq!(original_os_error(&error), Some(status));
                assert!(error.to_string().contains("StorageDeviceIdProperty/header"));
            }
        }
        let error = device_id_header_failure(io::Error::other("transport failed"), || {
            panic!("local errors must not invoke the existence query")
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(error.to_string().contains("transport failed"));
    }

    #[test]
    fn query_error_identifies_the_failed_request_and_retains_the_os_error() {
        let source = io::Error::from_raw_os_error(87);
        let message = source.to_string();
        let kind = source.kind();
        let error = query_error("StorageDeviceIdProperty/header", source);
        assert!(error.to_string().contains("StorageDeviceIdProperty/header"));
        assert!(error.to_string().contains(&message));
        assert_eq!(error.kind(), kind);
        let original = error
            .get_ref()
            .and_then(std::error::Error::source)
            .and_then(|source| source.downcast_ref::<io::Error>())
            .expect("the original OS error remains in the source chain");
        assert_eq!(original.raw_os_error(), Some(87));
    }

    fn descriptor() -> Vec<u8> {
        let mut bytes = vec![0; 48];
        bytes[..4].copy_from_slice(&36u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&48u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&36u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&7u32.to_le_bytes());
        bytes[36..43].copy_from_slice(b"SERIAL1");
        bytes
    }

    #[test]
    fn bounded_descriptor_extracts_serial_and_bus() {
        let bytes = descriptor();
        assert_eq!(descriptor_size(&bytes[..8]).unwrap(), 48);
        assert_eq!(parse_descriptor(&bytes).unwrap(), ("SERIAL1".into(), 7));
    }

    #[test]
    fn descriptor_rejects_missing_short_oversized_or_inconsistent_data() {
        let original = descriptor();
        for len in 0..original.len() {
            assert!(parse_descriptor(&original[..len]).is_err());
        }
        for (at, value) in [
            (0, 0),
            (0, 49),
            (4, u32::MAX),
            (4, 35),
            (24, 8),
            (24, 48),
            (24, u32::MAX),
            (32, u32::MAX),
        ] {
            let mut bytes = original.clone();
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(parse_descriptor(&bytes).is_err(), "{at}, {value}");
        }
    }

    #[test]
    fn descriptor_rejects_non_disk_missing_terminator_and_invalid_serial() {
        for (at, value) in [(8, 5), (36, 0), (36, 0xff), (36, b'\n')] {
            let mut bytes = descriptor();
            bytes[at] = value;
            assert!(parse_descriptor(&bytes).is_err());
        }
        let mut bytes = descriptor();
        bytes[36..].fill(b'X');
        assert!(parse_descriptor(&bytes).is_err());
        bytes[36..43].fill(b' ');
        bytes[43] = 0;
        assert!(parse_descriptor(&bytes).is_err());
    }

    // Captured from a newly created, test-owned VHDX. Its parsed device ID was
    // unchanged after detach/reattach. The final NextOffset points to the end.
    fn device_ids() -> Vec<u8> {
        hex::decode(concat!(
            "100000005c00000002000000",
            "010000000100000018002c0000000000",
            "4d53465420202020b279f9ad1a924a47a00dd4604957317200000000",
            "01000000030000001000240000000000",
            "60022480b279f9ad1a92d4604957317200000000"
        ))
        .unwrap()
    }

    #[test]
    fn absent_serial_is_distinct_from_a_malformed_reported_serial() {
        let mut bytes = descriptor();
        bytes[24..28].fill(0);
        assert_eq!(parse_descriptor(&bytes).unwrap(), (String::new(), 7));
    }

    #[test]
    fn observed_device_id_uses_semantic_naa_bytes_not_padding() {
        let bytes = device_ids();
        assert_eq!(id_descriptor_size(&bytes[..8]).unwrap(), 92);
        let expected = StableDeviceId::from_naa128(
            hex::decode("60022480b279f9ad1a92d46049573172")
                .unwrap()
                .try_into()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(parse_device_ids(&bytes).unwrap(), Some(expected.clone()));
        let mut changed_padding = bytes.clone();
        changed_padding[52..56].fill(0xa5);
        changed_padding[88..92].fill(0x5a);
        assert_eq!(
            parse_device_ids(&changed_padding).unwrap(),
            Some(expected.clone())
        );
        changed_padding[66..68].fill(0); // Last record may also terminate with zero.
        assert_eq!(parse_device_ids(&changed_padding).unwrap(), Some(expected));
    }

    #[test]
    fn device_id_rejects_truncation_counts_overlaps_and_out_of_bounds_links() {
        let original = device_ids();
        for length in 0..original.len() {
            assert!(
                parse_device_ids(&original[..length]).is_err(),
                "length {length}"
            );
        }
        for (offset, value) in [
            (0, 0u32),
            (0, 17),
            (4, 15),
            (4, u32::MAX),
            (8, 0),
            (8, 1),
            (8, 3),
            (8, u32::MAX),
        ] {
            let mut bytes = original.clone();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(parse_device_ids(&bytes).is_err(), "u32 {offset}={value}");
        }
        for (offset, value) in [
            (20, u16::MAX),
            (22, 0),
            (22, 1),
            (22, 39),
            (22, u16::MAX),
            (64, 0),
            (64, 15),
            (64, 17),
            (64, u16::MAX),
            (66, 1),
            (66, 31),
            (66, 35),
            (66, 37),
            (66, u16::MAX),
        ] {
            let mut bytes = original.clone();
            bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
            assert!(parse_device_ids(&bytes).is_err(), "u16 {offset}={value}");
        }
    }

    #[test]
    fn device_id_requires_binary_device_associated_supported_naa() {
        let original = device_ids();
        for association in [1u32, 2] {
            let mut bytes = original.clone();
            bytes[68..72].copy_from_slice(&association.to_le_bytes());
            assert_eq!(parse_device_ids(&bytes).unwrap(), None);
        }
        for (offset, value) in [(56, 0u32), (56, 2), (56, 3), (56, 4), (68, 3)] {
            let mut bytes = original.clone();
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(parse_device_ids(&bytes).is_err(), "{offset}={value}");
        }
        for kind in [0u32, 1, 2, 4, 5, 6, 7, 8, u32::MAX] {
            let mut bytes = original.clone();
            bytes[60..64].copy_from_slice(&kind.to_le_bytes());
            assert_eq!(parse_device_ids(&bytes).unwrap(), None);
        }
        for naa in 0..16 {
            if naa == 6 {
                continue;
            }
            let mut bytes = original.clone();
            bytes[72] = naa << 4;
            assert!(parse_device_ids(&bytes).is_err(), "NAA {naa}");
        }
    }

    #[test]
    fn device_id_detects_conflicting_candidates_independent_of_order() {
        let original = device_ids();
        let mut bytes = original.clone();
        bytes[4..8].copy_from_slice(&128u32.to_le_bytes());
        bytes[8..12].copy_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&original[56..]);
        assert_eq!(
            parse_device_ids(&bytes).unwrap(),
            parse_device_ids(&original).unwrap()
        );
        bytes[123] ^= 1;
        assert!(parse_device_ids(&bytes).is_err());
        // Put the NAA record before the vendor record; its identity is unchanged.
        let mut reordered = original[..12].to_vec();
        reordered.extend_from_slice(&original[56..]);
        reordered.extend_from_slice(&original[12..56]);
        assert_eq!(
            parse_device_ids(&reordered).unwrap(),
            parse_device_ids(&original).unwrap()
        );
    }

    #[test]
    fn empty_or_defined_unsupported_ids_do_not_fabricate_identity() {
        let mut bytes = vec![0; 16];
        bytes[..4].copy_from_slice(&16u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&16u32.to_le_bytes());
        assert_eq!(parse_device_ids(&bytes).unwrap(), None);
        // Defined 64-bit NAA forms are well-formed, but this implementation
        // only uses the validated 128-bit NAA-6 form as fallback identity.
        for naa in [2, 3, 5] {
            let mut bytes = device_ids();
            bytes.truncate(84);
            bytes[4..8].copy_from_slice(&84u32.to_le_bytes());
            bytes[64..66].copy_from_slice(&8u16.to_le_bytes());
            bytes[66..68].copy_from_slice(&28u16.to_le_bytes());
            bytes[72] = naa << 4;
            assert_eq!(parse_device_ids(&bytes).unwrap(), None);
        }
        let mut trailing = device_ids();
        trailing.push(0);
        assert!(parse_device_ids(&trailing).is_err());
    }
}
