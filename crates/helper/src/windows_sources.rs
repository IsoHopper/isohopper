// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained-source storage mapping, not target authorization or complete safety.
//! Maps filesystem-reported disk extents and rejects VHD/ISO dependencies and
//! externally backed files. It does not resolve Storage Spaces or RAID ancestry.
//! The caller supplies a fresh snapshot from its retained target and separately
//! authenticates the job, checks storage pools, protects system storage, and
//! verifies source content. Filesystems unable to prove inline file backing are
//! unsupported; a successful mapping does not establish complete safety.
use std::io;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SourceExtent {
    pub disk_number: u32,
    pub start_offset: u64,
    pub length_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum SourceError {
    #[error("source must be a retained regular file")]
    NotRegularFile,
    #[error("source mapping is unavailable: {0}")]
    Mapping(&'static str),
    #[error("source mapping failed during {stage}: {source}")]
    Io {
        stage: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("source resides on the candidate target")]
    OnTarget { extents: Vec<SourceExtent> },
    #[error("file-backed virtual source storage is unsupported")]
    VirtualDependency,
    #[error("externally backed source files are unsupported")]
    ExternalBacking,
    #[error("retained source, volume mapping, or target evidence changed")]
    Changed,
}

#[cfg(windows)]
pub use native::{SourceBinding, bind_source};
#[cfg(windows)]
pub(crate) use native::{no_virtual_dependencies, source_guid, volume_extents};

#[cfg(any(windows, test))]
const MAX_PATH_UNITS: usize = 32_768;
#[cfg(any(windows, test))]
const MAX_EXTENTS: usize = 64;

#[cfg(any(windows, test))]
fn check_external_backing(result: io::Result<usize>) -> Result<(), SourceError> {
    match result {
        // Win32 ERROR_OBJECT_NOT_EXTERNALLY_BACKED is the only accepted
        // negative result. Missing backing services are unknown, not safe.
        Err(error) if error.raw_os_error() == Some(342) => Ok(()),
        Err(source) => Err(SourceError::Io {
            stage: "source external backing",
            source,
        }),
        Ok(_) => Err(SourceError::ExternalBacking),
    }
}

#[cfg(any(windows, test))]
fn volume_guid(path: &[u16]) -> Result<String, SourceError> {
    if path.is_empty() || path.len() >= MAX_PATH_UNITS || path.contains(&0) {
        return Err(SourceError::Mapping("invalid source GUID path length"));
    }
    let path = String::from_utf16(path)
        .map_err(|_| SourceError::Mapping("invalid source path encoding"))?;
    let suffix = path
        .strip_prefix(r"\\?\Volume{")
        .ok_or(SourceError::Mapping(
            "source has no canonical local volume GUID",
        ))?;
    let guid = suffix
        .get(..36)
        .ok_or(SourceError::Mapping("truncated source volume GUID"))?;
    let relative = suffix
        .get(36..)
        .and_then(|s| s.strip_prefix("}\\"))
        .ok_or(SourceError::Mapping("invalid source volume GUID boundary"))?;
    if !guid.bytes().enumerate().all(|(i, b)| {
        if [8, 13, 18, 23].contains(&i) {
            b == b'-'
        } else {
            b.is_ascii_hexdigit()
        }
    }) || relative.is_empty()
        || relative.contains(['/', ':', '<', '>', '|', '?', '*'])
        || relative.chars().any(char::is_control)
        || relative
            .split('\\')
            .any(|s| s.is_empty() || matches!(s, "." | ".."))
    {
        return Err(SourceError::Mapping("unsupported source volume GUID path"));
    }
    Ok(format!(r"\\?\Volume{{{}}}\", guid.to_ascii_lowercase()))
}

#[cfg(any(windows, test))]
fn parse_extents(bytes: &[u8]) -> Result<Vec<SourceExtent>, SourceError> {
    let bad = || SourceError::Mapping("invalid source volume disk extents");
    if bytes.len() < 8 {
        return Err(bad());
    }
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if count == 0 || count > MAX_EXTENTS || bytes.len() != 8 + count * 24 {
        return Err(bad());
    }
    let mut extents = Vec::with_capacity(count);
    for entry in bytes[8..].as_chunks::<24>().0 {
        let start_offset = u64::from_le_bytes(entry[8..16].try_into().unwrap());
        let length_bytes = u64::from_le_bytes(entry[16..24].try_into().unwrap());
        if length_bytes == 0
            || start_offset
                .checked_add(length_bytes)
                .is_none_or(|end| end > i64::MAX as u64)
        {
            return Err(bad());
        }
        extents.push(SourceExtent {
            disk_number: u32::from_le_bytes(entry[..4].try_into().unwrap()),
            start_offset,
            length_bytes,
        });
    }
    extents.sort();
    if extents.windows(2).any(|p| {
        p[0].disk_number == p[1].disk_number
            && p[0].start_offset + p[0].length_bytes > p[1].start_offset
    }) {
        return Err(bad());
    }
    Ok(extents)
}

#[cfg(any(windows, test))]
fn reject_target(extents: &[SourceExtent], disk_number: u32) -> Result<(), SourceError> {
    if extents.is_empty() {
        return Err(SourceError::Mapping("source has no disk extents"));
    }
    if extents.iter().any(|e| e.disk_number == disk_number) {
        return Err(SourceError::OnTarget {
            extents: extents.to_vec(),
        });
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn check_dependencies(bytes: &[u8]) -> Result<(), SourceError> {
    if bytes.len() < 8 || bytes.len() > 8 + 64 * 28 {
        return Err(SourceError::Mapping(
            "invalid source dependency result size",
        ));
    }
    let version = u32::from_le_bytes(bytes[..4].try_into().unwrap());
    let count = u32::from_le_bytes(bytes[4..8].try_into().unwrap()) as usize;
    if version != 1 || count > 64 || bytes.len() < 8 + count * 28 {
        return Err(SourceError::Mapping("invalid source dependency result"));
    }
    if count != 0 {
        return Err(SourceError::VirtualDependency);
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn check_dependency_response(code: u32, bytes: &[u8]) -> Result<(), SourceError> {
    match code {
        0 => check_dependencies(bytes),
        // ERROR_VIRTDISK_NOT_VIRTUAL_DISK explicitly reports a nonvirtual
        // disk. It is not equivalent to a missing provider or unsupported
        // query. Windows defines output bytes only for ERROR_SUCCESS.
        0xc03a0015 => Ok(()),
        _ => Err(SourceError::Io {
            stage: "source backing dependencies",
            source: io::Error::from_raw_os_error(code as i32),
        }),
    }
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    volume_serial: u32,
    file_index: u64,
    length: u64,
    last_write: u64,
    created: u64,
}

#[cfg(any(windows, test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct Mapping {
    file: FileIdentity,
    guid: String,
    extents: Vec<SourceExtent>,
}

#[cfg(any(windows, test))]
fn unchanged(before: &Mapping, after: &Mapping) -> Result<(), SourceError> {
    if before != after {
        return Err(SourceError::Changed);
    }
    Ok(())
}

#[cfg(windows)]
mod native;

#[cfg(test)]
mod tests {
    use super::*;

    fn extent_bytes(entries: &[(u32, u64, u64)]) -> Vec<u8> {
        let mut bytes = vec![0; 8 + entries.len() * 24];
        bytes[..4].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        for (entry, &(disk, start, length)) in
            bytes[8..].as_chunks_mut::<24>().0.iter_mut().zip(entries)
        {
            entry[..4].copy_from_slice(&disk.to_le_bytes());
            entry[8..16].copy_from_slice(&start.to_le_bytes());
            entry[16..24].copy_from_slice(&length.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn source_paths_require_bounded_canonical_volume_guid_and_regular_relative_path() {
        let good = r"\\?\Volume{01234567-89AB-CDEF-0123-456789ABCDEF}\folder\source.iso";
        assert_eq!(
            volume_guid(&good.encode_utf16().collect::<Vec<_>>()).unwrap(),
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\"
        );
        for bad in [
            r"C:\source.iso",
            r"\\server\share\source.iso",
            r"\\?\UNC\server\share\source.iso",
            r"\\?\volume{01234567-89ab-cdef-0123-456789abcdef}\source.iso",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\..\source.iso",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\source.iso:stream",
            r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdeg}\source.iso",
        ] {
            assert!(volume_guid(&bad.encode_utf16().collect::<Vec<_>>()).is_err());
        }
        assert!(volume_guid(&[]).is_err());
        assert!(volume_guid(&vec![b'a' as u16; MAX_PATH_UNITS]).is_err());
        assert!(volume_guid(&[0xd800]).is_err());
        let mut embedded_nul: Vec<_> = good.encode_utf16().collect();
        embedded_nul.push(0);
        assert!(volume_guid(&embedded_nul).is_err());
    }

    #[test]
    fn every_source_extent_is_checked_including_another_partition_on_the_target() {
        let extents =
            parse_extents(&extent_bytes(&[(3, 4096, 8192), (7, 1024 * 1024, 8192)])).unwrap();
        reject_target(&extents, 9).unwrap();
        match reject_target(&extents, 7).unwrap_err() {
            SourceError::OnTarget { extents: reported } => assert_eq!(reported, extents),
            other => panic!("wrong error: {other}"),
        }
        assert!(reject_target(&[], 7).is_err());
        let reversed =
            parse_extents(&extent_bytes(&[(7, 1024 * 1024, 8192), (3, 4096, 8192)])).unwrap();
        assert_eq!(extents, reversed);
    }

    #[test]
    fn extent_parser_rejects_truncation_unbounded_counts_and_invalid_ranges() {
        let good = extent_bytes(&[(3, 4096, 8192)]);
        for length in 0..good.len() {
            assert!(parse_extents(&good[..length]).is_err());
        }
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(parse_extents(&trailing).is_err());
        for entries in [
            vec![],
            vec![(1, 0, 1); MAX_EXTENTS + 1],
            vec![(1, u64::MAX, 1)],
            vec![(1, 1, 0)],
            vec![(1, 1, u64::MAX)],
            vec![(1, i64::MAX as u64, 1)],
            vec![(1, 4096, 8192), (1, 4096, 8192)],
            vec![(1, 4096, 8192), (1, 8192, 8192)],
        ] {
            assert!(parse_extents(&extent_bytes(&entries)).is_err());
        }
        let mut huge = good;
        huge[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_extents(&huge).is_err());
    }

    #[test]
    fn only_validated_empty_host_dependency_result_establishes_direct_mapping() {
        let empty = [1, 0, 0, 0, 0, 0, 0, 0];
        check_dependencies(&empty).unwrap();
        let mut virtual_disk = vec![0; 8 + 28];
        virtual_disk[..4].copy_from_slice(&1u32.to_le_bytes());
        virtual_disk[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            check_dependencies(&virtual_disk),
            Err(SourceError::VirtualDependency)
        ));
        for length in 0..8 {
            assert!(check_dependencies(&empty[..length]).is_err());
        }
        let mut invalid = empty;
        invalid[0] = 2;
        assert!(check_dependencies(&invalid).is_err());
        invalid = empty;
        invalid[4] = 1;
        assert!(check_dependencies(&invalid).is_err());
        invalid = empty;
        invalid[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(check_dependencies(&invalid).is_err());
    }

    #[test]
    fn external_backing_requires_explicit_negative_evidence() {
        // Win32 ERROR_OBJECT_NOT_EXTERNALLY_BACKED, not generic unsupported.
        check_external_backing(Err(io::Error::from_raw_os_error(342))).unwrap();
        for reported_size in [0, 8, 256, usize::MAX] {
            assert!(matches!(
                check_external_backing(Ok(reported_size)),
                Err(SourceError::ExternalBacking)
            ));
        }
        for code in [1, 5, 50, 87, 122, 234] {
            assert!(matches!(
                check_external_backing(Err(io::Error::from_raw_os_error(code))),
                Err(SourceError::Io {
                    stage: "source external backing",
                    ..
                })
            ));
        }
        assert!(check_external_backing(Err(io::Error::other("unknown backing state"))).is_err());
    }

    #[test]
    fn dependency_response_accepts_only_valid_success_or_exact_nonvirtual_status() {
        let empty = [1, 0, 0, 0, 0, 0, 0, 0];
        check_dependency_response(0, &empty).unwrap();
        let mut virtual_disk = vec![0; 36];
        virtual_disk[..4].copy_from_slice(&1u32.to_le_bytes());
        virtual_disk[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert!(matches!(
            check_dependency_response(0, &virtual_disk),
            Err(SourceError::VirtualDependency)
        ));
        for bytes in [vec![], vec![0xff], vec![0xff; 16], vec![0; 1801]] {
            assert!(check_dependency_response(0, &bytes).is_err());
            // On non-success Windows leaves the output undefined. Only this
            // documented negative status may succeed without reading output.
            check_dependency_response(0xc03a0015, &bytes).unwrap();
        }
        check_dependency_response(0xc03a0015, &virtual_disk).unwrap();
    }

    #[test]
    fn dependency_response_rejects_every_other_failure_without_parsing_undefined_output() {
        for code in [
            1,
            2,
            5,
            50,
            87,
            122,
            234,
            1167,
            0xc03a0014, // ERROR_VIRTDISK_PROVIDER_NOT_FOUND
            0xc03a0016, // ERROR_VHD_PARENT_VHD_ACCESS_DENIED
            0xc03a001d, // ERROR_VIRTDISK_UNSUPPORTED_DISK_SECTOR_SIZE
            u32::MAX,
        ] {
            for bytes in [vec![], vec![0xff; 17], vec![1, 0, 0, 0, 0, 0, 0, 0]] {
                match check_dependency_response(code, &bytes).unwrap_err() {
                    SourceError::Io { stage, source } => {
                        assert_eq!(stage, "source backing dependencies");
                        assert_eq!(source.raw_os_error(), Some(code as i32));
                    }
                    other => panic!("unexpected dependency error: {other}"),
                }
            }
        }
    }

    #[test]
    fn mapping_revalidation_rejects_each_changed_source_sentinel_and_volume() {
        let before = Mapping {
            file: FileIdentity {
                volume_serial: 10,
                file_index: 12,
                length: 4096,
                last_write: 14,
                created: 16,
            },
            guid: r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\".to_owned(),
            extents: parse_extents(&extent_bytes(&[(3, 4096, 8192)])).unwrap(),
        };
        unchanged(&before, &before.clone()).unwrap();
        for change in 0..9 {
            let mut after = before.clone();
            match change {
                0 => after.file.volume_serial += 1,
                1 => after.file.file_index += 1,
                2 => after.file.length += 1,
                3 => after.file.last_write += 1,
                4 => after.file.created += 1,
                5 => after.guid.replace_range(11..12, "9"),
                6 => after.extents[0].disk_number += 1,
                7 => after.extents[0].start_offset += 512,
                8 => after.extents[0].length_bytes += 512,
                _ => unreachable!(),
            }
            assert!(matches!(
                unchanged(&before, &after),
                Err(SourceError::Changed)
            ));
        }
    }
}
