// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;

pub(super) const MAX_PATH_UNITS: usize = 32_768;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirectoryIdentity {
    pub volume_serial: u32,
    pub file_index: u64,
    pub created: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DirectoryMapping {
    pub os_path: String,
    pub identity: DirectoryIdentity,
    pub guid: String,
    pub extents: Vec<SourceExtent>,
}

pub(super) fn system_path(units: &[u16]) -> Result<String, ProtectedError> {
    let invalid = || ProtectedError::MissingEvidence("invalid Windows directory path");
    if units.is_empty() || units.len() >= MAX_PATH_UNITS || units.contains(&0) {
        return Err(invalid());
    }
    let path = String::from_utf16(units).map_err(|_| invalid())?;
    let bytes = path.as_bytes();
    if bytes.len() < 3
        || !bytes[0].is_ascii_alphabetic()
        || &bytes[1..3] != b":\\"
        || path.chars().any(char::is_control)
        || path[3..].contains(['/', ':', '<', '>', '|', '?', '*', '"'])
        || (!path[3..].is_empty()
            && path[3..].split('\\').any(|part| {
                part.is_empty() || matches!(part, "." | "..") || part.ends_with(['.', ' '])
            }))
    {
        return Err(invalid());
    }
    Ok(path)
}

pub(super) fn exclude_target(extents: &[SourceExtent], number: u32) -> Result<(), ProtectedError> {
    if extents.is_empty() {
        return Err(ProtectedError::MissingEvidence(
            "protected volume has no extents",
        ));
    }
    if extents.iter().any(|extent| extent.disk_number == number) {
        return Err(SourceError::OnTarget {
            extents: extents.to_vec(),
        }
        .into());
    }
    Ok(())
}

pub(super) fn unchanged(
    before: &DirectoryMapping,
    after: &DirectoryMapping,
) -> Result<(), ProtectedError> {
    if before != after {
        return Err(ProtectedError::Changed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_directory_path_requires_bounded_local_absolute_path() {
        for path in [r"C:\Windows", r"D:\System Root", "E:\\Système", r"C:\"] {
            assert_eq!(
                system_path(&path.encode_utf16().collect::<Vec<_>>()).unwrap(),
                path
            );
        }
        for path in [
            "",
            r"C:Windows",
            r"\Windows",
            r"\\server\Windows",
            r"\\?\C:\Windows",
            r"\Device\HarddiskVolume1\Windows",
            r"C:\Windows\..",
            r"C:\Windows\.",
            r"C:\Windows\",
            r"C:\Windows\\Folder",
            r"C:\Windows:stream",
            "C:\\Windows\0hidden",
            "C:\\Windows\n",
        ] {
            assert!(
                system_path(&path.encode_utf16().collect::<Vec<_>>()).is_err(),
                "{path:?}"
            );
        }
        assert!(system_path(&[0xd800]).is_err());
        assert!(system_path(&vec![b'A' as u16; MAX_PATH_UNITS]).is_err());
    }

    fn mapping() -> DirectoryMapping {
        DirectoryMapping {
            os_path: r"C:\Windows".into(),
            identity: DirectoryIdentity {
                volume_serial: 7,
                file_index: 19,
                created: 23,
            },
            guid: r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\".into(),
            extents: vec![SourceExtent {
                disk_number: 2,
                start_offset: 1_048_576,
                length_bytes: 16_777_216,
            }],
        }
    }

    #[test]
    fn target_in_any_protected_extent_is_rejected_and_empty_is_unknown() {
        let mut extents = mapping().extents;
        assert!(exclude_target(&extents, 9).is_ok());
        extents.push(SourceExtent {
            disk_number: 9,
            start_offset: 4096,
            length_bytes: 4096,
        });
        assert!(matches!(
            exclude_target(&extents, 9),
            Err(ProtectedError::Source(SourceError::OnTarget { .. }))
        ));
        assert!(matches!(
            exclude_target(&[], 9),
            Err(ProtectedError::MissingEvidence(_))
        ));
    }

    #[test]
    fn revalidation_rejects_changed_directory_identity_or_storage() {
        let before = mapping();
        assert!(unchanged(&before, &before).is_ok());
        for field in 0..8 {
            let mut after = before.clone();
            match field {
                0 => after.os_path = r"D:\Windows".into(),
                1 => after.identity.volume_serial += 1,
                2 => after.identity.file_index += 1,
                3 => after.identity.created += 1,
                4 => after.guid = "another-volume".into(),
                5 => after.extents[0].disk_number += 1,
                6 => after.extents[0].start_offset += 512,
                _ => after.extents[0].length_bytes += 512,
            }
            assert!(
                matches!(unchanged(&before, &after), Err(ProtectedError::Changed)),
                "field {field}"
            );
        }
    }
}
