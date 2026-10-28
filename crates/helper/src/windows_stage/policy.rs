// SPDX-License-Identifier: GPL-3.0-or-later
use super::StageError;
use crate::writer::Geometry;
use std::collections::BTreeSet;

pub(super) fn validate_geometry(value: &Geometry) -> Result<(), StageError> {
    value.validate().map_err(|_| StageError::Geometry)?;
    if value.size_bytes < 3 * 1024 * 1024
        || value.logical_sector_size != 512
        || ![512, 4096].contains(&value.physical_sector_size)
    {
        return Err(StageError::Geometry);
    }
    Ok(())
}

pub(super) fn privilege_enabled(bytes: &[u8], wanted: u64) -> Result<bool, StageError> {
    let invalid = || StageError::Invalid("token privilege response");
    if bytes.len() < 4 {
        return Err(invalid());
    }
    let count = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if count > 128 || bytes.len() != 4 + 12 * count {
        return Err(invalid());
    }
    let mut found = false;
    let mut seen = BTreeSet::new();
    for entry in bytes[4..].as_chunks::<12>().0 {
        let luid = u64::from_le_bytes(entry[..8].try_into().unwrap());
        let flags = u32::from_le_bytes(entry[8..].try_into().unwrap());
        if !seen.insert(luid) || flags & !0x8000_0003 != 0 {
            return Err(invalid());
        }
        if luid == wanted {
            found = flags & 2 != 0;
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::Geometry;

    #[test]
    fn staging_geometry_rejects_unsupported_before_creation() {
        let valid = Geometry {
            size_bytes: 256 * 1024 * 1024,
            logical_sector_size: 512,
            physical_sector_size: 4096,
        };
        validate_geometry(&valid).unwrap();
        for changed in [
            Geometry {
                size_bytes: 0,
                ..valid.clone()
            },
            Geometry {
                size_bytes: 2 * 1024 * 1024,
                ..valid.clone()
            },
            Geometry {
                size_bytes: valid.size_bytes + 1,
                ..valid.clone()
            },
            Geometry {
                logical_sector_size: 4096,
                ..valid.clone()
            },
            Geometry {
                physical_sector_size: 8192,
                ..valid.clone()
            },
        ] {
            assert!(validate_geometry(&changed).is_err());
        }
    }

    fn privileges(entries: &[(u64, u32)]) -> Vec<u8> {
        let mut bytes = (entries.len() as u32).to_le_bytes().to_vec();
        for (id, attributes) in entries {
            bytes.extend_from_slice(&id.to_le_bytes());
            bytes.extend_from_slice(&attributes.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn token_privilege_requires_exact_present_enabled_entry() {
        assert!(privilege_enabled(&privileges(&[(7, 2)]), 7).unwrap());
        assert!(privilege_enabled(&privileges(&[(8, 0), (7, 3)]), 7).unwrap());
        assert!(!privilege_enabled(&privileges(&[(7, 0)]), 7).unwrap());
        assert!(!privilege_enabled(&privileges(&[(7, 1)]), 7).unwrap());
        assert!(!privilege_enabled(&privileges(&[]), 7).unwrap());
        for bytes in [
            vec![],
            vec![0; 3],
            vec![0; 5],
            privileges(&[(7, 2), (7, 2)]),
            privileges(&[(7, 4)]),
            privileges(&[(7, 8)]),
            privileges(&vec![(8, 2); 129]),
        ] {
            assert!(privilege_enabled(&bytes, 7).is_err());
        }
    }
}
