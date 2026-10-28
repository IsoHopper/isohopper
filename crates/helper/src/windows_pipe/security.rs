// SPDX-License-Identifier: GPL-3.0-or-later
use super::PipeError;
use crate::windows_peer::Sid;

pub(super) const CLIENT_RIGHTS: u32 = 0x0012_0083;
pub(super) const MAX_DESCRIPTOR_BYTES: usize = 65_536;

pub(super) fn descriptor(owner: &Sid, logon: &Sid) -> Vec<u8> {
    let dacl_offset = 20 + owner.as_bytes().len();
    let ace_size = 8 + logon.as_bytes().len();
    let mut bytes = vec![1, 0, 4, 144]; // relative, protected, present DACL
    bytes.extend(20u32.to_le_bytes());
    bytes.extend([0; 8]); // no group or SACL
    bytes.extend((dacl_offset as u32).to_le_bytes());
    bytes.extend(owner.as_bytes());
    bytes.extend([2, 0]); // ACL_REVISION
    bytes.extend(((8 + ace_size) as u16).to_le_bytes());
    bytes.extend([1, 0, 0, 0]); // one ACE, reserved zero
    bytes.extend([0, 0]); // ACCESS_ALLOWED_ACE_TYPE, no inheritance
    bytes.extend((ace_size as u16).to_le_bytes());
    bytes.extend(CLIENT_RIGHTS.to_le_bytes());
    bytes.extend(logon.as_bytes());
    bytes
}

fn bad(reason: &'static str) -> PipeError {
    PipeError::Security(reason)
}
fn u16_at(bytes: &[u8], at: usize) -> Result<u16, PipeError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(at..at + 2)
            .ok_or_else(|| bad("truncated word"))?
            .try_into()
            .unwrap(),
    ))
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, PipeError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(at..at + 4)
            .ok_or_else(|| bad("truncated DWORD"))?
            .try_into()
            .unwrap(),
    ))
}
fn component_offset(bytes: &[u8], at: usize) -> Result<usize, PipeError> {
    let offset = u32_at(bytes, at)? as usize;
    if offset < 20 || !offset.is_multiple_of(4) || offset >= bytes.len() {
        return Err(bad("component offset"));
    }
    Ok(offset)
}
fn sid_end(bytes: &[u8], start: usize) -> Result<usize, PipeError> {
    let header = bytes
        .get(start..start + 8)
        .ok_or_else(|| bad("SID header"))?;
    let end = start + 8 + usize::from(header[1]) * 4;
    Sid::from_bytes(bytes.get(start..end).ok_or_else(|| bad("SID length"))?)
        .map_err(|_| bad("invalid SID"))?;
    Ok(end)
}

/// Compare grants and principals, not component placement. Owner implicit
/// WRITE_DAC rights are not removed by this DACL; this is not isolation from
/// every other same-user process.
pub(super) fn validate(bytes: &[u8], owner: &Sid, logon: &Sid) -> Result<(), PipeError> {
    if !(20..=MAX_DESCRIPTOR_BYTES).contains(&bytes.len()) || bytes[0] != 1 || bytes[1] != 0 {
        return Err(bad("descriptor header"));
    }
    let control = u16_at(bytes, 2)?;
    if control & 0x9004 != 0x9004 || control & !0x9007 != 0 || u32_at(bytes, 12)? != 0 {
        return Err(bad("descriptor control or SACL"));
    }
    let owner_start = component_offset(bytes, 4)?;
    let owner_end = sid_end(bytes, owner_start)?;
    if &bytes[owner_start..owner_end] != owner.as_bytes() {
        return Err(bad("owner SID"));
    }
    let dacl_start = component_offset(bytes, 16)?;
    let acl = bytes
        .get(dacl_start..dacl_start + 8)
        .ok_or_else(|| bad("ACL header"))?;
    let dacl_end = dacl_start + usize::from(u16_at(acl, 2)?);
    let dacl = bytes
        .get(dacl_start..dacl_end)
        .ok_or_else(|| bad("ACL size"))?;
    if acl[0] != 2 || acl[1] != 0 || u16_at(acl, 4)? != 1 || u16_at(acl, 6)? != 0 || dacl.len() < 16
    {
        return Err(bad("ACL revision or ACE count"));
    }
    let ace = &dacl[8..];
    if ace[0] != 0
        || ace[1] != 0
        || usize::from(u16_at(ace, 2)?) != ace.len()
        || u32_at(ace, 4)? != CLIENT_RIGHTS
    {
        return Err(bad("ACE type, flags, size or grant"));
    }
    Sid::from_bytes(&ace[8..]).map_err(|_| bad("ACE SID"))?;
    if &ace[8..] != logon.as_bytes() {
        return Err(bad("logon SID"));
    }
    let mut ranges = vec![(owner_start, owner_end), (dacl_start, dacl_end)];
    if u32_at(bytes, 8)? != 0 {
        let start = component_offset(bytes, 8)?;
        ranges.push((start, sid_end(bytes, start)?));
    }
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(bad("overlapping components"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn identities() -> (Sid, Sid) {
        (
            Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]).unwrap(),
            Sid::from_bytes(&[1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 42, 0, 0, 0, 43, 0, 0, 0])
                .unwrap(),
        )
    }
    fn sample() -> (Vec<u8>, Sid, Sid) {
        let (owner, logon) = identities();
        let mut bytes = vec![
            1, 0, 4, 144, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0,
        ];
        bytes.extend(owner.as_bytes());
        bytes.extend([2, 0, 36, 0, 1, 0, 0, 0, 0, 0, 28, 0, 131, 0, 18, 0]);
        bytes.extend(logon.as_bytes());
        (bytes, owner, logon)
    }
    #[test]
    fn builds_only_the_exact_logon_grant_without_create_instance() {
        let (bytes, owner, logon) = sample();
        assert_eq!(CLIENT_RIGHTS & 4, 0);
        assert_eq!(descriptor(&owner, &logon), bytes);
        validate(&bytes, &owner, &logon).unwrap();
    }
    #[test]
    fn compares_security_semantics_not_component_order() {
        let (bytes, owner, logon) = sample();
        let mut reordered = bytes[..20].to_vec();
        reordered[4..8].copy_from_slice(&56u32.to_le_bytes());
        reordered[16..20].copy_from_slice(&20u32.to_le_bytes());
        reordered.extend(&bytes[32..]);
        reordered.extend(&bytes[20..32]);
        validate(&reordered, &owner, &logon).unwrap();
    }
    #[test]
    fn rejects_truncation_oversize_offsets_and_component_overlap() {
        let (bytes, owner, logon) = sample();
        for end in 0..bytes.len() {
            assert!(validate(&bytes[..end], &owner, &logon).is_err());
        }
        assert!(validate(&vec![0; MAX_DESCRIPTOR_BYTES + 1], &owner, &logon).is_err());
        for (offset, value) in [
            (4, 0),
            (4, 16),
            (4, u32::MAX),
            (16, 0),
            (16, 20),
            (16, 33),
            (12, 20),
        ] {
            let mut bad = bytes.clone();
            bad[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            assert!(
                validate(&bad, &owner, &logon).is_err(),
                "offset {offset} value {value}"
            );
        }
    }
    #[test]
    fn rejects_extra_or_inherited_grants_wrong_principals_and_null_dacls() {
        let (bytes, owner, logon) = sample();
        for (offset, value) in [
            (0, 2),
            (2, 0),
            (3, 128),
            (32, 4),
            (36, 2),
            (40, 1),
            (41, 1),
            (41, 8),
            (41, 16),
            (42, 24),
            (44, 135),
            (45, 1),
            (52, 6),
            (60, 41),
        ] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(validate(&bad, &owner, &logon).is_err(), "offset {offset}");
        }
        assert!(validate(&bytes, &logon, &logon).is_err());
        assert!(validate(&bytes, &owner, &owner).is_err());
    }
}
