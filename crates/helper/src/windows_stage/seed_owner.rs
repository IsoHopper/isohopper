// SPDX-License-Identifier: GPL-3.0-or-later
//! Only the fresh seed created inside this job. No existing-path adoption.
use super::*;
use std::os::windows::fs::MetadataExt;
use windows_sys::Win32::{
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT, SetSecurityInfo},
        DACL_SECURITY_INFORMATION, GetLengthSid, IsValidAcl, IsValidSid,
        OWNER_SECURITY_INFORMATION, PSID, TOKEN_OWNER, TokenOwner,
    },
    Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT,
};

// SAFETY: callers pass live SID pointers returned by Windows security APIs.
// IsValidSid/GetLengthSid are used only with those owned API outputs.
unsafe fn sid_bytes(sid: PSID) -> Result<Vec<u8>, StageError> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err(StageError::Invalid("invalid seed owner SID"));
    }
    let length = unsafe { GetLengthSid(sid) } as usize;
    if !(8..=68).contains(&length) {
        return Err(StageError::Invalid("seed owner SID length"));
    }
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
}
fn default_owner() -> Result<Vec<u8>, StageError> {
    let mut raw = ptr::null_mut();
    // SAFETY: query-only current primary token; no token mutation.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(error("seed token owner", io::Error::last_os_error()));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut words = [0usize; 32];
    let mut returned = 0;
    // SAFETY: bounded pointer-aligned output for TOKEN_OWNER plus its SID.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenOwner,
            words.as_mut_ptr().cast(),
            size_of_val(&words) as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(error("read seed token owner", io::Error::last_os_error()));
    }
    if (returned as usize) < size_of::<TOKEN_OWNER>() || returned as usize > size_of_val(&words) {
        return Err(StageError::Invalid("seed token owner length"));
    }
    let owner = unsafe { (*words.as_ptr().cast::<TOKEN_OWNER>()).Owner };
    let offset = (owner as usize)
        .checked_sub(words.as_ptr() as usize)
        .ok_or(StageError::Invalid("seed token owner bounds"))?;
    if offset.checked_add(8).is_none_or(|n| n > returned as usize) {
        return Err(StageError::Invalid("seed token owner header bounds"));
    }
    let count = unsafe { *owner.cast::<u8>().add(1) } as usize;
    if offset
        .checked_add(8 + count * 4)
        .is_none_or(|n| n > returned as usize)
    {
        return Err(StageError::Invalid("seed token owner SID bounds"));
    }
    unsafe { sid_bytes(owner) }
}
fn security(file: &File) -> Result<(Vec<u8>, Vec<u8>), StageError> {
    let (mut owner, mut acl, mut sd) = (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    // SAFETY: retained file with READ_CONTROL. Windows owns all pointers in the
    // returned LocalAlloc descriptor until our guard releases it.
    status("seed file security", unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut sd,
        )
    })?;
    let _guard = Descriptor(sd);
    if sd.is_null() || acl.is_null() || unsafe { IsValidAcl(acl) } == 0 {
        return Err(StageError::Invalid("missing seed DACL"));
    }
    let size = unsafe { (*acl).AclSize } as usize;
    if !(8..=4096).contains(&size) {
        return Err(StageError::Invalid("seed DACL bound"));
    }
    let acl = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), size) }.to_vec();
    build_policy::validate_seed_acl(&acl)?;
    Ok((unsafe { sid_bytes(owner) }?, acl))
}

/// Fix only token-default ownership; the inherited private DACL is never set
/// or tightened later. SetSecurityInfo is handle based and changes owner only.
/// https://learn.microsoft.com/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo
pub(super) fn fix(file: &File) -> Result<(), StageError> {
    let metadata = file.metadata().map_err(|e| error("seed kind", e))?;
    if !metadata.is_file() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(StageError::Invalid("seed is not a regular file"));
    }
    let before = file_stamp(file)?;
    let (owner, acl) = security(file)?;
    if owner != default_owner()? {
        return Err(StageError::Invalid(
            "seed owner differs from creating token",
        ));
    }
    // Windows SID storage is DWORD aligned; Vec<u8> would not guarantee that.
    let mut admin = [0u32; 4];
    for (word, bytes) in admin
        .iter_mut()
        .zip(build_policy::ADMIN_SID.as_chunks::<4>().0)
    {
        *word = u32::from_le_bytes(*bytes);
    }
    // SAFETY: the retained new-file handle has WRITE_OWNER; this DWORD-aligned
    // fixed SID stays live. OWNER only leaves DACL/SACL/group untouched.
    status("set fresh seed owner", unsafe {
        SetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            admin.as_mut_ptr().cast(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
        )
    })?;
    let (owner, current_acl) = security(file)?;
    if owner != build_policy::ADMIN_SID || current_acl != acl || file_stamp(file)? != before {
        return Err(StageError::Invalid(
            "seed ownership handoff changed identity or DACL",
        ));
    }
    check_stage_object(file, false).map_err(StageError::Installation)
}
