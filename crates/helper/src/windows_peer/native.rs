// SPDX-License-Identifier: GPL-3.0-or-later
use super::{PeerError, PeerEvidence, TokenEvidence, decode};
use crate::windows_installation::{InstalledRole, MachineInstallation, wide_name};
use std::{
    ffi::c_void,
    io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::Arc,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, FILETIME, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::{
        GetTokenInformation, SID_AND_ATTRIBUTES, TOKEN_ELEVATION, TOKEN_ELEVATION_TYPE,
        TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
        TOKEN_STATISTICS, TOKEN_USER, TokenElevation, TokenElevationType, TokenIntegrityLevel,
        TokenIsAppContainer, TokenLogonSid, TokenSessionId, TokenStatistics, TokenUser,
    },
    System::Threading::{
        GetProcessId, GetProcessTimes, OpenProcessToken, PROCESS_NAME_NATIVE,
        QueryFullProcessImageNameW, WaitForSingleObject,
    },
};
#[path = "installed.rs"]
mod installed;
#[path = "source.rs"]
mod source;

const _: () = {
    assert!(size_of::<TOKEN_ELEVATION>() == 4);
    assert!(offset_of!(TOKEN_ELEVATION, TokenIsElevated) == 0);
    assert!(size_of::<TOKEN_ELEVATION_TYPE>() == 4);
    assert!(size_of::<u32>() == 4);
    assert!(size_of::<TOKEN_STATISTICS>() == 56);
    assert!(offset_of!(TOKEN_STATISTICS, TokenId) == 0);
    assert!(offset_of!(TOKEN_STATISTICS, AuthenticationId) == 8);
    assert!(offset_of!(TOKEN_STATISTICS, TokenType) == 24);
    assert!(offset_of!(TOKEN_STATISTICS, ModifiedId) == 48);
    assert!(size_of::<SID_AND_ATTRIBUTES>() == size_of::<usize>() * 2);
    assert!(offset_of!(SID_AND_ATTRIBUTES, Sid) == 0);
    assert!(offset_of!(SID_AND_ATTRIBUTES, Attributes) == size_of::<usize>());
    assert!(size_of::<TOKEN_USER>() == size_of::<SID_AND_ATTRIBUTES>());
    assert!(size_of::<TOKEN_MANDATORY_LABEL>() == size_of::<SID_AND_ATTRIBUTES>());
    assert!(offset_of!(TOKEN_GROUPS, Groups) == size_of::<usize>());
};

/// Owns one process handle and a fixed, last-confirmed baseline. It never opens
/// a process by PID/path, launches a process, changes a token or extracts its
/// retained handle. No method returns authorization to write or elevate.
pub struct ProcessPeer {
    process: OwnedHandle,
    evidence: PeerEvidence,
    installation: Option<(Arc<MachineInstallation>, InstalledRole)>,
}

impl ProcessPeer {
    /// Observe a live process using a caller-owned handle with
    /// PROCESS_QUERY_LIMITED_INFORMATION and SYNCHRONIZE rights. Additional
    /// rights are unused by observations; `receive_source_file` additionally
    /// requires PROCESS_DUP_HANDLE. All queries complete synchronously.
    ///
    /// Supplying a handle says nothing about how the caller obtained or
    /// authenticated it. In particular, this does not bind a named-pipe peer.
    pub fn from_owned_handle(process: OwnedHandle) -> Result<Self, PeerError> {
        let evidence = observe(&process)?;
        Ok(Self {
            process,
            evidence,
            installation: None,
        })
    }

    /// Retain the protected installation and correlate this process's native
    /// image name with its fixed role. No process-reported path is opened.
    /// Revalidation repeats the binding while this peer is owned by a pipe.
    /// This is not mapped-image file-ID proof, injection prevention, or write
    /// authority. A peer cannot replace an existing installation binding.
    pub fn bind_installation(
        mut self,
        installation: Arc<MachineInstallation>,
        role: InstalledRole,
    ) -> Result<Self, PeerError> {
        if self.installation.is_some() {
            return Err(PeerError::Invalid("peer installation already bound"));
        }
        self.installation = Some((installation, role));
        self.revalidate()?;
        Ok(self)
    }

    /// Historical evidence. Retaining a process handle does not freeze its
    /// token or guarantee that it remains alive.
    pub fn evidence(&self) -> &PeerEvidence {
        &self.evidence
    }

    /// Reopen the primary token through the same retained process handle and
    /// compare every captured field with the baseline. Errors do not replace
    /// the baseline. This is a point-in-time check, not a liveness/token lease.
    pub fn revalidate(&mut self) -> Result<&PeerEvidence, PeerError> {
        if let Some((installation, role)) = &self.installation {
            installed::check(&mut InstalledPeer {
                process: &self.process,
                evidence: &self.evidence,
                installation,
                role: *role,
            })?;
        } else {
            decode::unchanged(&self.evidence, &observe(&self.process)?)?;
        }
        Ok(&self.evidence)
    }

    /// Receive a backend-owned source handle value from this retained process.
    /// The process handle must already include PROCESS_DUP_HANDLE in addition
    /// to query/synchronize rights; this never reopens a process by PID. Only
    /// positive 32-bit handle values are supported. The caller must retain the
    /// sender's source lease through transfer and authenticate that sender and
    /// handle selection independently; this API adds no transport/role policy.
    ///
    /// Returns an independently positioned synchronous read-only regular File
    /// with share-read only. Directory, reparse, delete-pending, changed or
    /// unsupported sources fail closed. Metadata is a change sentinel, not
    /// immutable-content proof: existing mapped writes and attribute-only
    /// changes are not prevented by sharing modes. The coordinator must still
    /// hash the exact source and perform source-volume/external-backing checks.
    /// No path is opened or original remote handle exposed, and no write
    /// authority is granted.
    pub fn receive_source_file(&mut self, remote: u64) -> Result<std::fs::File, PeerError> {
        self.revalidate()?;
        let result = source::receive(&self.process, &self.evidence, remote);
        self.revalidate()?;
        result
    }
}

struct InstalledPeer<'a> {
    process: &'a OwnedHandle,
    evidence: &'a PeerEvidence,
    installation: &'a MachineInstallation,
    role: InstalledRole,
}
impl installed::Backend for InstalledPeer<'_> {
    fn peer(&mut self) -> Result<(), PeerError> {
        decode::unchanged(self.evidence, &observe(self.process)?)
    }
    fn installation(&mut self) -> Result<(), PeerError> {
        self.installation
            .revalidate()
            .map_err(PeerError::Installation)
    }
    fn installed_image(&self) -> &[u16] {
        self.installation.native_name(self.role)
    }
    fn process_image(&mut self) -> Result<Vec<u16>, PeerError> {
        let mut buffer = vec![u16::MAX; 32768];
        let mut length = buffer.len() as u32;
        // SAFETY: the retained process handle has QUERY_LIMITED_INFORMATION.
        // Bounded UTF-16 output is used only for an exact name comparison.
        // https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew
        if unsafe {
            QueryFullProcessImageNameW(
                self.process.as_raw_handle(),
                PROCESS_NAME_NATIVE,
                buffer.as_mut_ptr(),
                &mut length,
            )
        } == 0
        {
            return Err(os_error("process native image name"));
        }
        wide_name(&buffer, length as usize).map_err(PeerError::Installation)
    }
}

fn os_error(stage: &'static str) -> PeerError {
    PeerError::Io {
        stage,
        source: io::Error::last_os_error(),
    }
}

fn process_identity(process: &OwnedHandle) -> Result<(u32, u64), PeerError> {
    // SAFETY: the owner keeps the handle live. Invalid/non-process handles
    // return an error; no output pointers or asynchronous operations are used.
    let pid = unsafe { GetProcessId(process.as_raw_handle()) };
    if pid == 0 {
        return Err(os_error("process ID"));
    }
    // Only reached after GetProcessId classified this as a process handle.
    // SAFETY: a zero-time wait on this retained handle cannot outlive its owner.
    match unsafe { WaitForSingleObject(process.as_raw_handle(), 0) } {
        WAIT_TIMEOUT => {}
        WAIT_OBJECT_0 => return Err(PeerError::Exited),
        WAIT_FAILED => return Err(os_error("process liveness")),
        _ => return Err(PeerError::Invalid("process wait result")),
    }
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    // SAFETY: all four typed output structures and the retained process handle
    // are live for this synchronous call. Undefined exit time is never read.
    if unsafe {
        GetProcessTimes(
            process.as_raw_handle(),
            &mut created,
            &mut exited,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(os_error("process creation time"));
    }
    let creation_time =
        (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
    Ok((pid, creation_time))
}

fn primary_token(process: &OwnedHandle) -> Result<OwnedHandle, PeerError> {
    let mut token = ptr::null_mut();
    // SAFETY: process is retained; token is a live, typed output location.
    // TOKEN_QUERY grants no token modification or impersonation rights.
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(os_error("open primary token"));
    }
    if token.is_null() || token as isize == -1 {
        return Err(PeerError::Invalid("primary token handle"));
    }
    // SAFETY: successful OpenProcessToken returned one new owned token handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(token) })
}

struct TokenBuffer {
    // u64 storage aligns SDK pointers/LUIDs; no SDK structure is dereferenced.
    storage: Vec<u64>,
    length: usize,
}

impl TokenBuffer {
    fn bytes(&self) -> &[u8] {
        // SAFETY: length is checked against initialized storage capacity before
        // construction; the slice borrows that storage and cannot outlive it.
        unsafe { std::slice::from_raw_parts(self.storage.as_ptr().cast(), self.length) }
    }

    fn view(&self) -> decode::Buffer<'_> {
        decode::Buffer {
            bytes: self.bytes(),
            base: self.storage.as_ptr() as usize as u64,
            pointer_bytes: size_of::<usize>(),
        }
    }
}

fn query(
    token: &OwnedHandle,
    class: TOKEN_INFORMATION_CLASS,
    stage: &'static str,
) -> Result<TokenBuffer, PeerError> {
    query_with(class, stage, |buffer, length, returned| {
        // SAFETY: query_with provides either a null/zero sizing request or
        // bounded initialized aligned storage. This call is synchronous and
        // the retained token and output locations remain live until it returns.
        if unsafe { GetTokenInformation(token.as_raw_handle(), class, buffer, length, returned) }
            == 0
        {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })
}

fn query_with(
    class: TOKEN_INFORMATION_CLASS,
    stage: &'static str,
    mut call: impl FnMut(*mut c_void, u32, &mut u32) -> io::Result<()>,
) -> Result<TokenBuffer, PeerError> {
    // These classes have documented fixed DWORD/enum outputs. In particular,
    // TokenElevation can reject a null/zero probe with ERROR_BAD_LENGTH. Supply
    // the SDK-sized buffer directly; do not reinterpret any failed call.
    let fixed = [
        TokenElevation,
        TokenElevationType,
        TokenSessionId,
        TokenIsAppContainer,
    ]
    .contains(&class);
    let mut needed = if fixed { 4 } else { 0 };
    if !fixed {
        match call(ptr::null_mut(), 0, &mut needed) {
            Err(error) if error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32) => {}
            Err(source) => return Err(PeerError::Io { stage, source }),
            Ok(()) => return Err(PeerError::Invalid("unexpected token sizing success")),
        }
    }
    let length = needed as usize;
    if length == 0 || length > decode::MAX_TOKEN_BYTES {
        return Err(PeerError::Invalid("token buffer size limit"));
    }
    let mut storage = vec![0u64; length.div_ceil(size_of::<u64>())];
    let mut returned = 0;
    call(storage.as_mut_ptr().cast(), needed, &mut returned)
        .map_err(|source| PeerError::Io { stage, source })?;
    if returned == 0 || returned > needed || (fixed && returned != needed) {
        return Err(PeerError::Invalid("token returned byte count"));
    }
    Ok(TokenBuffer {
        storage,
        length: returned as usize,
    })
}

fn observe(process: &OwnedHandle) -> Result<PeerEvidence, PeerError> {
    let (process_id, creation_time) = process_identity(process)?;
    let token = primary_token(process)?;
    let before =
        decode::statistics(query(&token, TokenStatistics, "initial token statistics")?.bytes())?;
    let user = query(&token, TokenUser, "token user")?.view().user()?;
    let logon = query(&token, TokenLogonSid, "token logon SID")?
        .view()
        .logon()?;
    let session_id = decode::scalar(query(&token, TokenSessionId, "token session")?.bytes())?;
    let integrity = query(&token, TokenIntegrityLevel, "token integrity")?
        .view()
        .integrity()?;
    let elevated = decode::boolean(query(&token, TokenElevation, "token elevation")?.bytes())?;
    let elevation_type =
        decode::elevation(query(&token, TokenElevationType, "token elevation type")?.bytes())?;
    let is_app_container =
        decode::boolean(query(&token, TokenIsAppContainer, "token app container")?.bytes())?;
    let after =
        decode::statistics(query(&token, TokenStatistics, "final token statistics")?.bytes())?;
    // Comparing only the original token cannot detect replacement of the
    // process's primary token. Reopen through the retained process and compare.
    let reopened = primary_token(process)?;
    let current = decode::statistics(
        query(&reopened, TokenStatistics, "reopened token statistics")?.bytes(),
    )?;
    decode::stable_token(before, after, current)?;
    if process_identity(process)? != (process_id, creation_time) {
        return Err(PeerError::Changed);
    }
    Ok(PeerEvidence {
        process_id,
        creation_time,
        token: TokenEvidence {
            user,
            logon,
            session_id,
            integrity,
            elevated,
            elevation_type,
            is_app_container,
            token_id: before.token,
            authentication_id: before.authentication,
            modified_id: before.modified,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "read-only current/linked-token diagnostic; no UAC or token changes"]
    fn native_linked_token_relationship_is_observed_without_elevation()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::windows_peer::ElevationType;
        use windows_sys::Win32::{
            Security::{TOKEN_LINKED_TOKEN, TokenLinkedToken},
            System::Threading::{
                GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_SYNCHRONIZE,
            },
        };

        fn stamp(token: &OwnedHandle) -> Result<decode::Stamp, PeerError> {
            decode::statistics(query(token, TokenStatistics, "diagnostic stamp")?.bytes())
        }

        // Only query this process. The retained process and token handles are
        // never impersonated, assigned, elevated, or used to create a process.
        // SAFETY: these functions have no pointer inputs or asynchronous work.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                GetCurrentProcessId(),
            )
        };
        if raw.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: successful OpenProcess returned one owned process handle.
        let process = unsafe { OwnedHandle::from_raw_handle(raw) };
        let current = primary_token(&process)?;
        let current_before = stamp(&current)?;
        let current_type = decode::elevation(
            query(&current, TokenElevationType, "diagnostic elevation type")?.bytes(),
        )?;
        if current_type == ElevationType::Default {
            decode::stable_token(
                current_before,
                stamp(&current)?,
                stamp(&primary_token(&process)?)?,
            )?;
            println!("LINKED_TOKEN status=unsupported reason=no_split_token");
            return Ok(());
        }

        // This class returns an owned HANDLE, not a byte buffer. Query its
        // exact SDK structure once and close the returned handle on every
        // successful path, including a rejected returned length.
        // https://learn.microsoft.com/windows/win32/api/winnt/ns-winnt-token_linked_token
        let mut output = TOKEN_LINKED_TOKEN::default();
        let mut returned = 0;
        // SAFETY: current is live; output and returned are initialized, typed
        // locations of the exact supplied sizes. The operation is synchronous.
        if unsafe {
            GetTokenInformation(
                current.as_raw_handle(),
                TokenLinkedToken,
                (&mut output as *mut TOKEN_LINKED_TOKEN).cast(),
                size_of::<TOKEN_LINKED_TOKEN>() as u32,
                &mut returned,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            decode::stable_token(
                current_before,
                stamp(&current)?,
                stamp(&primary_token(&process)?)?,
            )?;
            println!(
                "LINKED_TOKEN status=unsupported reason=linked_query_unavailable win32={}",
                error.raw_os_error().unwrap_or(0)
            );
            return Ok(());
        }
        if output.LinkedToken.is_null() || output.LinkedToken as isize == -1 {
            return Err(PeerError::Invalid("diagnostic linked-token handle").into());
        }
        // SAFETY: successful TokenLinkedToken returns a new handle whose
        // documented cleanup is CloseHandle, performed by OwnedHandle.
        let linked = unsafe { OwnedHandle::from_raw_handle(output.LinkedToken) };
        if returned as usize != size_of::<TOKEN_LINKED_TOKEN>() {
            return Err(PeerError::Invalid("diagnostic linked-token size").into());
        }
        let linked_before = stamp(&linked)?;
        let same_user = query(&current, TokenUser, "diagnostic current user")?
            .view()
            .user()?
            == query(&linked, TokenUser, "diagnostic linked user")?
                .view()
                .user()?;
        let same_logon = query(&current, TokenLogonSid, "diagnostic current logon")?
            .view()
            .logon()?
            == query(&linked, TokenLogonSid, "diagnostic linked logon")?
                .view()
                .logon()?;
        let same_session =
            decode::scalar(query(&current, TokenSessionId, "diagnostic current session")?.bytes())?
                == decode::scalar(
                    query(&linked, TokenSessionId, "diagnostic linked session")?.bytes(),
                )?;
        let linked_type = decode::elevation(
            query(
                &linked,
                TokenElevationType,
                "diagnostic linked elevation type",
            )?
            .bytes(),
        )?;
        decode::stable_token(
            current_before,
            stamp(&current)?,
            stamp(&primary_token(&process)?)?,
        )?;
        if linked_before != stamp(&linked)? {
            return Err(PeerError::Changed.into());
        }

        // Observations only: differing logon/authentication IDs are printed,
        // not accepted by the broker or translated into role/ACL exceptions.
        println!(
            "LINKED_TOKEN status=observed same_user={same_user} same_logon={same_logon} same_session={same_session} same_authentication={} current_full={} current_limited={} linked_full={} linked_limited={}",
            current_before.authentication == linked_before.authentication,
            current_type == ElevationType::Full,
            current_type == ElevationType::Limited,
            linked_type == ElevationType::Full,
            linked_type == ElevationType::Limited,
        );
        Ok(())
    }

    #[test]
    fn fixed_token_outputs_use_one_sdk_sized_call_without_a_probe() {
        for class in [
            TokenElevation,
            TokenElevationType,
            TokenSessionId,
            TokenIsAppContainer,
        ] {
            let mut calls = 0;
            let result = query_with(class, "fixed test", |buffer, length, returned| {
                calls += 1;
                assert!(!buffer.is_null());
                assert_eq!(length, 4);
                assert_eq!(buffer as usize % align_of::<u32>(), 0);
                // SAFETY: query_with supplies four initialized aligned bytes.
                unsafe { buffer.cast::<u32>().write(0x1234_5678) };
                *returned = 4;
                Ok(())
            })
            .unwrap();
            assert_eq!(calls, 1);
            assert_eq!(result.bytes(), 0x1234_5678u32.to_ne_bytes());
        }
    }

    #[test]
    fn fixed_token_outputs_reject_partial_or_excess_returned_lengths() {
        for returned_length in [0, 1, 2, 3, 5, u32::MAX] {
            assert!(matches!(
                query_with(TokenElevation, "fixed test", |_, _, returned| {
                    *returned = returned_length;
                    Ok(())
                }),
                Err(PeerError::Invalid("token returned byte count"))
            ));
        }
    }

    #[test]
    fn failed_fixed_and_variable_queries_never_infer_a_value() {
        for class in [TokenElevation, TokenUser] {
            for code in [5, 24, 50, 122] {
                let mut calls = 0;
                let result = query_with(class, "failure test", |_, _, returned| {
                    calls += 1;
                    // Even plausible output metadata cannot turn failure
                    // into valid evidence. A variable 122 only permits retry.
                    *returned = 4;
                    Err(io::Error::from_raw_os_error(code))
                });
                assert!(
                    matches!(result, Err(PeerError::Io { stage: "failure test", source })
                    if source.raw_os_error() == Some(code))
                );
                assert_eq!(
                    calls,
                    if class == TokenUser && code == 122 {
                        2
                    } else {
                        1
                    }
                );
            }
        }
    }

    #[test]
    fn variable_outputs_keep_the_bounded_insufficient_buffer_probe() {
        let mut calls = 0;
        let result = query_with(TokenUser, "variable test", |buffer, length, returned| {
            calls += 1;
            *returned = 16;
            if calls == 1 {
                assert!(buffer.is_null());
                assert_eq!(length, 0);
                Err(io::Error::from_raw_os_error(
                    ERROR_INSUFFICIENT_BUFFER as i32,
                ))
            } else {
                assert!(!buffer.is_null());
                assert_eq!(length, 16);
                Ok(())
            }
        })
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(result.bytes(), [0; 16]);

        assert!(matches!(
            query_with(TokenUser, "variable test", |_, _, _| Ok(())),
            Err(PeerError::Invalid("unexpected token sizing success"))
        ));
    }
}
