// SPDX-License-Identifier: GPL-3.0-or-later
use super::{PeerError, PeerEvidence, TokenEvidence, decode};
use std::{
    io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, FILETIME, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
    Security::{
        GetTokenInformation, SID_AND_ATTRIBUTES, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER, TokenElevation,
        TokenElevationType, TokenIntegrityLevel, TokenIsAppContainer, TokenLogonSid,
        TokenSessionId, TokenStatistics, TokenUser,
    },
    System::Threading::{GetProcessId, GetProcessTimes, OpenProcessToken, WaitForSingleObject},
};

const _: () = {
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
}

impl ProcessPeer {
    /// Observe a live process using a caller-owned handle with
    /// PROCESS_QUERY_LIMITED_INFORMATION and SYNCHRONIZE rights. Additional
    /// rights, if present, are unused. All queries complete synchronously.
    ///
    /// Supplying a handle says nothing about how the caller obtained or
    /// authenticated it. In particular, this does not bind a named-pipe peer.
    pub fn from_owned_handle(process: OwnedHandle) -> Result<Self, PeerError> {
        let evidence = observe(&process)?;
        Ok(Self { process, evidence })
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
        decode::unchanged(&self.evidence, &observe(&self.process)?)?;
        Ok(&self.evidence)
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
    let mut needed = 0;
    // SAFETY: null output with zero length is the documented sizing request.
    let sized = unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            ptr::null_mut(),
            0,
            &mut needed,
        )
    };
    let error = io::Error::last_os_error();
    if sized != 0 || error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(if sized == 0 {
            PeerError::Io {
                stage,
                source: error,
            }
        } else {
            PeerError::Invalid("unexpected token sizing success")
        });
    }
    let length = needed as usize;
    if length == 0 || length > decode::MAX_TOKEN_BYTES {
        return Err(PeerError::Invalid("token buffer size limit"));
    }
    let mut storage = vec![0u64; length.div_ceil(size_of::<u64>())];
    let mut returned = 0;
    // SAFETY: bounded initialized aligned storage has at least needed bytes.
    // This synchronous query finishes before the storage can move or be freed.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            class,
            storage.as_mut_ptr().cast(),
            needed,
            &mut returned,
        )
    } == 0
    {
        return Err(os_error(stage));
    }
    if returned == 0 || returned > needed {
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
