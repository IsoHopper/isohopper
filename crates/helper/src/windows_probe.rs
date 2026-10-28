// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
//! Native read-only probe entry. No disk, source-transfer or Session operations.
use crate::{
    broker_probe::{ProbeArgs, ProbeReply, ProbeRequest, check_pair},
    windows_installation::{InstalledRole, MachineInstallation},
    windows_peer::{PeerError, ProcessPeer},
    windows_pipe::{Endpoint, connect},
};
use std::{
    io,
    os::windows::io::{FromRawHandle, OwnedHandle},
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

fn observe_process(pid: u32) -> Result<ProcessPeer, PeerError> {
    // SAFETY: read-only process query; the returned owned handle prevents PID
    // reuse from changing the observed object after this call.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            pid,
        )
    };
    if handle.is_null() {
        return Err(PeerError::Io {
            stage: "open probe process",
            source: io::Error::last_os_error(),
        });
    }
    // SAFETY: successful OpenProcess returned one owned, noninheritable handle.
    ProcessPeer::from_owned_handle(unsafe { OwnedHandle::from_raw_handle(handle) })
}

/// Observe only this process. The observation grants no role or operation.
pub fn current_peer() -> Result<ProcessPeer, PeerError> {
    // SAFETY: GetCurrentProcessId takes no pointers and cannot outlive a borrow.
    observe_process(unsafe { GetCurrentProcessId() })
}

/// Handle exactly one diagnostic request, then wait for the caller to close.
/// A normally launched, non-elevated helper cannot pass the role policy.
pub fn serve(args: ProbeArgs) -> Result<(), String> {
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut local = current_peer().map_err(|e| e.to_string())?;
    let remote = observe_process(args.studio_pid()).map_err(|e| e.to_string())?;
    if remote.evidence().creation_time != args.studio_created() {
        return Err("probe caller creation time mismatch".into());
    }
    check_pair(remote.evidence(), local.evidence()).map_err(|e| e.to_string())?;
    let installation = Arc::new(MachineInstallation::open()?);
    local = local
        .bind_installation(Arc::clone(&installation), InstalledRole::Helper)
        .map_err(|e| e.to_string())?;
    let remote = remote
        .bind_installation(installation, InstalledRole::Studio)
        .map_err(|e| e.to_string())?;
    let endpoint = Endpoint::from_nonce(args.nonce()).map_err(|e| e.to_string())?;
    let mut connection =
        connect(&endpoint, remote, deadline, &cancel).map_err(|e| e.to_string())?;
    local.revalidate().map_err(|e| e.to_string())?;
    let bytes = connection
        .read_frame(deadline, &cancel)
        .map_err(|e| e.to_string())?
        .ok_or("probe caller closed before request")?;
    let request = ProbeRequest::decode(&bytes).map_err(|e| e.to_string())?;
    let reply = ProbeReply::for_request(&request)
        .encode()
        .map_err(|e| e.to_string())?;
    local.revalidate().map_err(|e| e.to_string())?;
    connection
        .write_frame(&reply, deadline, &cancel)
        .map_err(|e| e.to_string())?;
    // Stay alive until the parent's post-read peer validation completes. EOF
    // ends the one-shot exchange; another frame is always a protocol error.
    if connection
        .read_frame(deadline, &cancel)
        .map_err(|e| e.to_string())?
        .is_some()
    {
        return Err("additional helper probe request refused".into());
    }
    local.revalidate().map_err(|e| e.to_string())?;
    Ok(())
}
