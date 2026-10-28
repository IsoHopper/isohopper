// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
use super::{ProbeOutcome, check_digest, installation};
use isohopper_helper::{
    broker_probe::{ProbeArgs, ProbeSession, check_pair, check_studio},
    prepare_protocol::PrepareArgs,
    windows_installation::InstalledRole,
    windows_peer::ProcessPeer,
    windows_pipe::{Connection, PipeError, Server},
    windows_probe::current_peer,
};
use std::{
    io,
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::Path,
    ptr,
    sync::{Arc, atomic::AtomicBool},
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        DuplicateHandle, ERROR_CANCELLED, HANDLE, HWND, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    },
    System::{
        Com::{COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE, CoInitializeEx, CoUninitialize},
        Threading::{
            GetCurrentProcess, GetCurrentProcessId, GetExitCodeProcess,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, WaitForSingleObject,
        },
    },
    UI::{
        Shell::{
            SEE_MASK_FLAG_NO_UI, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW,
            ShellExecuteExW,
        },
        WindowsAndMessaging::{GetWindowThreadProcessId, SW_HIDE},
    },
};

fn wide(value: &std::ffi::OsStr) -> Result<Vec<u16>, String> {
    let mut units: Vec<_> = value.encode_wide().collect();
    if units.contains(&0) {
        return Err("Unexpected NUL in helper launch data".into());
    }
    units.push(0);
    Ok(units)
}
fn last(stage: &str) -> String {
    format!("{stage}: {}", io::Error::last_os_error())
}

struct Apartment;
impl Apartment {
    fn enter() -> Result<Self, String> {
        // SAFETY: caller creates a fresh dedicated thread; no COM object or
        // apartment is transferred to it. Both successful results need uninit.
        let result = unsafe {
            CoInitializeEx(
                ptr::null(),
                (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32,
            )
        };
        if result < 0 {
            return Err(format!(
                "Initialize helper launch STA: HRESULT {result:#010x}"
            ));
        }
        Ok(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() }
    }
}

fn restricted_duplicate(handle: HANDLE) -> Result<OwnedHandle, String> {
    let mut copy = ptr::null_mut();
    // SAFETY: source handle remains owned by this process throughout this
    // call; output is a new noninheritable handle to the same process object.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut copy,
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            0,
        )
    } == 0
    {
        return Err(last("Retain launched helper"));
    }
    if copy.is_null() || copy == INVALID_HANDLE_VALUE {
        return Err("Invalid duplicated helper process".into());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(copy) })
}

fn launch_result(
    info: &mut SHELLEXECUTEINFOW,
    execute: impl FnOnce(&mut SHELLEXECUTEINFOW) -> io::Result<()>,
) -> Result<Option<OwnedHandle>, String> {
    if let Err(error) = execute(info) {
        if error.raw_os_error() == Some(ERROR_CANCELLED as i32) {
            return Ok(None);
        }
        return Err(format!("Launch elevated helper: {error}"));
    }
    if info.hProcess.is_null() || info.hProcess == INVALID_HANDLE_VALUE {
        return Err("Windows returned no helper process handle".into());
    }
    // SAFETY: successful native launch transfers its new process handle. The
    // only injected implementation is in tests and also transfers a real one.
    Ok(Some(unsafe { OwnedHandle::from_raw_handle(info.hProcess) }))
}

/// Call only from a fresh dedicated thread. The native owner window is kept
/// alive by the command's close/exit guard until this function returns.
fn launch(
    owner: usize,
    directory: &Path,
    expected_digest: &str,
    prepare: bool,
) -> Result<Option<Launched>, String> {
    let _apartment = Apartment::enter()?;
    let mut local = current_peer().map_err(|e| e.to_string())?;
    check_studio(local.evidence()).map_err(|e| e.to_string())?;
    let owner = owner as HWND;
    let mut window_pid = 0;
    // SAFETY: querying a window handle does not dereference it. Stale/foreign
    // handles are rejected, and the app defers normal destruction during probe.
    if owner.is_null()
        || unsafe { GetWindowThreadProcessId(owner, &mut window_pid) } == 0
        || window_pid != unsafe { GetCurrentProcessId() }
    {
        return Err("Studio owner window is unavailable".into());
    }
    let installation = installation::open(directory)?;
    local = local
        .bind_installation(Arc::clone(&installation), InstalledRole::Studio)
        .map_err(|e| e.to_string())?;
    let mut helper_image = installation.image(InstalledRole::Helper);
    let digest = check_digest(&mut helper_image, expected_digest)?;
    let server = Server::create().map_err(|e| e.to_string())?;
    let arguments = if prepare {
        PrepareArgs::new(
            server.endpoint().nonce(),
            local.evidence().process_id,
            local.evidence().creation_time,
        )
        .map_err(|e| e.to_string())?
        .launch_arguments()
    } else {
        ProbeArgs::new(
            server.endpoint().nonce(),
            local.evidence().process_id,
            local.evidence().creation_time,
        )
        .map_err(|e| e.to_string())?
        .launch_arguments()
    };
    let verb = wide(std::ffi::OsStr::new("runas"))?;
    let file = wide(installation.path(InstalledRole::Helper).as_os_str())?;
    let parameters = wide(std::ffi::OsStr::new(&arguments))?;
    let working_directory = wide(installation.directory().as_os_str())?;
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI,
        hwnd: owner,
        lpVerb: verb.as_ptr(),
        lpFile: file.as_ptr(),
        lpParameters: parameters.as_ptr(),
        lpDirectory: working_directory.as_ptr(),
        nShow: SW_HIDE,
        ..Default::default()
    };
    local.revalidate().map_err(|e| e.to_string())?;
    installation.revalidate()?;
    // SAFETY: synchronous launch on initialized STA; all UTF-16 buffers and
    // owner-window guard remain live. NOASYNC avoids a missing message pump.
    let Some(original) = launch_result(&mut info, |info| {
        if unsafe { ShellExecuteExW(info) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    })?
    else {
        return Ok(None);
    };
    let launched = (|| -> Result<Launched, String> {
        let handle = restricted_duplicate(original.as_raw_handle())?;
        let exit_handle = restricted_duplicate(original.as_raw_handle())?;
        let cancel = AtomicBool::new(false);
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut evidence = None;
        // The preparation helper enables its volume privilege before connecting.
        // Capture its token only after that rendezvous; the retained ShellExecute
        // process handle still selects the exact child, without reopening a PID.
        let connection = server
            .accept_with_peer(
                || {
                    let remote = ProcessPeer::from_owned_handle(handle)?
                        .bind_installation(Arc::clone(&installation), InstalledRole::Helper)?;
                    local.revalidate()?;
                    check_pair(local.evidence(), remote.evidence()).map_err(|error| {
                        PipeError::Io {
                            stage: "capture prepared helper",
                            source: io::Error::other(error.to_string()),
                        }
                    })?;
                    evidence = Some(remote.evidence().clone());
                    Ok(remote)
                },
                deadline,
                &cancel,
            )
            .map_err(|e| e.to_string())?;
        let evidence = evidence.ok_or("Missing launched helper identity")?;
        Ok(Launched {
            connection: Some(connection),
            local,
            exit_handle,
            digest,
            helper_pid: evidence.process_id,
            helper_created: evidence.creation_time,
        })
    })();
    // The closure consumes the server, so failed setup closes its pipe before
    // waiting. Keep the exact ShellExecute handle until the child has unwound.
    if launched.is_err() {
        loop {
            let result = unsafe { WaitForSingleObject(original.as_raw_handle(), 1000) };
            if result == WAIT_OBJECT_0 {
                break;
            }
            if result != windows_sys::Win32::Foundation::WAIT_TIMEOUT {
                return Err(last("Wait for failed helper launch cleanup"));
            }
        }
    }
    launched.map(Some)
}

pub(crate) struct Launched {
    pub(crate) connection: Option<Connection>,
    pub(crate) local: ProcessPeer,
    exit_handle: OwnedHandle,
    digest: String,
    helper_pid: u32,
    helper_created: u64,
}
impl Launched {
    /// Closing IPC requests helper cancellation. Keep the process handle and
    /// wait for its own cleanup; never kill it while storage may be active.
    pub(crate) fn close_and_wait(&mut self) -> Result<(), String> {
        self.wait_after_close(None)
    }
    fn wait_after_close(&mut self, deadline: Option<Instant>) -> Result<(), String> {
        drop(self.connection.take());
        loop {
            let result = unsafe { WaitForSingleObject(self.exit_handle.as_raw_handle(), 1000) };
            if result == WAIT_OBJECT_0 {
                break;
            }
            if deadline.is_some_and(|d| Instant::now() >= d) {
                return Err("Helper exit was not confirmed before deadline".into());
            }
            if result != windows_sys::Win32::Foundation::WAIT_TIMEOUT {
                return Err(last("Wait for helper cleanup"));
            }
        }
        let mut exit_code = 0;
        if unsafe { GetExitCodeProcess(self.exit_handle.as_raw_handle(), &mut exit_code) } == 0 {
            return Err(last("Read helper exit status"));
        }
        if exit_code != 0 {
            return Err(format!("Helper exited with status {exit_code}"));
        }
        Ok(())
    }
}

pub(crate) fn launch_preparation(
    owner: usize,
    directory: &Path,
    expected_digest: &str,
) -> Result<Option<Launched>, String> {
    launch(owner, directory, expected_digest, true)
}

pub fn run(owner: usize, directory: &Path, expected_digest: &str) -> Result<ProbeOutcome, String> {
    let Some(mut launched) = launch(owner, directory, expected_digest, false)? else {
        return Ok(ProbeOutcome::Cancelled {
            physical_preparation: false,
        });
    };
    let cancel = AtomicBool::new(false);
    let deadline = Instant::now() + Duration::from_secs(20);
    let connection = launched
        .connection
        .as_mut()
        .ok_or("Helper connection is unavailable")?;
    let mut random = [0u8; 32];
    getrandom::fill(&mut random).map_err(|e| format!("Create helper probe nonce: {e}"))?;
    let nonce: String = random.iter().map(|b| format!("{b:02x}")).collect();
    let mut probe = ProbeSession::new(&nonce).map_err(|e| e.to_string())?;
    connection
        .write_frame(
            &probe.request().map_err(|e| e.to_string())?,
            deadline,
            &cancel,
        )
        .map_err(|e| e.to_string())?;
    let response = connection
        .read_frame(deadline, &cancel)
        .map_err(|e| e.to_string())?
        .ok_or("Helper closed before probe reply")?;
    launched.local.revalidate().map_err(|e| e.to_string())?;
    let report = probe.complete(&response).map_err(|e| e.to_string())?;
    launched.wait_after_close(Some(Instant::now() + Duration::from_secs(5)))?;
    Ok(ProbeOutcome::Connected {
        protocol: report.protocol,
        helper_version: report.helper_version,
        helper_pid: launched.helper_pid,
        helper_created: launched.helper_created.to_string(),
        helper_sha256: launched.digest,
        physical_preparation: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::io::IntoRawHandle;
    use windows_sys::Win32::System::Threading::GetProcessId;

    #[test]
    fn launch_failure_cancel_and_missing_handle_remain_distinct_without_uac() {
        let mut info = SHELLEXECUTEINFOW::default();
        assert!(
            launch_result(&mut info, |_| Err(io::Error::from_raw_os_error(1223)))
                .unwrap()
                .is_none()
        );
        assert!(
            launch_result(&mut info, |_| Err(io::Error::from_raw_os_error(5)))
                .unwrap_err()
                .contains("Launch elevated helper")
        );
        assert!(
            launch_result(&mut info, |_| Ok(()))
                .unwrap_err()
                .contains("no helper process")
        );
        info.hProcess = INVALID_HANDLE_VALUE;
        assert!(launch_result(&mut info, |_| Ok(())).is_err());
    }

    #[test]
    fn successful_launch_result_retains_the_exact_transferred_process_handle() {
        let mut info = SHELLEXECUTEINFOW::default();
        // Duplicate only our own process for an inert launch adapter test.
        let returned = restricted_duplicate(unsafe { GetCurrentProcess() }).unwrap();
        let handle = launch_result(&mut info, |info| {
            info.hProcess = returned.into_raw_handle();
            Ok(())
        })
        .unwrap()
        .unwrap();
        assert_eq!(unsafe { GetProcessId(handle.as_raw_handle()) }, unsafe {
            GetCurrentProcessId()
        });
        let copied = restricted_duplicate(handle.as_raw_handle()).unwrap();
        drop(handle);
        assert_eq!(unsafe { GetProcessId(copied.as_raw_handle()) }, unsafe {
            GetCurrentProcessId()
        });
    }
}
