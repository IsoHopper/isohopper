// SPDX-License-Identifier: GPL-3.0-or-later
//! Installed, cross-integrity preparation handshake. The fixed Studio mode
//! cancels before execution; these owned diagnostic children cannot write media.
#![cfg(all(test, windows, debug_assertions))]
use isohopper_helper::{
    broker_probe::{check_pair, check_studio},
    prepare_protocol::PrepareArgs,
    windows_installation::{InstalledRole, MachineInstallation},
    windows_peer::{ElevationType, IntegrityLevel, ProcessPeer},
    windows_probe::current_peer,
};
use serde::Deserialize;
use std::{
    fs::File,
    io::{self, BufRead, BufReader, Read, Write},
    mem::size_of,
    os::windows::{
        ffi::OsStrExt,
        io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
        process::CommandExt,
    },
    process::{Child, Command, Stdio},
    ptr,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_INSUFFICIENT_BUFFER, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
        SetHandleInformation, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        DuplicateTokenEx, GetTokenInformation, SECURITY_ATTRIBUTES, SecurityImpersonation,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_ELEVATION_TYPE, TOKEN_LINKED_TOKEN,
        TOKEN_QUERY, TokenElevationType, TokenElevationTypeLimited, TokenLinkedToken, TokenPrimary,
    },
    System::{
        Pipes::CreatePipe,
        Threading::{
            CREATE_NO_WINDOW, CreateProcessAsUserW, DeleteProcThreadAttributeList,
            EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess,
            InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST, OpenProcessToken,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOEXW, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
        },
    },
};

const WAIT: Duration = Duration::from_secs(40);
const MAX_LINE: u64 = 1024;
const MAX_STDERR: usize = 4096;

fn last(stage: &str) -> String {
    format!("{stage}: {}", io::Error::last_os_error())
}

fn own(raw: HANDLE, stage: &str) -> Result<OwnedHandle, String> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(format!("{stage}: invalid returned handle"));
    }
    // SAFETY: each caller passes one newly created successful native handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn limited_token() -> Result<Option<OwnedHandle>, String> {
    let parent = current_peer().map_err(|error| error.to_string())?;
    let evidence = &parent.evidence().token;
    // TokenElevationTypeDefault explicitly means there is no linked token.
    // Report that unsupported runner shape separately from authentication errors.
    if evidence.elevation_type == ElevationType::Default {
        return Ok(None);
    }
    if !evidence.elevated
        || evidence.elevation_type != ElevationType::Full
        || evidence.integrity != IntegrityLevel::High
    {
        return Err("Run this ignored test from an elevated split-token administrator".into());
    }
    let mut raw = ptr::null_mut();
    // SAFETY: query only this process's primary token; output is live.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(last("Open diagnostic parent token"));
    }
    let primary = own(raw, "Parent token")?;
    let mut linked = TOKEN_LINKED_TOKEN::default();
    let mut returned = 0;
    // SAFETY: exact SDK-sized output. A successful call transfers a new handle.
    if unsafe {
        GetTokenInformation(
            primary.as_raw_handle(),
            TokenLinkedToken,
            (&mut linked as *mut TOKEN_LINKED_TOKEN).cast(),
            size_of::<TOKEN_LINKED_TOKEN>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(last("Read diagnostic linked token"));
    }
    let linked = own(linked.LinkedToken, "Linked token")?;
    if returned as usize != size_of::<TOKEN_LINKED_TOKEN>() {
        return Err("Unexpected linked token response length".into());
    }
    let mut kind: TOKEN_ELEVATION_TYPE = 0;
    // SAFETY: exact fixed scalar output for TokenElevationType.
    if unsafe {
        GetTokenInformation(
            linked.as_raw_handle(),
            TokenElevationType,
            (&mut kind as *mut TOKEN_ELEVATION_TYPE).cast(),
            size_of::<TOKEN_ELEVATION_TYPE>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(last("Read linked token elevation type"));
    }
    if returned as usize != size_of::<TOKEN_ELEVATION_TYPE>() || kind != TokenElevationTypeLimited {
        return Err("Diagnostic linked token is not Limited".into());
    }
    let mut duplicate = ptr::null_mut();
    // SAFETY: clone the linked token as a primary token. No token is adjusted,
    // impersonated, or assigned to this process or its threads.
    if unsafe {
        DuplicateTokenEx(
            linked.as_raw_handle(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            ptr::null(),
            SecurityImpersonation,
            TokenPrimary,
            &mut duplicate,
        )
    } == 0
    {
        return Err(last("Duplicate linked primary token"));
    }
    own(duplicate, "Limited primary token").map(Some)
}

fn pipe(child_reads: bool) -> Result<(File, OwnedHandle), String> {
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: 1,
    };
    let (mut read, mut write) = (ptr::null_mut(), ptr::null_mut());
    // SAFETY: fixed synchronous anonymous pipe with live typed outputs.
    if unsafe { CreatePipe(&mut read, &mut write, &attributes, 4096) } == 0 {
        return Err(last("Create diagnostic stdio pipe"));
    }
    let read = own(read, "Pipe read end")?;
    let write = own(write, "Pipe write end")?;
    let (parent, child) = if child_reads {
        (write, read)
    } else {
        (read, write)
    };
    // SAFETY: parent owns this endpoint. Only the opposite endpoint is inherited.
    if unsafe { SetHandleInformation(parent.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err(last("Exclude parent stdio endpoint from inheritance"));
    }
    Ok((File::from(parent), child))
}

struct Attributes(Vec<usize>);
impl Attributes {
    fn new() -> Result<Self, String> {
        let mut bytes = 0;
        // SAFETY: documented sizing call, with no output allocation yet.
        let result =
            unsafe { InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut bytes) };
        if result != 0
            || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
            || bytes == 0
            || bytes > 65536
        {
            return Err(last("Size diagnostic handle attribute list"));
        }
        let mut storage = vec![0usize; bytes.div_ceil(size_of::<usize>())];
        // SAFETY: aligned storage covers the native requested allocation.
        if unsafe {
            InitializeProcThreadAttributeList(storage.as_mut_ptr().cast(), 1, 0, &mut bytes)
        } == 0
        {
            return Err(last("Initialize diagnostic handle attribute list"));
        }
        Ok(Self(storage))
    }
    fn raw(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.0.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: the list was initialized and its allocation remains live.
        unsafe { DeleteProcThreadAttributeList(self.raw()) };
    }
}

fn stop_diagnostic(handle: HANDLE) {
    // These handles identify only children launched by this test's fixed
    // cancellation-only protocol, never an application performing real work.
    if unsafe { WaitForSingleObject(handle, 0) } == WAIT_TIMEOUT {
        unsafe { TerminateProcess(handle, 255) };
        if unsafe { WaitForSingleObject(handle, 5000) } != WAIT_OBJECT_0 {
            eprintln!("Owned diagnostic child did not confirm exit after termination");
        }
    }
}

fn exit_code(handle: HANDLE, deadline: Instant) -> Result<u32, String> {
    let milliseconds = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(40_000) as u32;
    match unsafe { WaitForSingleObject(handle, milliseconds) } {
        WAIT_OBJECT_0 => {}
        WAIT_TIMEOUT => return Err("Diagnostic child exit timed out".into()),
        _ => return Err(last("Wait for diagnostic child")),
    }
    let mut code = 0;
    if unsafe { GetExitCodeProcess(handle, &mut code) } == 0 {
        return Err(last("Read diagnostic child exit status"));
    }
    Ok(code)
}

struct StudioChild {
    process: OwnedHandle,
    input: Option<File>,
    output: Option<File>,
    error: Option<File>,
}
impl Drop for StudioChild {
    fn drop(&mut self) {
        drop(self.input.take());
        stop_diagnostic(self.process.as_raw_handle());
    }
}
struct HelperChild(Child);
impl Drop for HelperChild {
    fn drop(&mut self) {
        stop_diagnostic(self.0.as_raw_handle());
        let _ = self.0.try_wait();
    }
}

fn launch_studio(
    installation: &MachineInstallation,
    token: &OwnedHandle,
) -> Result<StudioChild, String> {
    let (input, child_input) = pipe(true)?;
    let (output, child_output) = pipe(false)?;
    let (error, child_error) = pipe(false)?;
    let inherited = [
        child_input.as_raw_handle(),
        child_output.as_raw_handle(),
        child_error.as_raw_handle(),
    ];
    let mut attributes = Attributes::new()?;
    // SAFETY: the exact three inheritable handles and their array stay live
    // through process creation and until after the attribute list is deleted.
    if unsafe {
        UpdateProcThreadAttribute(
            attributes.raw(),
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            inherited.as_ptr().cast(),
            size_of_val(&inherited),
            ptr::null_mut(),
            ptr::null(),
        )
    } == 0
    {
        return Err(last("Restrict diagnostic child handle inheritance"));
    }
    let mut startup = STARTUPINFOEXW::default();
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    startup.StartupInfo.hStdInput = child_input.as_raw_handle();
    startup.StartupInfo.hStdOutput = child_output.as_raw_handle();
    startup.StartupInfo.hStdError = child_error.as_raw_handle();
    startup.lpAttributeList = attributes.raw();
    let application: Vec<_> = installation
        .path(InstalledRole::Studio)
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let directory: Vec<_> = installation
        .directory()
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut command: Vec<_> = [b'"' as u16]
        .into_iter()
        .chain(application[..application.len() - 1].iter().copied())
        .chain("\" --diagnose-empty-preparation".encode_utf16())
        .chain(Some(0))
        .collect();
    let mut info = PROCESS_INFORMATION::default();
    installation.revalidate()?;
    // SAFETY: fixed guarded executable and fixed diagnostic-only argument;
    // mutable terminated command, token, stdio and attribute storage stay live.
    if unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle(),
            application.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            1,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            ptr::null(),
            directory.as_ptr(),
            &startup.StartupInfo,
            &mut info,
        )
    } == 0
    {
        return Err(last("Launch installed Limited Studio diagnostic"));
    }
    let process = own(info.hProcess, "Diagnostic Studio process")?;
    drop(own(info.hThread, "Diagnostic Studio thread")?);
    Ok(StudioChild {
        process,
        input: Some(input),
        output: Some(output),
        error: Some(error),
    })
}

struct Lines {
    receiver: mpsc::Receiver<Result<String, String>>,
    worker: thread::JoinHandle<()>,
}
impl Lines {
    fn new(output: File) -> Self {
        let (sender, receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut reader = BufReader::new(output);
            for _ in 0..2 {
                let result = (|| {
                    let mut line = Vec::new();
                    reader
                        .by_ref()
                        .take(MAX_LINE + 1)
                        .read_until(b'\n', &mut line)
                        .map_err(|error| error.to_string())?;
                    if line.len() as u64 > MAX_LINE || line.last() != Some(&b'\n') {
                        return Err("Diagnostic output was missing a bounded complete line".into());
                    }
                    line.pop();
                    if line.last() == Some(&b'\r') {
                        line.pop();
                    }
                    String::from_utf8(line).map_err(|_| "Diagnostic output was not UTF-8".into())
                })();
                let failed = result.is_err();
                if sender.send(result).is_err() || failed {
                    break;
                }
            }
        });
        Self { receiver, worker }
    }
    fn next(&self, deadline: Instant) -> Result<String, String> {
        self.receiver
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| "Timed out or disconnected waiting for diagnostic output".to_string())?
    }
}

struct Capture {
    bytes: Arc<Mutex<Vec<u8>>>,
    done: mpsc::Receiver<()>,
    worker: thread::JoinHandle<()>,
}
impl Capture {
    fn new(mut input: impl Read + Send + 'static) -> Self {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let result = bytes.clone();
        let (sender, done) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut buffer = [0; 1024];
            while let Ok(count) = input.read(&mut buffer) {
                if count == 0 {
                    break;
                }
                if let Ok(mut captured) = result.lock() {
                    let remaining = MAX_STDERR.saturating_sub(captured.len());
                    captured.extend_from_slice(&buffer[..count.min(remaining)]);
                }
            }
            let _ = sender.send(());
        });
        Self {
            bytes,
            done,
            worker,
        }
    }
    fn finish(self) -> String {
        if self.done.recv_timeout(Duration::from_secs(5)).is_ok() {
            let _ = self.worker.join();
        }
        self.bytes
            .lock()
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|_| "stderr capture unavailable".into())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Routing {
    nonce: String,
    studio_pid: u32,
    studio_created: u64,
}

#[test]
#[ignore = "requires installed debug Studio/helper and elevated split-token administrator; no UAC or device access"]
fn native_installed_empty_preparation_handoff_cancels_before_execution() -> Result<(), String> {
    let Some(token) = limited_token()? else {
        println!("INSTALLED_EMPTY_PREPARATION_HANDOFF_UNSUPPORTED reason=no_split_token");
        return Ok(());
    };
    let installation = Arc::new(MachineInstallation::open()?);
    let mut studio = launch_studio(&installation, &token)?;
    let lines = Lines::new(studio.output.take().ok_or("Missing diagnostic stdout")?);
    let studio_error = Capture::new(studio.error.take().ok_or("Missing diagnostic stderr")?);
    let mut helper: Option<HelperChild> = None;
    let mut helper_error: Option<Capture> = None;
    let result = (|| {
        let route: Routing = serde_json::from_str(&lines.next(Instant::now() + WAIT)?)
            .map_err(|error| format!("Invalid diagnostic routing: {error}"))?;
        let mut peer = ProcessPeer::from_owned_handle(
            studio
                .process
                .as_handle()
                .try_clone_to_owned()
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?
        .bind_installation(installation.clone(), InstalledRole::Studio)
        .map_err(|error| error.to_string())?;
        check_studio(peer.evidence()).map_err(|error| error.to_string())?;
        let parent = current_peer().map_err(|error| error.to_string())?;
        check_pair(peer.evidence(), parent.evidence()).map_err(|error| error.to_string())?;
        if route.studio_pid != peer.evidence().process_id
            || route.studio_created != peer.evidence().creation_time
        {
            return Err("Diagnostic routing does not identify the retained Studio child".into());
        }
        let arguments = PrepareArgs::new(&route.nonce, route.studio_pid, route.studio_created)
            .map_err(|error| error.to_string())?
            .launch_arguments();
        peer.revalidate().map_err(|error| error.to_string())?;
        installation.revalidate()?;
        let launched = Command::new(installation.path(InstalledRole::Helper))
            .args(arguments.split_ascii_whitespace())
            .current_dir(installation.directory())
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| format!("Launch installed diagnostic helper: {error}"))?;
        let pid = launched.id();
        helper = Some(HelperChild(launched));
        let error = helper
            .as_mut()
            .ok_or("Missing helper child")?
            .0
            .stderr
            .take()
            .ok_or("Missing helper diagnostic stderr")?;
        helper_error = Some(Capture::new(error));
        writeln!(
            studio.input.as_mut().ok_or("Missing diagnostic stdin")?,
            "{pid}"
        )
        .map_err(|error| format!("Send retained helper PID: {error}"))?;
        drop(studio.input.take());
        let line = lines.next(Instant::now() + WAIT)?;
        if line != "EMPTY_PREPARATION_HANDOFF_OK" {
            return Err(format!("Unexpected diagnostic completion: {line}"));
        }
        let studio_code = exit_code(studio.process.as_raw_handle(), Instant::now() + WAIT)?;
        let helper_code = exit_code(
            helper
                .as_ref()
                .ok_or("Missing helper child")?
                .0
                .as_raw_handle(),
            Instant::now() + WAIT,
        )?;
        if studio_code != 0 || helper_code != 0 {
            return Err(format!(
                "Diagnostic exit status: Studio {studio_code}; helper {helper_code}"
            ));
        }
        installation.revalidate()?;
        Ok(())
    })();
    // On failure, only these fixed cancellation-only children may be stopped.
    // Close all writers before waiting for diagnostic readers to finish.
    drop(studio);
    drop(helper);
    let reader_deadline = Instant::now() + Duration::from_secs(5);
    while !lines.worker.is_finished() && Instant::now() < reader_deadline {
        thread::sleep(Duration::from_millis(10));
    }
    if lines.worker.is_finished() {
        let _ = lines.worker.join();
    }
    let studio_error = studio_error.finish();
    let helper_error = helper_error.map(Capture::finish).unwrap_or_default();
    if let Err(error) = result {
        return Err(format!(
            "{error}\nStudio stderr (first {MAX_STDERR} bytes): {studio_error}\nHelper stderr (first {MAX_STDERR} bytes): {helper_error}"
        ));
    }
    println!(
        "INSTALLED_EMPTY_PREPARATION_HANDOFF_OK Limited Studio; elevated real helper; archive transferred; cancelled before execution; no UAC or devices"
    );
    Ok(())
}
