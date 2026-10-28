// SPDX-License-Identifier: GPL-3.0-or-later
use super::{Endpoint, PipeError, security};
use crate::{framing, windows_peer::ProcessPeer};
use std::{
    io::{self, Read, Write},
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{
        ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_INCOMPLETE, ERROR_IO_PENDING,
        ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
        WAIT_TIMEOUT,
    },
    Security::{
        Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
        DACL_SECURITY_INFORMATION, GetKernelObjectSecurity, GetSecurityDescriptorLength,
        OWNER_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, OPEN_EXISTING,
        PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
    },
    System::{
        IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED},
        Pipes::{
            ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId,
            GetNamedPipeServerProcessId, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_BYTE, PIPE_WAIT,
        },
        Threading::{
            CreateEventW, GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_SYNCHRONIZE, WaitForSingleObject,
        },
    },
};

fn error(stage: &'static str, source: io::Error) -> PipeError {
    PipeError::Io { stage, source }
}
fn last(stage: &'static str) -> PipeError {
    error(stage, io::Error::last_os_error())
}
fn raw(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle()
}
fn owned(handle: HANDLE, stage: &'static str) -> Result<OwnedHandle, PipeError> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(last(stage));
    }
    // SAFETY: each caller supplies one newly created successful Win32 handle.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
fn wide(endpoint: &Endpoint) -> Vec<u16> {
    endpoint.local_name().encode_utf16().chain([0]).collect()
}
fn check_deadline(deadline: Instant, cancel: &AtomicBool) -> Result<(), PipeError> {
    if cancel.load(Ordering::Acquire) {
        return Err(PipeError::Cancelled);
    }
    if Instant::now() >= deadline {
        return Err(PipeError::TimedOut);
    }
    Ok(())
}

fn current_peer() -> Result<ProcessPeer, PipeError> {
    // SAFETY: query only our own process, with query and synchronization rights.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            GetCurrentProcessId(),
        )
    };
    Ok(ProcessPeer::from_owned_handle(owned(
        handle,
        "open current process",
    )?)?)
}

fn check_security(handle: &OwnedHandle, expected: &ProcessPeer) -> Result<(), PipeError> {
    let requested = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let mut needed = 0;
    // SAFETY: size query has no output buffer and valid result pointer.
    let success =
        unsafe { GetKernelObjectSecurity(raw(handle), requested, ptr::null_mut(), 0, &mut needed) };
    if success != 0
        || io::Error::last_os_error().raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32)
    {
        return Err(last("pipe security size"));
    }
    if !(20..=security::MAX_DESCRIPTOR_BYTES).contains(&(needed as usize)) {
        return Err(PipeError::Security("security descriptor size"));
    }
    let capacity = needed;
    let mut words = vec![0u32; (capacity as usize).div_ceil(4)];
    // SAFETY: DWORD-aligned allocation covers capacity bytes and remains live.
    if unsafe {
        GetKernelObjectSecurity(
            raw(handle),
            requested,
            words.as_mut_ptr().cast(),
            capacity,
            &mut needed,
        )
    } == 0
    {
        return Err(last("pipe security readback"));
    }
    // SAFETY: initialized allocation contains at least capacity bytes.
    let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), capacity as usize) };
    let token = &expected.evidence().token;
    if needed > capacity || needed < 20 {
        return Err(descriptor_size_error(
            bytes,
            needed,
            &token.user,
            &token.logon,
        ));
    }
    security::validate(&bytes[..needed as usize], &token.user, &token.logon)
}

fn descriptor_size_error(
    bytes: &[u8],
    returned: u32,
    owner: &crate::windows_peer::Sid,
    logon: &crate::windows_peer::Sid,
) -> PipeError {
    let grants_valid = security::validate(bytes, owner, logon).is_ok();
    let length = if grants_valid {
        // SAFETY: this diagnostic is reached only after the bounded parser
        // validated the self-relative header, every present component range,
        // SID and ACL. The allocation is initialized, immutable and remains
        // live throughout this synchronous query. No pointer-sized absolute
        // descriptor or unchecked component offset can reach the SDK call.
        unsafe { GetSecurityDescriptorLength(bytes.as_ptr().cast_mut().cast()) }
    } else {
        0
    };
    // Fixed keys and integers only: no descriptor bytes or user identifiers.
    // This remains an error regardless of the diagnostic validation result.
    error(
        "pipe security readback length",
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "capacity={} returned={returned} expected_grants_valid={} descriptor_length={length}",
                bytes.len(),
                u8::from(grants_valid)
            ),
        ),
    )
}

/// Owns one noninheritable, local-only pipe instance. Dropping closes it.
pub struct Server {
    endpoint: Endpoint,
    handle: OwnedHandle,
}

impl Server {
    pub fn create() -> Result<Self, PipeError> {
        let mut creator = current_peer()?;
        let mut nonce = [0u8; 32];
        // SAFETY: system RNG receives a writable fixed-size buffer.
        let status = unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                nonce.as_mut_ptr(),
                nonce.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        };
        if status < 0 {
            return Err(error("pipe nonce", io::Error::from_raw_os_error(status)));
        }
        let endpoint = Endpoint::from_nonce(&hex::encode(nonce))?;
        let token = &creator.evidence().token;
        let descriptor = security::descriptor(&token.user, &token.logon);
        let mut words = vec![0u32; descriptor.len().div_ceil(4)];
        // SAFETY: destination allocation covers descriptor.len() initialized bytes.
        unsafe {
            ptr::copy_nonoverlapping(
                descriptor.as_ptr(),
                words.as_mut_ptr().cast(),
                descriptor.len(),
            );
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: words.as_mut_ptr().cast(),
            bInheritHandle: 0,
        };
        let name = wide(&endpoint);
        // SAFETY: fixed local NUL-terminated name and valid self-relative descriptor;
        // pipe has one instance and every subsequent I/O uses OVERLAPPED.
        let handle = owned(
            unsafe {
                CreateNamedPipeW(
                    name.as_ptr(),
                    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED,
                    PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    65_536,
                    65_536,
                    0,
                    &attributes,
                )
            },
            "create local pipe",
        )?;
        check_security(&handle, &creator)?;
        creator.revalidate()?;
        Ok(Self { endpoint, handle })
    }
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Consumes the sole instance. The expected process must come from the
    /// caller's independently retained process handle, not an endpoint PID.
    pub fn accept(
        self,
        expected: ProcessPeer,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Connection, PipeError> {
        check_deadline(deadline, cancel)?;
        {
            let mut operation = Operation::new(&self.handle)?;
            // SAFETY: stable boxed OVERLAPPED and event outlive pending connect.
            let success =
                unsafe { ConnectNamedPipe(raw(&self.handle), operation.overlapped.as_mut()) };
            if success == 0 {
                let source = io::Error::last_os_error();
                match source.raw_os_error() {
                    Some(code) if code == ERROR_PIPE_CONNECTED as i32 => {}
                    Some(code) if code == ERROR_IO_PENDING as i32 => {
                        operation.pending = true;
                        operation.wait(deadline, cancel)?;
                    }
                    _ => return Err(error("connect local pipe", source)),
                }
            }
        }
        let mut connection = Connection {
            handle: Some(self.handle),
            expected,
            server_end: true,
        };
        connection.check_peer()?;
        check_deadline(deadline, cancel)?;
        Ok(connection)
    }
}

/// Opens only the fixed local endpoint with explicit data/attribute/read-control
/// rights. Identification SQOS prevents use of this connection for impersonation
/// beyond identity inspection. It does not authorize the expected server.
pub fn connect(
    endpoint: &Endpoint,
    expected: ProcessPeer,
    deadline: Instant,
    cancel: &AtomicBool,
) -> Result<Connection, PipeError> {
    let name = wide(endpoint);
    let handle = loop {
        check_deadline(deadline, cancel)?;
        // SAFETY: bounded fixed local name, no inheritance, explicit rights,
        // OVERLAPPED I/O, identification-only SQOS.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                security::CLIENT_RIGHTS,
                0,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if handle != INVALID_HANDLE_VALUE && !handle.is_null() {
            break owned(handle, "open local pipe")?;
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(ERROR_PIPE_BUSY as i32) {
            return Err(error("open local pipe", source));
        }
        // No indefinite WaitNamedPipe; retries share the caller's absolute deadline.
        thread::sleep(
            Duration::from_millis(5).min(deadline.saturating_duration_since(Instant::now())),
        );
    };
    check_security(&handle, &expected)?;
    let mut connection = Connection {
        handle: Some(handle),
        expected,
        server_end: false,
    };
    connection.check_peer()?;
    check_deadline(deadline, cancel)?;
    Ok(connection)
}

/// A checked endpoint and retained peer observation. No raw handle escape,
/// reconnect or clone API is supplied. Any failed frame closes the stream.
pub struct Connection {
    handle: Option<OwnedHandle>,
    expected: ProcessPeer,
    server_end: bool,
}

impl Connection {
    fn check_peer(&mut self) -> Result<(), PipeError> {
        let handle = self.handle.as_ref().ok_or(PipeError::Closed)?;
        self.expected.revalidate()?;
        let mut pid = 0;
        // SAFETY: handle is our retained connected pipe and pid is writable.
        let success = unsafe {
            if self.server_end {
                GetNamedPipeClientProcessId(raw(handle), &mut pid)
            } else {
                GetNamedPipeServerProcessId(raw(handle), &mut pid)
            }
        };
        if success == 0 {
            return Err(last("pipe peer PID"));
        }
        if pid != self.expected.evidence().process_id {
            return Err(PipeError::WrongPeer);
        }
        self.expected.revalidate()?;
        Ok(())
    }
    pub fn read_frame(
        &mut self,
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<Option<Vec<u8>>, PipeError> {
        let result = (|| {
            check_deadline(deadline, cancel)?;
            self.check_peer()?;
            let mut io = FrameIo {
                handle: self.handle.as_ref().ok_or(PipeError::Closed)?,
                deadline,
                cancel,
                failure: None,
            };
            let result = framing::read_frame(&mut io);
            if let Some(failure) = io.failure {
                return Err(failure);
            }
            let frame = result.map_err(|source| error("read frame", source))?;
            check_deadline(deadline, cancel)?;
            // EOF releases no payload and closes this connection. A complete
            // frame must pass the terminal peer check before any bytes escape.
            if frame.is_some() {
                self.check_peer()?;
            }
            check_deadline(deadline, cancel)?;
            Ok(frame)
        })();
        if result.is_err() || matches!(result, Ok(None)) {
            self.handle = None;
        }
        result
    }
    pub fn write_frame(
        &mut self,
        payload: &[u8],
        deadline: Instant,
        cancel: &AtomicBool,
    ) -> Result<(), PipeError> {
        let result = (|| {
            check_deadline(deadline, cancel)?;
            self.check_peer()?;
            let mut io = FrameIo {
                handle: self.handle.as_ref().ok_or(PipeError::Closed)?,
                deadline,
                cancel,
                failure: None,
            };
            let result = framing::write_frame(&mut io, payload);
            if let Some(failure) = io.failure {
                return Err(failure);
            }
            result.map_err(|source| error("write frame", source))?;
            check_deadline(deadline, cancel)?;
            self.check_peer()?;
            check_deadline(deadline, cancel)?;
            Ok(())
        })();
        if result.is_err() {
            self.handle = None;
        }
        result
    }
}

/// Pending operation storage stays put even when this wrapper moves. Its handle
/// borrow prevents closing the pipe before Drop has drained an outstanding I/O.
struct Operation<'a> {
    handle: &'a OwnedHandle,
    event: OwnedHandle,
    overlapped: Box<OVERLAPPED>,
    pending: bool,
}
impl<'a> Operation<'a> {
    fn new(handle: &'a OwnedHandle) -> Result<Self, PipeError> {
        // SAFETY: unnamed, noninheritable manual-reset event, initially nonsignaled.
        let event = owned(
            unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) },
            "create I/O event",
        )?;
        let mut overlapped = Box::<OVERLAPPED>::default();
        overlapped.hEvent = raw(&event);
        Ok(Self {
            handle,
            event,
            overlapped,
            pending: false,
        })
    }
    fn completed(&mut self, wait: bool) -> Result<u32, PipeError> {
        let mut transferred = 0;
        // SAFETY: same retained handle and stable OVERLAPPED used by submitted I/O.
        let success = unsafe {
            GetOverlappedResult(
                raw(self.handle),
                self.overlapped.as_ref(),
                &mut transferred,
                i32::from(wait),
            )
        };
        if success != 0 {
            self.pending = false;
            return Ok(transferred);
        }
        let source = io::Error::last_os_error();
        if source.raw_os_error() != Some(ERROR_IO_INCOMPLETE as i32) {
            self.pending = false;
        }
        Err(error("complete pipe I/O", source))
    }
    fn cancel_and_drain(&mut self) {
        if !self.pending {
            return;
        }
        // SAFETY: cancellation is for our exact pending operation. A failed
        // cancel (including ERROR_NOT_FOUND) never bypasses completion drain.
        unsafe {
            CancelIoEx(raw(self.handle), self.overlapped.as_ref());
        }
        while self.pending {
            let _ = self.completed(true);
        }
    }
    fn wait(&mut self, deadline: Instant, cancel: &AtomicBool) -> Result<u32, PipeError> {
        loop {
            if let Err(reason) = check_deadline(deadline, cancel) {
                self.cancel_and_drain();
                return Err(reason);
            }
            let timeout = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, 50) as u32;
            // SAFETY: event lives until after pending completion; short bounded wait.
            match unsafe { WaitForSingleObject(raw(&self.event), timeout) } {
                WAIT_TIMEOUT => continue,
                WAIT_OBJECT_0 => {
                    if let Err(reason) = check_deadline(deadline, cancel) {
                        self.cancel_and_drain();
                        return Err(reason);
                    }
                    let result = self.completed(false);
                    check_deadline(deadline, cancel)?;
                    return result;
                }
                _ => {
                    let reason = last("wait for pipe I/O");
                    self.cancel_and_drain();
                    return Err(reason);
                }
            }
        }
    }
}
impl Drop for Operation<'_> {
    fn drop(&mut self) {
        self.cancel_and_drain();
    }
}

struct FrameIo<'a> {
    handle: &'a OwnedHandle,
    deadline: Instant,
    cancel: &'a AtomicBool,
    failure: Option<PipeError>,
}
impl FrameIo<'_> {
    fn save(&mut self, result: Result<usize, PipeError>) -> io::Result<usize> {
        result.map_err(|reason| {
            self.failure = Some(reason);
            io::Error::other("pipe operation failed")
        })
    }
    fn transfer(&self, read: Option<&mut [u8]>, write: Option<&[u8]>) -> Result<usize, PipeError> {
        check_deadline(self.deadline, self.cancel)?;
        let mut operation = Operation::new(self.handle)?;
        let length = read
            .as_ref()
            .map_or_else(|| write.unwrap().len(), |bytes| bytes.len())
            .min(65_536);
        if length == 0 {
            return Ok(0);
        }
        // SAFETY: the borrowed buffer outlives operation, including its Drop on
        // every exit. No pending buffer is released until completion is drained.
        let success = unsafe {
            match read {
                Some(bytes) => ReadFile(
                    raw(self.handle),
                    bytes.as_mut_ptr(),
                    length as u32,
                    ptr::null_mut(),
                    operation.overlapped.as_mut(),
                ),
                None => WriteFile(
                    raw(self.handle),
                    write.unwrap().as_ptr(),
                    length as u32,
                    ptr::null_mut(),
                    operation.overlapped.as_mut(),
                ),
            }
        };
        if success == 0 {
            let source = io::Error::last_os_error();
            if source.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) && write.is_none() {
                return Ok(0);
            }
            if source.raw_os_error() != Some(ERROR_IO_PENDING as i32) {
                return Err(error("submit pipe I/O", source));
            }
        }
        operation.pending = true;
        // An immediate TRUE completion need not signal hEvent. Query its count
        // without waiting; only ERROR_IO_PENDING uses the event/deadline loop.
        let result = if success != 0 {
            let result = operation.completed(false);
            check_deadline(self.deadline, self.cancel)?;
            result
        } else {
            operation.wait(self.deadline, self.cancel)
        };
        let transferred = match result {
            Err(PipeError::Io { source, .. })
                if write.is_none() && source.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32) =>
            {
                0
            }
            other => other?,
        } as usize;
        if transferred > length {
            return Err(error(
                "pipe transfer size",
                io::Error::other("oversized completion"),
            ));
        }
        Ok(transferred)
    }
}
impl Read for FrameIo<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let result = self.transfer(Some(bytes), None);
        self.save(result)
    }
}
impl Write for FrameIo<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let result = self.transfer(None, Some(bytes));
        self.save(result)
    }
    // Every write already waited for local completion. A named-pipe
    // FlushFileBuffers would wait for peer drain and defeat our deadline.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_peer::Sid;

    fn descriptor_fixture() -> (Vec<u32>, usize, Sid, Sid) {
        let owner = Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]).unwrap();
        let logon =
            Sid::from_bytes(&[1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 42, 0, 0, 0, 43, 0, 0, 0])
                .unwrap();
        let bytes = security::descriptor(&owner, &logon);
        let mut words = vec![0u32; bytes.len().div_ceil(4)];
        // SAFETY: initialized aligned destination covers this fixture's bytes.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), words.as_mut_ptr().cast(), bytes.len());
        }
        (words, bytes.len(), owner, logon)
    }

    #[test]
    fn descriptor_size_diagnostic_keeps_valid_grants_as_an_error() {
        let (words, length, owner, logon) = descriptor_fixture();
        // SAFETY: fixture allocation contains length initialized bytes.
        let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), length) };
        for returned in [0, 19, u32::MAX] {
            let result = descriptor_size_error(bytes, returned, &owner, &logon);
            match result {
                PipeError::Io { stage, source } => {
                    assert_eq!(stage, "pipe security readback length");
                    assert_eq!(source.kind(), io::ErrorKind::InvalidData);
                    assert_eq!(
                        source.to_string(),
                        format!(
                            "capacity={length} returned={returned} expected_grants_valid=1 descriptor_length={length}"
                        )
                    );
                }
                other => panic!("unexpected diagnostic error: {other:?}"),
            }
        }
    }

    #[test]
    fn descriptor_size_diagnostic_never_follows_an_invalid_component_pointer() {
        let (mut words, length, owner, logon) = descriptor_fixture();
        words[1] = u32::MAX; // invalid self-relative owner offset
        // SAFETY: fixture allocation contains length initialized bytes.
        let bytes = unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), length) };
        let result = descriptor_size_error(bytes, 0, &owner, &logon);
        match result {
            PipeError::Io { stage, source } => {
                assert_eq!(stage, "pipe security readback length");
                assert_eq!(
                    source.to_string(),
                    format!(
                        "capacity={length} returned=0 expected_grants_valid=0 descriptor_length=0"
                    )
                );
            }
            other => panic!("unexpected diagnostic error: {other:?}"),
        }
    }
}
