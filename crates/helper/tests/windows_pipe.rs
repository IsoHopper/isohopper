// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::windows_pipe::Endpoint;

#[test]
fn endpoint_accepts_only_a_fixed_length_lowercase_public_nonce() {
    let nonce = "a1".repeat(32);
    let endpoint = Endpoint::from_nonce(&nonce).unwrap();
    assert_eq!(endpoint.nonce(), nonce);
    assert_eq!(
        endpoint.local_name(),
        format!(r"\\.\pipe\IsoHopper.v1.{nonce}")
    );
    for invalid in [
        String::new(),
        "a".repeat(63),
        "a".repeat(65),
        "A".repeat(64),
        "g".repeat(64),
        "\\".repeat(64),
        "é".repeat(32),
        format!("{}\0", "a".repeat(63)),
    ] {
        assert!(Endpoint::from_nonce(&invalid).is_err());
    }
}

#[test]
fn endpoint_never_accepts_an_arbitrary_pipe_or_network_path() {
    for path in [
        r"\\.\pipe\other",
        r"\\server\pipe\other",
        r"C:\other",
        r"..\pipe",
    ] {
        assert!(Endpoint::from_nonce(path).is_err());
    }
}

#[cfg(windows)]
#[test]
#[ignore = "internal controlled child for Windows pipe wrong-peer observation"]
fn windows_pipe_child_waits_for_parent() {
    use std::io::Read;
    if std::env::var_os("ISOHOPPER_PIPE_TEST_CHILD").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, [0x5a]);
}

#[cfg(windows)]
#[test]
#[ignore = "internal controlled child for Windows pipe cross-process roundtrip"]
fn windows_pipe_child_echoes_parent() -> Result<(), Box<dyn std::error::Error>> {
    use isohopper_helper::{windows_peer::ProcessPeer, windows_pipe::connect};
    use std::{
        io::{Read, Write},
        os::windows::io::{FromRawHandle, OwnedHandle},
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    // General ignored-test runs must neither block on stdin nor open a process.
    if std::env::var_os("ISOHOPPER_PIPE_ECHO_CHILD").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return Ok(());
    }
    // Test-only bootstrap: public routing/identity fields, no secret. Reading
    // at most 129 bytes distinguishes a valid bounded message from oversize.
    let mut input = String::new();
    std::io::stdin().take(129).read_to_string(&mut input)?;
    assert!(input.len() <= 128, "oversized child bootstrap");
    let fields: Vec<_> = input.split_ascii_whitespace().collect();
    assert_eq!(fields.len(), 3, "invalid child bootstrap");
    let endpoint = Endpoint::from_nonce(fields[0])?;
    let parent_id: u32 = fields[1].parse()?;
    let creation_time: u64 = fields[2].parse()?;
    // SAFETY: this guarded test child receives its live test parent's PID from
    // inherited stdin. The retained observation must match creation time too.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            parent_id,
        )
    };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful OpenProcess returned one newly owned handle.
    let expected = ProcessPeer::from_owned_handle(unsafe { OwnedHandle::from_raw_handle(raw) })?;
    assert!(
        expected.evidence().process_id == parent_id
            && expected.evidence().creation_time == creation_time,
        "parent identity mismatch"
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let cancel = AtomicBool::new(false);
    let mut connection = connect(&endpoint, expected, deadline, &cancel)?;
    let payload = connection
        .read_frame(deadline, &cancel)?
        .ok_or("missing parent frame")?;
    assert_eq!(payload, b"cross-process roundtrip");
    connection.write_frame(&payload, deadline, &cancel)?;
    // Separate test-only lifecycle signal: let the parent know the echo's
    // terminal peer check finished before it closes the production connection.
    std::io::stderr().write_all(&[0x5a])?;
    assert!(
        connection.read_frame(deadline, &cancel)?.is_none(),
        "unexpected frame after echo"
    );
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "disposable local pipe and own child only; no UAC or device access"]
fn windows_pipe_checks_peers_deadlines_and_frames() -> Result<(), Box<dyn std::error::Error>> {
    use isohopper_helper::{
        framing::MAX_FRAME_BYTES,
        windows_peer::ProcessPeer,
        windows_pipe::{Connection, PipeError, Server, connect},
    };
    use std::{
        io::{Read, Write},
        os::windows::io::{AsHandle, FromRawHandle, OwnedHandle},
        process::{Child, Command, Stdio},
        ptr,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
            mpsc,
        },
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::{ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{
            CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
            SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WriteFile,
        },
        System::{
            Pipes::{CreateNamedPipeW, PIPE_TYPE_BYTE},
            Threading::{
                GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
                PROCESS_SYNCHRONIZE,
            },
        },
    };

    fn current() -> ProcessPeer {
        // SAFETY: own process only, read-only query and synchronization rights.
        let raw = unsafe {
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                GetCurrentProcessId(),
            )
        };
        assert!(!raw.is_null(), "open own process failed");
        ProcessPeer::from_owned_handle(unsafe { OwnedHandle::from_raw_handle(raw) }).unwrap()
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }
    fn pair() -> (Connection, Connection) {
        let server = Server::create().unwrap();
        let endpoint = server.endpoint().clone();
        let listener = thread::spawn(move || {
            server
                .accept(current(), deadline(), &AtomicBool::new(false))
                .unwrap()
        });
        let client = connect(&endpoint, current(), deadline(), &AtomicBool::new(false)).unwrap();
        (listener.join().unwrap(), client)
    }
    struct OwnChild(Child);
    impl Drop for OwnChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // Both sides open with the production exact rights and verify the protected
    // DACL before these frames. Maximum payload also exercises partial transfers.
    let (mut server, mut client) = pair();
    // Prebuffered small reads/writes complete immediately. Win32 need not signal
    // the OVERLAPPED event for this path; waiting for that event would time out.
    client.write_frame(b"already buffered", deadline(), &AtomicBool::new(false))?;
    assert_eq!(
        server
            .read_frame(deadline(), &AtomicBool::new(false))?
            .unwrap(),
        b"already buffered"
    );
    server.write_frame(b"immediate reply", deadline(), &AtomicBool::new(false))?;
    assert_eq!(
        client
            .read_frame(deadline(), &AtomicBool::new(false))?
            .unwrap(),
        b"immediate reply"
    );
    let (release_echo, wait_echo) = mpsc::channel();
    let echo = thread::spawn(move || {
        let payload = server
            .read_frame(deadline(), &AtomicBool::new(false))
            .unwrap()
            .unwrap();
        assert_eq!(payload, vec![0x5a; MAX_FRAME_BYTES]);
        server
            .write_frame(&payload, deadline(), &AtomicBool::new(false))
            .unwrap();
        // Retain the pipe until the client's terminal peer check has completed.
        wait_echo.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    client.write_frame(
        &vec![0x5a; MAX_FRAME_BYTES],
        deadline(),
        &AtomicBool::new(false),
    )?;
    assert_eq!(
        client
            .read_frame(deadline(), &AtomicBool::new(false))?
            .unwrap(),
        vec![0x5a; MAX_FRAME_BYTES]
    );
    release_echo.send(())?;
    echo.join().unwrap();

    // A pending read completes as clean EOF when only the peer pipe closes.
    // Its process stays alive, and EOF releases no frame bytes as valid data.
    let (mut server, client) = pair();
    let (ready, waiting) = mpsc::channel();
    let eof = thread::spawn(move || {
        ready.send(()).unwrap();
        let frame = server
            .read_frame(deadline(), &AtomicBool::new(false))
            .unwrap();
        assert!(frame.is_none());
        assert!(matches!(
            server.read_frame(deadline(), &AtomicBool::new(false)),
            Err(PipeError::Closed)
        ));
    });
    waiting.recv_timeout(Duration::from_secs(10))?;
    thread::sleep(Duration::from_millis(80));
    drop(client);
    eof.join().unwrap();

    // The peer process is still this live test process, but its pipe handle has
    // already closed before read_frame starts. Exercise both native PID-query
    // directions; clean EOF must not depend on winning a close/read race.
    let (mut server, client) = pair();
    drop(client);
    assert!(
        server
            .read_frame(deadline(), &AtomicBool::new(false))?
            .is_none(),
        "server did not report clean EOF after the client handle closed"
    );
    assert!(matches!(
        server.read_frame(deadline(), &AtomicBool::new(false)),
        Err(PipeError::Closed)
    ));
    let (server, mut client) = pair();
    drop(server);
    assert!(
        client
            .read_frame(deadline(), &AtomicBool::new(false))?
            .is_none(),
        "client did not report clean EOF after the server handle closed"
    );
    assert!(matches!(
        client.read_frame(deadline(), &AtomicBool::new(false)),
        Err(PipeError::Closed)
    ));

    // A complete length header followed by only one of four payload bytes is
    // not clean EOF. Keep the raw client alive while the receiver starts, then
    // close only its pipe and require the framing error, not an arbitrary error.
    let server = Server::create()?;
    let name: Vec<_> = server
        .endpoint()
        .local_name()
        .encode_utf16()
        .chain([0])
        .collect();
    let (written, wait_written) = mpsc::channel();
    let (close, wait_close) = mpsc::channel();
    let partial_client = thread::spawn(move || {
        // SAFETY: fixed disposable endpoint, exact data rights, synchronous
        // noninheritable handle and identification-only security context.
        let raw = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x0012_0083,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        assert_ne!(
            raw, INVALID_HANDLE_VALUE,
            "partial payload client open failed"
        );
        // SAFETY: CreateFileW returned one new owned handle.
        let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
        let bytes = [0, 0, 0, 4, 0x5a];
        let mut count = 0;
        // SAFETY: synchronous handle and fixed live input/output buffers.
        assert_ne!(
            unsafe { WriteFile(raw, bytes.as_ptr(), 5, &mut count, ptr::null_mut()) },
            0,
            "partial payload write failed"
        );
        assert_eq!(count, 5);
        written.send(()).unwrap();
        wait_close.recv_timeout(Duration::from_secs(10)).unwrap();
        drop(handle);
    });
    let mut server = server.accept(current(), deadline(), &AtomicBool::new(false))?;
    wait_written.recv_timeout(Duration::from_secs(10))?;
    let (reading, wait_reading) = mpsc::channel();
    let partial_reader = thread::spawn(move || {
        reading.send(()).unwrap();
        let result = server.read_frame(deadline(), &AtomicBool::new(false));
        assert!(
            matches!(result, Err(PipeError::Io { stage: "read frame", ref source })
                if source.kind() == std::io::ErrorKind::UnexpectedEof),
            "partial payload close must return a framing EOF error: {result:?}"
        );
        assert!(matches!(
            server.read_frame(deadline(), &AtomicBool::new(false)),
            Err(PipeError::Closed)
        ));
    });
    wait_reading.recv_timeout(Duration::from_secs(10))?;
    thread::sleep(Duration::from_millis(80));
    close.send(())?;
    partial_client.join().unwrap();
    partial_reader.join().unwrap();

    // Positive roundtrip across real processes. The parent uses the actual
    // spawned child's retained handle; the child independently checks this
    // parent's retained identity before production pipe peer validation.
    let server = Server::create()?;
    let parent = current();
    let bootstrap = format!(
        "{} {} {}\n",
        server.endpoint().nonce(),
        parent.evidence().process_id,
        parent.evidence().creation_time
    );
    let mut echo_child = OwnChild(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "windows_pipe_child_echoes_parent",
                "--ignored",
                "--nocapture",
            ])
            .env("ISOHOPPER_PIPE_ECHO_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut child_stderr = echo_child
        .0
        .stderr
        .take()
        .ok_or("missing echo child stderr")?;
    let (completed, wait_completed) = mpsc::channel();
    let completion = thread::spawn(move || {
        let mut signal = [0];
        let result = child_stderr.read_exact(&mut signal).map(|()| signal);
        // Return and retain the pipe even after the signal, so child errors can
        // still write diagnostics without receiving a broken stderr pipe.
        let _ = completed.send((result, child_stderr));
    });
    let expected_child =
        ProcessPeer::from_owned_handle(echo_child.0.as_handle().try_clone_to_owned()?)?;
    echo_child
        .0
        .stdin
        .take()
        .ok_or("missing echo child stdin")?
        .write_all(bootstrap.as_bytes())?;
    let mut connection = server.accept(expected_child, deadline(), &AtomicBool::new(false))?;
    connection.write_frame(
        b"cross-process roundtrip",
        deadline(),
        &AtomicBool::new(false),
    )?;
    assert_eq!(
        connection
            .read_frame(deadline(), &AtomicBool::new(false))?
            .ok_or("missing child echo")?,
        b"cross-process roundtrip"
    );
    let (signal, _child_stderr) = wait_completed.recv_timeout(Duration::from_secs(10))?;
    assert_eq!(signal?, [0x5a], "child echo completion signal mismatch");
    completion.join().unwrap();
    // Both frame operations and their terminal peer checks are now complete.
    // Dropping exercises the child's pending or already-closed EOF.
    drop(connection);
    let exit_deadline = deadline();
    loop {
        if let Some(status) = echo_child.0.try_wait()? {
            assert!(status.success(), "cross-process pipe child failed");
            break;
        }
        if Instant::now() >= exit_deadline {
            return Err("cross-process pipe child exit timed out".into());
        }
        thread::sleep(Duration::from_millis(10));
    }

    // First-instance creation refuses an existing endpoint. The client DACL
    // additionally grants no FILE_CREATE_PIPE_INSTANCE alias (bit 4).
    let only = Server::create()?;
    let name: Vec<_> = only
        .endpoint()
        .local_name()
        .encode_utf16()
        .chain([0])
        .collect();
    let duplicate = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE,
            1,
            4096,
            4096,
            0,
            ptr::null(),
        )
    };
    assert_eq!(
        duplicate, INVALID_HANDLE_VALUE,
        "duplicate pipe instance unexpectedly created"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(ERROR_ACCESS_DENIED as i32)
    );
    drop(only);

    // Missing peer cannot turn a pending connect into an unbounded wait.
    let server = Server::create()?;
    let started = Instant::now();
    assert!(matches!(
        server.accept(
            current(),
            started + Duration::from_millis(80),
            &AtomicBool::new(false)
        ),
        Err(PipeError::TimedOut)
    ));
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "local cancellation drain unexpectedly slow"
    );
    let server = Server::create()?;
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    let trigger = thread::spawn(move || {
        thread::sleep(Duration::from_millis(80));
        signal.store(true, Ordering::Release);
    });
    assert!(matches!(
        server.accept(current(), deadline(), &cancel),
        Err(PipeError::Cancelled)
    ));
    trigger.join().unwrap();

    // Read timeout and cancellation poison the connection, even with a live peer.
    let (mut server, _client) = pair();
    assert!(matches!(
        server.read_frame(
            Instant::now() + Duration::from_millis(80),
            &AtomicBool::new(false)
        ),
        Err(PipeError::TimedOut)
    ));
    assert!(matches!(
        server.read_frame(deadline(), &AtomicBool::new(false)),
        Err(PipeError::Closed)
    ));
    let (mut server, _client) = pair();
    let cancel = Arc::new(AtomicBool::new(false));
    let signal = cancel.clone();
    let trigger = thread::spawn(move || {
        thread::sleep(Duration::from_millis(80));
        signal.store(true, Ordering::Release);
    });
    assert!(matches!(
        server.read_frame(deadline(), &cancel),
        Err(PipeError::Cancelled)
    ));
    trigger.join().unwrap();
    assert!(matches!(
        server.write_frame(b"x", deadline(), &AtomicBool::new(false)),
        Err(PipeError::Closed)
    ));

    // The peer remains connected but does not read. Writes must eventually
    // exhaust the bounded pipe buffer and cancel/drain without reusing it.
    let (mut server, _client) = pair();
    let write_deadline = Instant::now() + Duration::from_millis(300);
    let mut timed_out = false;
    for _ in 0..64 {
        match server.write_frame(
            &vec![0x5a; MAX_FRAME_BYTES],
            write_deadline,
            &AtomicBool::new(false),
        ) {
            Err(PipeError::TimedOut) => {
                timed_out = true;
                break;
            }
            Ok(()) => {}
            Err(other) => return Err(other.into()),
        }
    }
    assert!(timed_out, "nonreading peer never blocked bounded writes");
    assert!(matches!(
        server.write_frame(b"x", deadline(), &AtomicBool::new(false)),
        Err(PipeError::Closed)
    ));

    // The absolute deadline spans partial header reads. The raw test client is
    // synchronous and transmits only one byte, then deliberately remains open.
    let server = Server::create()?;
    let name: Vec<_> = server
        .endpoint()
        .local_name()
        .encode_utf16()
        .chain([0])
        .collect();
    let (release, wait) = mpsc::channel();
    let partial = thread::spawn(move || {
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                0x0012_0083,
                0,
                ptr::null(),
                OPEN_EXISTING,
                SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        assert_ne!(
            handle, INVALID_HANDLE_VALUE,
            "partial test client open failed"
        );
        let _handle = unsafe { OwnedHandle::from_raw_handle(handle) };
        let mut written = 0;
        assert_ne!(
            unsafe { WriteFile(handle, [0u8].as_ptr(), 1, &mut written, ptr::null_mut()) },
            0
        );
        assert_eq!(written, 1);
        wait.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    let mut server = server.accept(current(), deadline(), &AtomicBool::new(false))?;
    assert!(matches!(
        server.read_frame(
            Instant::now() + Duration::from_millis(100),
            &AtomicBool::new(false)
        ),
        Err(PipeError::TimedOut)
    ));
    assert!(matches!(
        server.read_frame(deadline(), &AtomicBool::new(false)),
        Err(PipeError::Closed)
    ));
    release.send(())?;
    partial.join().unwrap();

    // Wrong process refuses the connection before frames. The expected process
    // is a retained handle to this test's disposable child, never a guessed PID.
    let mut child = OwnChild(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "windows_pipe_child_waits_for_parent",
                "--ignored",
                "--nocapture",
            ])
            .env("ISOHOPPER_PIPE_TEST_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let expected_child = ProcessPeer::from_owned_handle(child.0.as_handle().try_clone_to_owned()?)?;
    let server = Server::create()?;
    let endpoint = server.endpoint().clone();
    let (release, wait) = mpsc::channel();
    let wrong = thread::spawn(move || {
        // Server refusal may close the pipe while client checks its own peer;
        // either result is okay here. Server's exact WrongPeer result is required.
        let _connection = connect(&endpoint, current(), deadline(), &AtomicBool::new(false));
        wait.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    assert!(matches!(
        server.accept(expected_child, deadline(), &AtomicBool::new(false)),
        Err(PipeError::WrongPeer)
    ));
    release.send(())?;
    wrong.join().unwrap();
    child.0.stdin.take().unwrap().write_all(&[0x5a])?;
    assert!(child.0.wait()?.success());
    println!(
        "Windows pipe transport passed: roundtrip=1 cross_process=1 immediate_io=1 clean_eof=1 immediate_eof=1 partial_payload_eof=1 first_instance=1 wrong_peer=1 connect_timeout=1 connect_cancel=1 read_timeout=1 read_cancel=1 write_timeout=1 partial_header_timeout=1; no UAC or device access"
    );
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "internal controlled child offering an owned temporary source over a pipe"]
fn windows_pipe_child_offers_source() -> Result<(), Box<dyn std::error::Error>> {
    use isohopper_helper::{windows_peer::ProcessPeer, windows_pipe::connect};
    use std::{
        fs::OpenOptions,
        io::{BufRead, Read, Seek, SeekFrom, Write},
        os::windows::{
            fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        ptr,
        sync::atomic::AtomicBool,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE},
        System::Threading::{
            CreateEventW, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        },
    };
    if std::env::var_os("ISOHOPPER_PIPE_SOURCE_CHILD").as_deref() != Some(std::ffi::OsStr::new("1"))
    {
        return Ok(());
    }
    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut bootstrap = String::new();
    input.by_ref().take(129).read_line(&mut bootstrap)?;
    assert!(bootstrap.len() <= 128 && bootstrap.ends_with('\n'));
    let fields: Vec<_> = bootstrap.split_ascii_whitespace().collect();
    assert_eq!(fields.len(), 4);
    let endpoint = Endpoint::from_nonce(fields[0])?;
    let parent_id: u32 = fields[1].parse()?;
    let created: u64 = fields[2].parse()?;
    assert!(matches!(fields[3], "keep" | "close"));
    // SAFETY: this gated fixture receives its live parent's identity through
    // inherited stdin, and checks creation time before connecting to its pipe.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            parent_id,
        )
    };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful OpenProcess returned one new owned process handle.
    let expected = ProcessPeer::from_owned_handle(unsafe { OwnedHandle::from_raw_handle(raw) })?;
    assert_eq!(expected.evidence().creation_time, created);
    // This parent-owned temporary path is test bootstrap only. Production
    // transfer below receives a handle through the checked frame, not a path.
    let path = std::env::var_os("ISOHOPPER_PIPE_SOURCE_FILE").ok_or("missing fixture path")?;
    let mut source = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)?;
    source.seek(SeekFrom::Start(7))?;
    // SAFETY: one unnamed, noninheritable event, used as the wrong-type fixture.
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful CreateEventW returned one new owned event handle.
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    let deadline = Instant::now() + Duration::from_secs(15);
    let cancel = AtomicBool::new(false);
    let mut connection = connect(&endpoint, expected, deadline, &cancel)?;
    let mut offer = Vec::new();
    for handle in [source.as_raw_handle(), event.as_raw_handle()] {
        offer.extend_from_slice(&(handle as usize as u64).to_le_bytes());
    }
    connection.write_frame(&offer, deadline, &cancel)?;
    let mut source = Some(source);
    if fields[3] == "close" {
        drop(source.take());
    }
    // No further native object creation after closing the source: avoid handle
    // number reuse. This independent lifecycle signal follows frame peer checks.
    std::io::stderr().write_all(&[0x5a])?;
    std::io::stderr().flush()?;
    let mut done = [0];
    input.read_exact(&mut done)?;
    assert_eq!(done, [0x5a]);
    if let Some(mut source) = source {
        assert_eq!(
            source.stream_position()?,
            7,
            "receiver changed sender cursor"
        );
        let mut byte = [0];
        source.read_exact(&mut byte)?;
        assert_eq!(byte, [7]);
    }
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "owned child, temporary file and local pipe only; no UAC or device access"]
fn windows_pipe_transfers_source_from_retained_peer() -> Result<(), Box<dyn std::error::Error>> {
    use isohopper_helper::{
        windows_peer::{PeerError, ProcessPeer},
        windows_pipe::{PipeError, Server},
    };
    use sha2::{Digest, Sha256};
    use std::{
        io::{Read, Seek, Write},
        os::windows::io::{AsHandle, FromRawHandle, OwnedHandle},
        process::{Child, Command, Stdio},
        sync::{atomic::AtomicBool, mpsc},
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };
    struct OwnChild(Child);
    impl Drop for OwnChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(15)
    }
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("pipe-source.bin");
    let bytes: Vec<_> = (0..8193).map(|i| (i % 251) as u8).collect();
    std::fs::write(&path, &bytes)?;
    // SAFETY: query only this retained parent identity for fixture bootstrap.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            GetCurrentProcessId(),
        )
    };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful OpenProcess returned one new owned process handle.
    let parent = ProcessPeer::from_owned_handle(unsafe { OwnedHandle::from_raw_handle(raw) })?;
    let active = AtomicBool::new(false);
    for case in ["valid", "wrong", "closed", "cancelled", "expired"] {
        let server = Server::create()?;
        let bootstrap = format!(
            "{} {} {} {}\n",
            server.endpoint().nonce(),
            parent.evidence().process_id,
            parent.evidence().creation_time,
            if case == "closed" { "close" } else { "keep" }
        );
        let mut child = OwnChild(
            Command::new(std::env::current_exe()?)
                .args([
                    "--exact",
                    "windows_pipe_child_offers_source",
                    "--ignored",
                    "--nocapture",
                ])
                .env("ISOHOPPER_PIPE_SOURCE_CHILD", "1")
                .env("ISOHOPPER_PIPE_SOURCE_FILE", &path)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        // Child's actual process handle includes duplication rights. The pipe
        // consumes this same retained peer; no lookup by supplied PID occurs.
        let expected = ProcessPeer::from_owned_handle(child.0.as_handle().try_clone_to_owned()?)?;
        let mut stderr = child.0.stderr.take().ok_or("missing fixture stderr")?;
        let (sender, receiver) = mpsc::sync_channel(1);
        let ready = thread::spawn(move || {
            let mut signal = [0];
            let result = stderr.read_exact(&mut signal).map(|()| signal);
            let _ = sender.send((result, stderr));
        });
        child
            .0
            .stdin
            .as_mut()
            .ok_or("missing fixture stdin")?
            .write_all(bootstrap.as_bytes())?;
        let mut connection = server.accept(expected, deadline(), &active)?;
        let offer = connection
            .read_frame(deadline(), &active)?
            .ok_or("missing source offer")?;
        assert_eq!(offer.len(), 16);
        let source_handle = u64::from_le_bytes(offer[..8].try_into()?);
        let wrong_handle = u64::from_le_bytes(offer[8..].try_into()?);
        let (signal, _stderr) = receiver.recv_timeout(Duration::from_secs(15))?;
        assert_eq!(signal?, [0x5a]);
        ready.join().unwrap();
        let mut retained = None;
        match case {
            "valid" => {
                let mut file =
                    connection.receive_source_file(source_handle, deadline(), &active)?;
                assert_eq!(file.stream_position()?, 0);
                let mut actual = Vec::new();
                file.read_to_end(&mut actual)?;
                assert_eq!(actual, bytes);
                assert_eq!(
                    hex::encode(Sha256::digest(&actual)),
                    "7e3691790cd64b19d4edb1a80e988214515abeb53aa0f34ffbfe4b4bf405d120"
                );
                assert!(
                    file.write_all(&[0]).is_err(),
                    "received source was writable"
                );
                retained = Some(file);
            }
            "wrong" => assert!(matches!(
                connection.receive_source_file(wrong_handle, deadline(), &active),
                Err(PipeError::Peer(_))
            )),
            "closed" => assert!(matches!(
                connection.receive_source_file(source_handle, deadline(), &active),
                Err(PipeError::Peer(PeerError::Io { stage: "duplicate source file", source }))
                    if source.raw_os_error() == Some(6)
            )),
            "cancelled" => assert!(matches!(
                connection.receive_source_file(source_handle, deadline(), &AtomicBool::new(true)),
                Err(PipeError::Cancelled)
            )),
            "expired" => assert!(matches!(
                connection.receive_source_file(source_handle, Instant::now(), &active),
                Err(PipeError::TimedOut)
            )),
            _ => unreachable!(),
        }
        if case != "valid" {
            assert!(matches!(
                connection.receive_source_file(source_handle, deadline(), &active),
                Err(PipeError::Closed)
            ));
            assert!(matches!(
                connection.write_frame(b"after error", deadline(), &active),
                Err(PipeError::Closed)
            ));
            assert!(matches!(
                connection.read_frame(deadline(), &active),
                Err(PipeError::Closed)
            ));
        }
        drop(connection);
        child
            .0
            .stdin
            .take()
            .ok_or("missing fixture stdin")?
            .write_all(&[0x5a])?;
        let exit_deadline = deadline();
        loop {
            if let Some(status) = child.0.try_wait()? {
                assert!(status.success(), "source pipe child failed: {case}");
                break;
            }
            if Instant::now() >= exit_deadline {
                return Err("source pipe child exit timed out".into());
            }
            thread::sleep(Duration::from_millis(10));
        }
        if let Some(mut file) = retained {
            file.rewind()?;
            let mut actual = Vec::new();
            file.read_to_end(&mut actual)?;
            assert_eq!(
                actual, bytes,
                "received file did not outlive the child/connection"
            );
        }
    }
    assert_eq!(
        std::fs::read(path)?,
        bytes,
        "source transfer modified the fixture"
    );
    println!(
        "Windows pipe source transfer passed: framed_handle=1 retained_child=1 sha256=1 readonly=1 wrong_handle=1 closed_handle=1 cancellation=1 deadline=1 poisoned=1; no UAC or devices"
    );
    Ok(())
}
