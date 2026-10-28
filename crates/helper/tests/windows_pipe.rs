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
#[ignore = "disposable local pipe and own child only; no UAC or device access"]
fn windows_pipe_checks_peers_deadlines_and_frames() -> Result<(), Box<dyn std::error::Error>> {
    use isohopper_helper::{
        framing::MAX_FRAME_BYTES,
        windows_peer::ProcessPeer,
        windows_pipe::{Connection, PipeError, Server, connect},
    };
    use std::{
        io::Write,
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
        "Windows pipe transport passed: roundtrip=1 immediate_io=1 clean_eof=1 first_instance=1 wrong_peer=1 connect_timeout=1 connect_cancel=1 read_timeout=1 read_cancel=1 write_timeout=1 partial_header_timeout=1; no UAC or device access"
    );
    Ok(())
}
