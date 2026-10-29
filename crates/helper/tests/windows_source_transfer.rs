// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::windows_peer::PeerError;
#[path = "../src/windows_peer/source/decode.rs"]
mod decode;
use decode::{Backend, Snapshot, remote_handle, snapshot, transfer};
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

fn buffers() -> ([u8; 24], [u8; 40], [u8; 24]) {
    let mut id = [1; 24];
    id[..8].copy_from_slice(&42u64.to_le_bytes());
    let mut basic = [0; 40];
    basic[..8].copy_from_slice(&10i64.to_le_bytes());
    basic[8..16].copy_from_slice(&11i64.to_le_bytes());
    basic[16..24].copy_from_slice(&12i64.to_le_bytes());
    basic[24..32].copy_from_slice(&13i64.to_le_bytes());
    basic[32..36].copy_from_slice(&0x80u32.to_le_bytes());
    let mut standard = [0; 24];
    standard[..8].copy_from_slice(&4096i64.to_le_bytes());
    standard[8..16].copy_from_slice(&100i64.to_le_bytes());
    standard[16..20].copy_from_slice(&1u32.to_le_bytes());
    (id, basic, standard)
}

fn observed() -> Snapshot {
    Snapshot {
        volume: 42,
        id: [1; 16],
        bytes: 100,
        allocated: 4096,
        created: 10,
        written: 12,
        changed: 13,
        attributes: 0x80,
        links: 1,
    }
}

#[test]
fn handle_values_reject_null_pseudo_and_noncanonical_encodings() {
    for invalid in [
        0,
        u64::MAX,
        u64::MAX - 1,
        0xffff_ffff,
        0xffff_fffe,
        0xffff_fffa,
        0x8000_0000,
        1 << 32,
    ] {
        assert!(remote_handle(invalid).is_err(), "accepted {invalid:x}");
    }
    assert_eq!(remote_handle(0x1234).unwrap(), 0x1234);
}

#[test]
fn fixed_metadata_rejects_nonfiles_reparse_pending_delete_and_bad_shapes() {
    let (id, basic, standard) = buffers();
    assert_eq!(snapshot(&id, &basic, &standard).unwrap(), observed());
    assert!(snapshot(&id[..23], &basic, &standard).is_err());
    assert!(snapshot(&id, &basic[..39], &standard).is_err());
    assert!(snapshot(&id, &basic, &standard[..23]).is_err());
    assert!(snapshot(&[0; 25], &basic, &standard).is_err());
    for attribute in [0x10u32, 0x40, 0x400] {
        let mut bad = basic;
        bad[32..36].copy_from_slice(&attribute.to_le_bytes());
        assert!(snapshot(&id, &bad, &standard).is_err());
    }
    for (offset, value) in [(20, 1), (20, 2), (21, 1), (21, 2)] {
        let mut bad = standard;
        bad[offset] = value;
        assert!(snapshot(&id, &basic, &bad).is_err());
    }
    for offset in [0, 8] {
        let mut bad = standard;
        bad[offset..offset + 8].copy_from_slice(&(-1i64).to_le_bytes());
        assert!(snapshot(&id, &basic, &bad).is_err());
    }
    let mut bad = standard;
    bad[16..20].fill(0);
    assert!(snapshot(&id, &basic, &bad).is_err());
    // Reads can alter access time; that field is deliberately not a sentinel.
    let mut access_changed = basic;
    access_changed[8..16].copy_from_slice(&99i64.to_le_bytes());
    assert_eq!(
        snapshot(&id, &access_changed, &standard).unwrap(),
        observed()
    );
}

#[derive(Debug)]
struct Handle {
    name: &'static str,
    events: Rc<RefCell<Vec<String>>>,
}
impl Drop for Handle {
    fn drop(&mut self) {
        self.events.borrow_mut().push(format!("drop {}", self.name));
    }
}

struct Fixture {
    events: Rc<RefCell<Vec<String>>>,
    snapshots: VecDeque<Snapshot>,
    duplicates: usize,
    fail: Option<&'static str>,
}
impl Fixture {
    fn new() -> Self {
        Self {
            events: Rc::default(),
            snapshots: VecDeque::from(vec![observed(); 4]),
            duplicates: 0,
            fail: None,
        }
    }
    fn step(&self, name: &str) -> Result<(), PeerError> {
        self.events.borrow_mut().push(name.into());
        if self.fail == Some(name) {
            Err(PeerError::Invalid("injected failure"))
        } else {
            Ok(())
        }
    }
    fn handle(&self, name: &'static str) -> Handle {
        Handle {
            name,
            events: self.events.clone(),
        }
    }
}
impl Backend for Fixture {
    type Handle = Handle;
    fn peer(&mut self) -> Result<(), PeerError> {
        self.step(if self.duplicates == 0 {
            "peer before"
        } else {
            "peer after"
        })
    }
    fn duplicate(&mut self, remote: usize) -> Result<Handle, PeerError> {
        assert_eq!(remote, 0x1234);
        self.duplicates += 1;
        let name = if self.duplicates == 1 {
            "original"
        } else {
            "fresh"
        };
        self.step(name)?;
        Ok(self.handle(name))
    }
    fn snapshot(&mut self, handle: &Handle) -> Result<Snapshot, PeerError> {
        self.step(&format!("snapshot {}", handle.name))?;
        Ok(self.snapshots.pop_front().expect("bounded snapshot calls"))
    }
    fn reopen(&mut self, handle: &Handle) -> Result<Handle, PeerError> {
        assert_eq!(handle.name, "original");
        self.step("reopen")?;
        Ok(self.handle("reopened"))
    }
}

#[test]
fn transfer_brackets_reopen_and_remote_relookup_with_peer_checks_and_releases_duplicates() {
    let mut fixture = Fixture::new();
    let received = transfer(&mut fixture, 0x1234).unwrap();
    assert_eq!(received.name, "reopened");
    assert_eq!(
        *fixture.events.borrow(),
        [
            "peer before",
            "original",
            "snapshot original",
            "reopen",
            "snapshot reopened",
            "snapshot original",
            "fresh",
            "snapshot fresh",
            "peer after",
            "drop fresh",
            "drop original"
        ]
    );
    drop(received);
    assert_eq!(fixture.events.borrow().last().unwrap(), "drop reopened");
}

#[test]
fn any_failed_step_returns_no_file_and_closes_every_created_duplicate() {
    for step in [
        "peer before",
        "original",
        "snapshot original",
        "reopen",
        "snapshot reopened",
        "fresh",
        "snapshot fresh",
        "peer after",
    ] {
        let mut fixture = Fixture::new();
        fixture.fail = Some(step);
        assert!(
            matches!(
                transfer(&mut fixture, 0x1234),
                Err(PeerError::Invalid("injected failure"))
            ),
            "{step}"
        );
        let events = fixture.events.borrow();
        for (created, dropped) in [
            ("original", "drop original"),
            ("reopen", "drop reopened"),
            ("fresh", "drop fresh"),
        ] {
            if events.iter().any(|event| event == created) && step != created {
                assert!(
                    events.iter().any(|event| event == dropped),
                    "{step}: {events:?}"
                );
            }
        }
    }
    let mut fixture = Fixture::new();
    assert!(transfer(&mut fixture, 0).is_err());
    assert!(fixture.events.borrow().is_empty());
}

#[test]
fn source_rejections_are_distinct_from_peer_authentication_failures() {
    for step in ["peer before", "peer after"] {
        let mut fixture = Fixture::new();
        fixture.fail = Some(step);
        assert!(
            decode::transfer_checked(&mut fixture, 0x1234).is_err(),
            "{step}"
        );
    }
    for step in [
        "original",
        "snapshot original",
        "reopen",
        "snapshot reopened",
        "fresh",
        "snapshot fresh",
    ] {
        let mut fixture = Fixture::new();
        fixture.fail = Some(step);
        assert!(
            decode::transfer_checked(&mut fixture, 0x1234)
                .unwrap()
                .is_err(),
            "{step}"
        );
    }
}

#[cfg(windows)]
fn source_bytes() -> Vec<u8> {
    (0..8193).map(|index| (index % 251) as u8).collect()
}

#[cfg(windows)]
#[test]
#[ignore = "internal controlled child for Windows source-handle transfer"]
fn windows_source_child_retains_files() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
        os::windows::{
            fs::OpenOptionsExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
        path::PathBuf,
        ptr,
    };
    use windows_sys::Win32::{
        Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES,
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        },
        System::Threading::CreateEventW,
    };
    if std::env::var_os("ISOHOPPER_SOURCE_TEST_CHILD").as_deref() != Some(std::ffi::OsStr::new("1"))
    {
        return Ok(());
    }
    // Only the parent-created test file is opened. This path is not part of
    // production transfer; the actual API receives retained handle values.
    let path =
        PathBuf::from(std::env::var_os("ISOHOPPER_SOURCE_TEST_FILE").ok_or("missing test file")?);
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let mut source = OpenOptions::new()
        .read(true)
        .share_mode(share)
        .open(&path)?;
    source.seek(SeekFrom::Start(7))?;
    let asynchronous = OpenOptions::new()
        .read(true)
        .share_mode(share)
        .custom_flags(FILE_FLAG_OVERLAPPED)
        .open(&path)?;
    let directory = OpenOptions::new()
        .read(true)
        .share_mode(share)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path.parent().ok_or("test parent")?)?;
    let metadata_only = OpenOptions::new()
        .read(true)
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(share)
        .open(&path)?;
    // SAFETY: unnamed event with default security; no external object opened.
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful CreateEventW returned one new owned kernel handle.
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    let input = std::io::stdin();
    let handles = [
        source.as_raw_handle(),
        asynchronous.as_raw_handle(),
        directory.as_raw_handle(),
        event.as_raw_handle(),
        input.as_raw_handle(),
        metadata_only.as_raw_handle(),
    ];
    for handle in handles {
        std::io::stderr().write_all(&(handle as usize as u64).to_le_bytes())?;
    }
    std::io::stderr().flush()?;
    let mut command = [0];
    input.lock().read_exact(&mut command)?;
    assert_eq!(command, [1]);
    assert_eq!(
        source.stream_position()?,
        7,
        "receiver changed sender cursor"
    );
    let mut byte = [0];
    source.read_exact(&mut byte)?;
    assert_eq!(byte, [7]);
    drop(source);
    std::io::stderr().write_all(&[0xa1])?;
    std::io::stderr().flush()?;
    input.lock().read_exact(&mut command)?;
    assert_eq!(command, [0x5a]);
    Ok(())
}

#[cfg(windows)]
#[test]
#[ignore = "read-only handle transfer from a controlled child with a temporary file; no UAC or device access"]
fn windows_source_transfer_retains_readonly_file_from_owned_child()
-> Result<(), Box<dyn std::error::Error>> {
    use isohopper_helper::windows_peer::ProcessPeer;
    use std::{
        fs::OpenOptions,
        io::{self, Read, Seek, Write},
        os::windows::{
            fs::OpenOptionsExt,
            io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
        },
        process::{Child, ChildStderr, Command, Stdio},
        ptr,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::{
        Foundation::DuplicateHandle,
        Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE},
        System::Threading::{
            GetCurrentProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        },
    };

    struct OwnChild(Child);
    impl Drop for OwnChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn response<const N: usize>(
        mut pipe: ChildStderr,
    ) -> Result<(ChildStderr, [u8; N]), Box<dyn std::error::Error>> {
        let (sender, receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut bytes = [0; N];
            let result = pipe.read_exact(&mut bytes).map(|()| (pipe, bytes));
            let _ = sender.send(result);
        });
        Ok(receiver.recv_timeout(Duration::from_secs(15))??)
    }

    let directory = tempfile::tempdir()?;
    let path = directory.path().join("source.bin");
    let bytes = source_bytes();
    std::fs::write(&path, &bytes)?;
    let mut child = OwnChild(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "windows_source_child_retains_files",
                "--ignored",
                "--nocapture",
            ])
            .env("ISOHOPPER_SOURCE_TEST_CHILD", "1")
            .env("ISOHOPPER_SOURCE_TEST_FILE", &path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut peer = ProcessPeer::from_owned_handle(child.0.as_handle().try_clone_to_owned()?)?;
    let (stderr, encoded) = response::<48>(child.0.stderr.take().ok_or("missing stderr")?)?;
    let handles: Vec<_> = encoded
        .as_chunks::<8>()
        .0
        .iter()
        .map(|part| u64::from_le_bytes(*part))
        .collect();
    for handle in [0, u64::MAX, u64::MAX - 1, 0xffff_ffff] {
        assert!(
            peer.receive_source_file(handle).is_err(),
            "invalid handle passed"
        );
    }
    for &handle in &handles[2..5] {
        assert!(
            peer.receive_source_file(handle).is_err(),
            "non-file handle passed"
        );
    }
    assert!(
        matches!(
            peer.receive_source_file(handles[5]),
            Err(PeerError::Io {
                stage: "duplicate source file",
                ..
            })
        ),
        "metadata-only source must not acquire data-read rights"
    );
    // A retained process with observation rights alone must not acquire the
    // source right by reopening its PID or silently accepting missing access.
    let mut reduced = ptr::null_mut();
    // SAFETY: both process owners are live; the local output is noninheritable
    // and deliberately excludes PROCESS_DUP_HANDLE. No source is closed.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            child.0.as_raw_handle(),
            GetCurrentProcess(),
            &mut reduced,
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    // SAFETY: successful DuplicateHandle returned one new process handle.
    let mut insufficient =
        ProcessPeer::from_owned_handle(unsafe { OwnedHandle::from_raw_handle(reduced) })?;
    assert!(matches!(
        insufficient.receive_source_file(handles[0]),
        Err(PeerError::Io {
            stage: "duplicate source file",
            ..
        })
    ));

    for &handle in &handles[..2] {
        let mut received = peer.receive_source_file(handle)?;
        let mut actual = Vec::new();
        received.read_to_end(&mut actual)?;
        assert_eq!(
            actual, bytes,
            "synchronous receiver must start at offset zero"
        );
        assert!(
            received.write_all(&[0]).is_err(),
            "received file was writable"
        );
        received.rewind()?;
        assert_eq!(received.metadata()?.len(), bytes.len() as u64);
        let blocked = OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .open(&path)
            .unwrap_err();
        assert_eq!(
            blocked.raw_os_error(),
            Some(32),
            "receiver must deny new writer opens"
        );
    }
    // The child checks its original cursor, then closes that original while
    // remaining alive. A subsequent transfer of that value must fail.
    child
        .0
        .stdin
        .as_mut()
        .ok_or("missing stdin")?
        .write_all(&[1])?;
    let (_stderr, acknowledgement) = response::<1>(stderr)?;
    assert_eq!(acknowledgement, [0xa1]);
    assert!(matches!(
        peer.receive_source_file(handles[0]),
        Err(PeerError::Io {
            stage: "duplicate source file",
            ..
        })
    ));
    child
        .0
        .stdin
        .take()
        .ok_or("missing stdin")?
        .write_all(&[0x5a])?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.0.try_wait()? {
            assert!(status.success(), "source test child failed");
            break;
        }
        if Instant::now() >= deadline {
            return Err("source test child timed out".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(matches!(
        peer.receive_source_file(handles[1]),
        Err(PeerError::Exited)
    ));
    assert_eq!(
        std::fs::read(&path)?,
        bytes,
        "transfer changed source contents"
    );
    println!(
        "Windows source transfer passed: owned child, synchronous independent cursor, readonly sharing, invalid/non-file/closed/dead peer refusals; no UAC or devices"
    );
    Ok(())
}

#[test]
fn changed_identity_or_sentinels_at_every_observation_refuse_the_transfer() {
    let changes: [fn(&mut Snapshot); 10] = [
        |s| s.volume += 1,
        |s| s.id[0] ^= 1,
        |s| s.bytes += 1,
        |s| s.allocated += 1,
        |s| s.created += 1,
        |s| s.written += 1,
        |s| s.changed += 1,
        |s| s.attributes ^= 1,
        |s| s.links += 1,
        |s| {
            s.volume += 1;
            s.id[0] ^= 1;
        },
    ];
    for phase in 1..4 {
        for change in changes {
            let mut fixture = Fixture::new();
            change(&mut fixture.snapshots[phase]);
            assert!(transfer(&mut fixture, 0x1234).is_err(), "phase {phase}");
            assert!(
                fixture
                    .events
                    .borrow()
                    .iter()
                    .any(|event| event == "drop reopened")
            );
        }
    }
}
