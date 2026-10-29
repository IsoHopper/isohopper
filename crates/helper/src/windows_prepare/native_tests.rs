// SPDX-License-Identifier: GPL-3.0-or-later
//! Real preparation framing and source transfer, without preparation authority.
use super::{Wire, caller};
use crate::{
    prepare_protocol::{
        ClientFrame, ClientMessage, Outcome, Phase, ServerFrame, ServerMessage, VERSION,
    },
    windows_pipe::{Connection, Server, connect},
    windows_prepare::coordinator::{self, Executor, Inputs, JobFailure, Ready},
    windows_probe::current_peer,
};
use isohopper_core::engine;
use std::{
    fs::{File, OpenOptions},
    io::{Seek, SeekFrom, Write},
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        DELETE, FILE_FLAG_SEQUENTIAL_SCAN, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        ReOpenFile,
    },
    System::Threading::GetCurrentProcessId,
};

struct NoPreparation(Arc<AtomicBool>);
impl Executor for NoPreparation {
    type Ready = ();

    fn prepare(
        self,
        _: Inputs,
        _: &AtomicBool,
        _: &SyncSender<ServerMessage>,
    ) -> Result<Ready<Self::Ready>, JobFailure> {
        self.0.store(true, Ordering::Release);
        Err(JobFailure::failed(
            Phase::CheckingTarget,
            "Cancellation must prevent preparation",
        ))
    }

    fn write(
        _: Self::Ready,
        _: crate::raw_image_job::ConfirmationReceipt,
        _: &AtomicBool,
        _: &SyncSender<ServerMessage>,
    ) -> Result<crate::writer::Report, JobFailure> {
        panic!("The fixture cannot authorize writing")
    }
}

fn receive(connection: &mut Connection, sequence: u64, deadline: Instant) -> ServerFrame {
    let bytes = connection
        .read_frame(deadline, &AtomicBool::new(false))
        .unwrap()
        .expect("helper closed before the expected response");
    let frame = ServerFrame::decode(&bytes).unwrap();
    assert_eq!(frame.version, VERSION);
    assert_eq!(frame.job_id, "a3".repeat(32));
    assert_eq!(frame.sequence, sequence);
    frame
}

fn reply(connection: &mut Connection, frame: &ServerFrame, body: ClientMessage, deadline: Instant) {
    let reply = ClientFrame {
        version: VERSION,
        job_id: frame.job_id.clone(),
        reply_to: frame.sequence,
        body,
    };
    connection
        .write_frame(&reply.encode().unwrap(), deadline, &AtomicBool::new(false))
        .unwrap();
}

// This only requests a handle. It never renames or deletes the temporary file.
fn deletion_open(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(DELETE)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
}

#[test]
#[ignore = "real local pipe and retained temporary file only; no UAC, installed binaries, or devices"]
fn native_empty_preparation_transfers_archive_and_cancels_before_execution() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-engine-archive.tar.gz");
    {
        let mut writer = File::create(&path).unwrap();
        writer.write_all(b"synthetic transfer fixture").unwrap();
        writer
            .set_len(engine::archive::ARCHIVE_BYTES as u64)
            .unwrap();
    }
    // Match Studio's retained source: ReOpenFile, GENERIC_READ, sequential I/O,
    // read/delete sharing. Its bytes are deliberately synthetic; cancellation
    // occurs before the executor can verify or import an archive.
    let original = File::open(&path).unwrap();
    // SAFETY: original owns the live temporary file; no pointer output or
    // asynchronous operation is involved, and the new handle is read-only.
    let raw = unsafe {
        ReOpenFile(
            original.as_raw_handle(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_DELETE,
            FILE_FLAG_SEQUENTIAL_SCAN,
        )
    };
    assert_ne!(
        raw,
        INVALID_HANDLE_VALUE,
        "{}",
        std::io::Error::last_os_error()
    );
    // SAFETY: successful ReOpenFile returned this new owned file handle.
    let mut archive = unsafe { File::from_raw_handle(raw) };
    drop(original);
    archive.seek(SeekFrom::Start(7)).unwrap();
    drop(deletion_open(&path).expect("Studio's source permits delete sharing"));

    let listener = Server::create().unwrap();
    let endpoint = listener.endpoint().clone();
    let deadline = Instant::now() + Duration::from_secs(30);
    let executed = Arc::new(AtomicBool::new(false));
    let worker_executed = executed.clone();
    let pid = unsafe { GetCurrentProcessId() };
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let connection = connect(&endpoint, caller(pid)?, deadline, &AtomicBool::new(false))
                .map_err(|error| error.to_string())?;
            let mut wire = Wire {
                connection,
                local: current_peer().map_err(|error| error.to_string())?,
                job: "a3".repeat(32),
                sequence: 0,
                io_cancel: AtomicBool::new(false),
            };
            coordinator::run(&mut wire, NoPreparation(worker_executed))
        });
        let mut connection = listener
            .accept(current_peer().unwrap(), deadline, &AtomicBool::new(false))
            .unwrap();
        let frame = receive(&mut connection, 0, deadline);
        assert_eq!(frame.body, ServerMessage::Hello);
        reply(
            &mut connection,
            &frame,
            ClientMessage::Begin {
                target_selector: "fixture-must-never-open-a-target".into(),
                source_count: 0,
            },
            deadline,
        );
        let frame = receive(&mut connection, 1, deadline);
        assert_eq!(frame.body, ServerMessage::NeedArchive);
        reply(
            &mut connection,
            &frame,
            ClientMessage::Archive {
                remote_handle: archive.as_raw_handle() as usize as u64,
                bytes: engine::archive::ARCHIVE_BYTES as u64,
                sha256: engine::archive::ARCHIVE_SHA256.into(),
            },
            deadline,
        );
        let frame = receive(&mut connection, 2, deadline);
        assert_eq!(frame.body, ServerMessage::InputsReady);
        assert_eq!(archive.stream_position().unwrap(), 7);
        assert_eq!(
            deletion_open(&path).unwrap_err().raw_os_error(),
            Some(32),
            "the helper must retain an independently opened source denying delete sharing"
        );
        reply(&mut connection, &frame, ClientMessage::Cancel, deadline);
        let frame = receive(&mut connection, 3, deadline);
        assert!(matches!(
            frame.body,
            ServerMessage::Terminal {
                outcome: Outcome::Cancelled,
                phase: Phase::Receiving,
                bytes_written: 0,
                bytes_verified: 0,
                target_may_be_incomplete: false,
                sha256: None,
                ..
            }
        ));
        drop(deletion_open(&path).expect("cancellation must release the helper's source"));
        reply(&mut connection, &frame, ClientMessage::FinishAck, deadline);
        drop(connection);
        worker.join().unwrap().unwrap();
    });
    assert!(!executed.load(Ordering::Acquire));
    assert_eq!(archive.stream_position().unwrap(), 7);
    println!(
        "EMPTY_PREPARATION_IPC archive transferred; zero source requests; cancelled terminal received; executor not called; no UAC or device access"
    );
}

#[test]
#[ignore = "real local pipe and invalid event handle only; no UAC, installed binaries, or devices"]
fn native_empty_preparation_reports_rejected_archive_without_execution() {
    use std::{os::windows::io::OwnedHandle, ptr};
    use windows_sys::Win32::System::Threading::CreateEventW;
    // A retained event is a valid kernel handle but can never be a source file.
    let raw = unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) };
    assert!(!raw.is_null());
    let event = unsafe { OwnedHandle::from_raw_handle(raw) };
    let listener = Server::create().unwrap();
    let endpoint = listener.endpoint().clone();
    let deadline = Instant::now() + Duration::from_secs(30);
    let executed = Arc::new(AtomicBool::new(false));
    let worker_executed = executed.clone();
    let pid = unsafe { GetCurrentProcessId() };
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            let connection = connect(&endpoint, caller(pid)?, deadline, &AtomicBool::new(false))
                .map_err(|error| error.to_string())?;
            let mut wire = Wire {
                connection,
                local: current_peer().map_err(|error| error.to_string())?,
                job: "a3".repeat(32),
                sequence: 0,
                io_cancel: AtomicBool::new(false),
            };
            coordinator::run(&mut wire, NoPreparation(worker_executed))
        });
        let mut connection = listener
            .accept(current_peer().unwrap(), deadline, &AtomicBool::new(false))
            .unwrap();
        let frame = receive(&mut connection, 0, deadline);
        assert_eq!(frame.body, ServerMessage::Hello);
        reply(
            &mut connection,
            &frame,
            ClientMessage::Begin {
                target_selector: "fixture-must-never-open-a-target".into(),
                source_count: 0,
            },
            deadline,
        );
        let frame = receive(&mut connection, 1, deadline);
        assert_eq!(frame.body, ServerMessage::NeedArchive);
        reply(
            &mut connection,
            &frame,
            ClientMessage::Archive {
                remote_handle: event.as_raw_handle() as usize as u64,
                bytes: engine::archive::ARCHIVE_BYTES as u64,
                sha256: engine::archive::ARCHIVE_SHA256.into(),
            },
            deadline,
        );
        let frame = receive(&mut connection, 2, deadline);
        assert!(matches!(&frame.body, ServerMessage::Terminal {
            outcome: Outcome::Failed, phase: Phase::Receiving, message,
            bytes_written: 0, bytes_verified: 0, target_may_be_incomplete: false, sha256: None,
        } if message.contains("source")));
        reply(&mut connection, &frame, ClientMessage::FinishAck, deadline);
        drop(connection);
        worker.join().unwrap().unwrap();
    });
    assert!(!executed.load(Ordering::Acquire));
    println!(
        "EMPTY_PREPARATION_IPC rejected archive reported; executor not called; no UAC or device access"
    );
}
