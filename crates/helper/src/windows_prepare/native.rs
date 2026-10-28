// SPDX-License-Identifier: GPL-3.0-or-later
use super::coordinator::{self, Executor, Inputs, JobFailure, Ready, Transport};
use crate::{
    broker_probe::check_pair,
    prepare_protocol::{
        ClientFrame, ClientMessage, Phase, PrepareArgs, ServerFrame, ServerMessage, VERSION,
        decode_sha256,
    },
    raw_image_job::{
        BootArtifactFingerprint, ConfirmationReceipt, PreparedRawImage, RawImageDescription,
    },
    windows_installation::{InstalledRole, MachineInstallation},
    windows_peer::ProcessPeer,
    windows_pipe::{Connection, Endpoint, connect},
    windows_preparation_target::PreparationTarget,
    windows_stage::{self, TargetBoundStage},
    writer,
};
use isohopper_core::engine;
use std::{
    fs::File,
    io::{self, Read, Seek},
    mem::size_of,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::SyncSender,
    },
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GetLastError, LUID},
    Security::{
        AdjustTokenPrivileges,
        Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
        GetTokenInformation, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation,
    },
    System::Threading::{
        GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_DUP_HANDLE,
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    },
};

fn os_error(operation: &str) -> String {
    format!("{operation}: {}", io::Error::last_os_error())
}
/// Enable the one required privilege before any peer/token snapshot. This
/// process is one-shot and exits after the job; the read-only probe never calls
/// this bootstrap. It cannot grant a privilege absent from the elevated token.
fn bootstrap() -> Result<(), String> {
    let mut raw = ptr::null_mut();
    // SAFETY: own process token only, explicit query/adjust rights.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
            &mut raw,
        )
    } == 0
    {
        return Err(os_error("Open preparation token"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0;
    // SAFETY: fixed SDK-sized output; no variable pointer fields.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(os_error("Read preparation elevation"));
    }
    if returned as usize != size_of::<TOKEN_ELEVATION>() || elevation.TokenIsElevated != 1 {
        return Err("Preparation bootstrap requires elevation".into());
    }
    let name: Vec<_> = "SeManageVolumePrivilege"
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut luid = LUID::default();
    if unsafe { LookupPrivilegeValueW(ptr::null(), name.as_ptr(), &mut luid) } == 0 {
        return Err(os_error("Resolve volume privilege"));
    }
    let desired = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };
    // SAFETY: single fixed privilege and live token; no previous-state buffer.
    // Windows requires GetLastError even after a nonzero return (not-all-assigned).
    if unsafe {
        AdjustTokenPrivileges(
            token.as_raw_handle(),
            0,
            &desired,
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(os_error("Enable volume privilege"));
    }
    let status = unsafe { GetLastError() };
    if status != 0 {
        return Err(format!(
            "Enable volume privilege: {}",
            io::Error::from_raw_os_error(status as i32)
        ));
    }
    Ok(())
}
fn caller(pid: u32) -> Result<ProcessPeer, String> {
    // SAFETY: retain this process object once. Never reopen by PID for transfer.
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE | PROCESS_DUP_HANDLE,
            0,
            pid,
        )
    };
    if raw.is_null() {
        return Err(os_error("Open preparation caller"));
    }
    ProcessPeer::from_owned_handle(unsafe { OwnedHandle::from_raw_handle(raw) })
        .map_err(|e| e.to_string())
}
struct Wire {
    connection: Connection,
    local: ProcessPeer,
    job: String,
    sequence: u64,
    io_cancel: AtomicBool,
}
impl Transport for Wire {
    fn exchange(&mut self, body: ServerMessage) -> Result<ClientMessage, String> {
        let deadline = Instant::now() + Duration::from_secs(30);
        self.local.revalidate().map_err(|e| e.to_string())?;
        let frame = ServerFrame {
            version: VERSION,
            job_id: self.job.clone(),
            sequence: self.sequence,
            body,
        };
        let bytes = frame.encode().map_err(|e| e.to_string())?;
        self.connection
            .write_frame(&bytes, deadline, &self.io_cancel)
            .map_err(|e| e.to_string())?;
        let bytes = self
            .connection
            .read_frame(deadline, &self.io_cancel)
            .map_err(|e| e.to_string())?
            .ok_or("Preparation caller disconnected")?;
        self.local.revalidate().map_err(|e| e.to_string())?;
        let reply = ClientFrame::decode(&bytes).map_err(|e| e.to_string())?;
        frame.validate_reply(&reply).map_err(|e| e.to_string())?;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("Preparation sequence exhausted")?;
        Ok(reply.body)
    }
    fn receive(&mut self, remote: u64) -> Result<File, String> {
        self.local.revalidate().map_err(|e| e.to_string())?;
        let result = self
            .connection
            .receive_source_file(
                remote,
                Instant::now() + Duration::from_secs(30),
                &self.io_cancel,
            )
            .map_err(|e| e.to_string());
        self.local.revalidate().map_err(|e| e.to_string())?;
        result
    }
    fn finish(&mut self) -> Result<(), String> {
        self.local.revalidate().map_err(|e| e.to_string())?;
        if self
            .connection
            .read_frame(Instant::now() + Duration::from_secs(30), &self.io_cancel)
            .map_err(|e| e.to_string())?
            .is_some()
        {
            return Err("Additional preparation request refused".into());
        }
        self.local.revalidate().map_err(|e| e.to_string())?;
        Ok(())
    }
}
pub fn serve(args: PrepareArgs) -> Result<(), String> {
    bootstrap()?;
    let mut local = crate::windows_probe::current_peer().map_err(|e| e.to_string())?;
    let remote = caller(args.studio_pid())?;
    if remote.evidence().creation_time != args.studio_created() {
        return Err("Preparation caller creation time mismatch".into());
    }
    check_pair(remote.evidence(), local.evidence()).map_err(|e| e.to_string())?;
    let installation = Arc::new(MachineInstallation::open()?);
    local = local
        .bind_installation(installation.clone(), InstalledRole::Helper)
        .map_err(|e| e.to_string())?;
    let remote = remote
        .bind_installation(installation.clone(), InstalledRole::Studio)
        .map_err(|e| e.to_string())?;
    let endpoint = Endpoint::from_nonce(args.nonce()).map_err(|e| e.to_string())?;
    let connection = connect(
        &endpoint,
        remote,
        Instant::now() + Duration::from_secs(30),
        &AtomicBool::new(false),
    )
    .map_err(|e| e.to_string())?;
    let mut random = [0u8; 32];
    // SAFETY: fixed writable random output; no handle with system RNG mode.
    if unsafe {
        BCryptGenRandom(
            ptr::null_mut(),
            random.as_mut_ptr(),
            random.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    } < 0
    {
        return Err("Preparation job randomness unavailable".into());
    }
    let mut wire = Wire {
        connection,
        local,
        job: hex::encode(random),
        sequence: 0,
        io_cancel: AtomicBool::new(false),
    };
    coordinator::run(&mut wire, NativeExecutor { installation })
}

struct NativeExecutor {
    installation: Arc<MachineInstallation>,
}
struct NativeReady {
    target: PreparationTarget,
    stage: TargetBoundStage,
}
fn check_cancel(cancel: &AtomicBool, phase: Phase) -> Result<(), JobFailure> {
    if cancel.load(Ordering::Acquire) {
        Err(JobFailure::cancelled(phase))
    } else {
        Ok(())
    }
}
fn failure(phase: Phase, cancel: &AtomicBool, e: impl std::fmt::Display) -> JobFailure {
    if cancel.load(Ordering::Acquire) {
        JobFailure::cancelled(phase)
    } else {
        JobFailure::failed(phase, e)
    }
}
fn emit(
    progress: &SyncSender<ServerMessage>,
    phase: Phase,
    done: u64,
    total: u64,
    index: Option<u16>,
) {
    let _ = progress.try_send(ServerMessage::Progress {
        phase,
        completed_bytes: done,
        total_bytes: total,
        file_index: index,
    });
}
fn archive(mut file: File, cancel: &AtomicBool) -> Result<engine::archive::Imported, JobFailure> {
    let phase = Phase::CheckingSources;
    if file
        .metadata()
        .map_err(|e| failure(phase, cancel, e))?
        .len()
        != engine::archive::ARCHIVE_BYTES as u64
    {
        return Err(JobFailure::failed(phase, "Engine archive length changed"));
    }
    file.rewind().map_err(|e| failure(phase, cancel, e))?;
    let mut bytes = vec![0; engine::archive::ARCHIVE_BYTES];
    for chunk in bytes.chunks_mut(65536) {
        check_cancel(cancel, phase)?;
        file.read_exact(chunk)
            .map_err(|e| failure(phase, cancel, e))?;
    }
    if file.read(&mut [0]).map_err(|e| failure(phase, cancel, e))? != 0 {
        return Err(JobFailure::failed(phase, "Engine archive grew"));
    }
    drop(file);
    check_cancel(cancel, phase)?;
    engine::archive::import(&bytes).map_err(|e| failure(phase, cancel, e))
}
fn provenance() -> Vec<BootArtifactFingerprint> {
    [
        (
            "archive",
            engine::archive::ARCHIVE_BYTES,
            engine::archive::ARCHIVE_SHA256,
        ),
        ("boot", engine::BOOT_BYTES, engine::BOOT_SHA256),
        ("core", engine::CORE_BYTES, engine::CORE_SHA256),
        ("firmware", engine::FIRMWARE_BYTES, engine::FIRMWARE_SHA256),
    ]
    .into_iter()
    .map(|(role, bytes, hash)| BootArtifactFingerprint {
        role: role.into(),
        version: Some(engine::VERSION.into()),
        bytes: bytes as u64,
        sha256: decode_sha256(hash).expect("compiled hash"),
    })
    .collect()
}
impl Executor for NativeExecutor {
    type Ready = NativeReady;
    fn prepare(
        self,
        inputs: Inputs,
        cancel: &AtomicBool,
        progress: &SyncSender<ServerMessage>,
    ) -> Result<Ready<NativeReady>, JobFailure> {
        check_cancel(cancel, Phase::CheckingTarget)?;
        emit(progress, Phase::CheckingTarget, 0, 0, None);
        let target = PreparationTarget::open(self.installation.clone(), &inputs.selector)
            .map_err(|e| failure(Phase::CheckingTarget, cancel, e))?;
        check_cancel(cancel, Phase::CheckingSources)?;
        emit(progress, Phase::CheckingSources, 0, 0, None);
        let imported = archive(inputs.archive, cancel)?;
        let plan = engine::Plan::new(
            target.snapshot().geometry.size_bytes,
            u64::from(target.snapshot().geometry.logical_sector_size),
        )
        .map_err(|e| failure(Phase::BuildingSeed, cancel, e))?;
        let stage = windows_stage::build(
            self.installation,
            &plan,
            &imported.payloads(),
            target.snapshot().geometry.clone(),
            inputs.sources,
            cancel,
            |p| {
                let phase = match p.phase {
                    "building_seed" => Phase::BuildingSeed,
                    "checking_seed" => Phase::CheckingSources,
                    "seeding_vhd" | "flushing_seed" | "seeded" => Phase::WritingSeed,
                    "verifying_seed" => Phase::VerifyingSeed,
                    "formatting_data" => Phase::FormattingData,
                    "checking_source" => Phase::CheckingSources,
                    "copying_data" | "flushing_data" | "copied" => Phase::CopyingSources,
                    "verifying_data" => Phase::VerifyingSources,
                    "exporting_raw" => Phase::ExportingRaw,
                    "sealed" => Phase::Sealed,
                    _ => Phase::BuildingSeed,
                };
                emit(
                    progress,
                    phase,
                    p.completed_bytes,
                    p.total_bytes,
                    p.file_index.and_then(|i| u16::try_from(i).ok()),
                );
            },
        )
        .map_err(|e| failure(Phase::BuildingSeed, cancel, e))?;
        drop(imported);
        check_cancel(cancel, Phase::CheckingReadiness)?;
        let stage = stage
            .bind_target(target.snapshot())
            .map_err(|e| failure(Phase::CheckingReadiness, cancel, e))?;
        let description = PreparedRawImage::new(RawImageDescription {
            target: target.snapshot().clone(),
            image: stage.fingerprint().clone(),
            boot_artifacts: provenance(),
        })
        .map_err(|e| failure(Phase::Sealed, cancel, e))?;
        Ok(Ready {
            value: NativeReady { target, stage },
            description,
        })
    }
    fn write(
        mut value: NativeReady,
        receipt: ConfirmationReceipt,
        cancel: &AtomicBool,
        progress: &SyncSender<ServerMessage>,
    ) -> Result<writer::Report, JobFailure> {
        let approved = receipt.description();
        if value.target.snapshot() != approved.target()
            || value.stage.fingerprint() != approved.image()
        {
            return Err(JobFailure::failed(
                Phase::CheckingReadiness,
                "Confirmed image or target changed",
            ));
        }
        check_cancel(cancel, Phase::CheckingReadiness)?;
        emit(progress, Phase::CheckingReadiness, 0, 0, None);
        value
            .target
            .revalidate_readiness()
            .map_err(|e| failure(Phase::CheckingReadiness, cancel, e))?;
        value
            .stage
            .revalidate_readiness(approved.target())
            .map_err(|e| failure(Phase::CheckingReadiness, cancel, e))?;
        check_cancel(cancel, Phase::LockingTarget)?;
        emit(progress, Phase::LockingTarget, 0, 0, None);
        let mut target = value
            .target
            .into_locked()
            .map_err(|e| failure(Phase::LockingTarget, cancel, e))?;
        check_cancel(cancel, Phase::WritingTarget)?;
        writer::write_image(
            &mut target,
            &mut value.stage,
            approved.target(),
            approved.image().sha256,
            cancel,
            |p| {
                emit(
                    progress,
                    write_phase(p.phase),
                    p.completed_bytes,
                    p.total_bytes,
                    None,
                )
            },
        )
        .map_err(|e| JobFailure {
            outcome: if matches!(e.failure, writer::Failure::Cancelled) {
                crate::prepare_protocol::Outcome::Cancelled
            } else {
                crate::prepare_protocol::Outcome::Failed
            },
            phase: write_phase(e.phase),
            message: e.to_string(),
            bytes_written: e.bytes_written,
            target_may_be_incomplete: e.target_may_be_incomplete,
        })
    }
}
fn write_phase(phase: writer::Phase) -> Phase {
    match phase {
        writer::Phase::CheckingSource => Phase::CheckingSources,
        writer::Phase::Writing => Phase::WritingTarget,
        writer::Phase::Flushing => Phase::FlushingTarget,
        writer::Phase::Verifying => Phase::VerifyingTarget,
        writer::Phase::Complete => Phase::Complete,
    }
}
