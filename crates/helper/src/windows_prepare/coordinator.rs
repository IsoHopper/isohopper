// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{
    prepare_protocol::{
        self as protocol, ClientMessage, Outcome, Phase, ServerMessage, SourceList, TargetSummary,
    },
    raw_image_job::{ConfirmationReceipt, PreparedRawImage},
    windows_stage::StageInput,
};
use std::{
    fs::File,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::Duration,
};

pub(crate) trait Transport {
    fn exchange(&mut self, body: ServerMessage) -> Result<ClientMessage, String>;
    // Outer failure is a broken/authentication-failed transport; inner failure
    // is a rejected source and must produce a terminal report without execution.
    fn receive(&mut self, handle: u64) -> Result<Result<File, String>, String>;
    fn finish(&mut self) -> Result<(), String>;
}
pub(crate) struct Inputs {
    pub selector: String,
    pub archive: File,
    pub sources: Vec<StageInput>,
}
pub(crate) struct Ready<T> {
    pub value: T,
    pub description: PreparedRawImage,
}
pub(crate) trait Executor: Send + 'static {
    type Ready: Send + 'static;
    fn prepare(
        self,
        inputs: Inputs,
        cancel: &AtomicBool,
        progress: &SyncSender<ServerMessage>,
    ) -> Result<Ready<Self::Ready>, JobFailure>;
    fn write(
        value: Self::Ready,
        receipt: ConfirmationReceipt,
        cancel: &AtomicBool,
        progress: &SyncSender<ServerMessage>,
    ) -> Result<crate::writer::Report, JobFailure>;
}
#[derive(Debug)]
pub(crate) struct JobFailure {
    pub outcome: Outcome,
    pub phase: Phase,
    pub message: String,
    pub bytes_written: u64,
    pub target_may_be_incomplete: bool,
}
impl JobFailure {
    pub fn failed(phase: Phase, message: impl std::fmt::Display) -> Self {
        Self {
            outcome: Outcome::Failed,
            phase,
            message: message.to_string(),
            bytes_written: 0,
            target_may_be_incomplete: false,
        }
    }
    pub fn cancelled(phase: Phase) -> Self {
        Self {
            outcome: Outcome::Cancelled,
            phase,
            message: "Cancelled".into(),
            bytes_written: 0,
            target_may_be_incomplete: false,
        }
    }
}
enum RunError {
    Transport(String),
    Failure(JobFailure),
}
impl From<JobFailure> for RunError {
    fn from(value: JobFailure) -> Self {
        Self::Failure(value)
    }
}
fn invalid(message: impl std::fmt::Display) -> RunError {
    JobFailure::failed(Phase::Receiving, message).into()
}
fn ask(transport: &mut impl Transport, body: ServerMessage) -> Result<ClientMessage, RunError> {
    let reply = transport
        .exchange(body.clone())
        .map_err(RunError::Transport)?;
    // Independently preserve the state constraint even for an injected private
    // transport. The native transport additionally checks its real job/sequence.
    let frame = protocol::ServerFrame {
        version: protocol::VERSION,
        job_id: "00".repeat(32),
        sequence: 0,
        body,
    };
    frame
        .validate_reply(&protocol::ClientFrame {
            version: protocol::VERSION,
            job_id: frame.job_id.clone(),
            reply_to: 0,
            body: reply.clone(),
        })
        .map_err(invalid)?;
    Ok(reply)
}
fn active(reply: ClientMessage, phase: Phase) -> Result<ClientMessage, RunError> {
    if reply == ClientMessage::Cancel {
        Err(JobFailure::cancelled(phase).into())
    } else {
        Ok(reply)
    }
}
fn transfer(transport: &mut impl Transport, handle: u64) -> Result<File, RunError> {
    transport
        .receive(handle)
        .map_err(RunError::Transport)?
        .map_err(invalid)
}

struct Joined<R> {
    worker: Option<thread::JoinHandle<Result<R, JobFailure>>>,
    cancel: Arc<AtomicBool>,
}
impl<R> Drop for Joined<R> {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            self.cancel.store(true, Ordering::Release);
            let _ = worker.join();
        }
    }
}
fn work<T: Send + 'static>(
    transport: &mut impl Transport,
    phase: Phase,
    physical: bool,
    cancel: Arc<AtomicBool>,
    action: impl FnOnce(&AtomicBool, &SyncSender<ServerMessage>) -> Result<T, JobFailure>
    + Send
    + 'static,
) -> Result<T, RunError> {
    let (sender, updates) = mpsc::sync_channel(1);
    let flag = cancel.clone();
    let mut joined = Joined {
        worker: Some(thread::spawn(move || action(&flag, &sender))),
        cancel,
    };
    let mut latest = ServerMessage::Progress {
        phase,
        completed_bytes: 0,
        total_bytes: 0,
        file_index: None,
    };
    loop {
        if joined.worker.as_ref().expect("owned worker").is_finished() {
            return joined
                .worker
                .take()
                .expect("owned worker")
                .join()
                .unwrap_or_else(|_| {
                    let mut failure =
                        JobFailure::failed(phase, "Preparation worker failed unexpectedly");
                    failure.target_may_be_incomplete = physical;
                    Err(failure)
                })
                .map_err(RunError::Failure);
        }
        for update in updates.try_iter() {
            latest = update;
        }
        if ask(transport, latest.clone())? == ClientMessage::Cancel {
            joined.cancel.store(true, Ordering::Release);
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn run_job<E: Executor>(
    transport: &mut impl Transport,
    executor: E,
) -> Result<crate::writer::Report, RunError> {
    let ClientMessage::Begin {
        target_selector,
        source_count,
    } = active(ask(transport, ServerMessage::Hello)?, Phase::Receiving)?
    else {
        return Err(invalid("Expected Begin"));
    };
    let ClientMessage::Archive {
        remote_handle,
        bytes: _,
        sha256,
    } = active(
        ask(transport, ServerMessage::NeedArchive)?,
        Phase::Receiving,
    )?
    else {
        return Err(invalid("Expected Archive"));
    };
    if sha256 != isohopper_core::engine::archive::ARCHIVE_SHA256 {
        return Err(invalid("Engine archive pin differs"));
    }
    let archive = transfer(transport, remote_handle)?;
    let mut list = SourceList::new(source_count).map_err(invalid)?;
    let mut sources = Vec::with_capacity(usize::from(source_count));
    for index in 0..source_count {
        let message = active(
            ask(transport, ServerMessage::NeedSource { index })?,
            Phase::Receiving,
        )?;
        list.push(&message).map_err(invalid)?;
        let ClientMessage::Source {
            relative_path,
            bytes,
            sha256,
            remote_handle,
            ..
        } = message
        else {
            return Err(invalid("Expected Source"));
        };
        sources.push(StageInput {
            file: transfer(transport, remote_handle)?,
            entry: isohopper_media::copy::CopyEntry {
                relative_path,
                bytes,
                sha256: protocol::decode_sha256(&sha256).map_err(invalid)?,
            },
        });
    }
    list.finish().map_err(invalid)?;
    active(
        ask(transport, ServerMessage::InputsReady)?,
        Phase::Receiving,
    )?;
    let cancel = Arc::new(AtomicBool::new(false));
    let ready = work(
        transport,
        Phase::CheckingTarget,
        false,
        cancel.clone(),
        move |cancel, progress| {
            executor.prepare(
                Inputs {
                    selector: target_selector,
                    archive,
                    sources,
                },
                cancel,
                progress,
            )
        },
    )?;
    if cancel.load(Ordering::Acquire) {
        return Err(JobFailure::cancelled(Phase::Sealed).into());
    }
    let target = ready.description.target().clone();
    let prepared = ServerMessage::Prepared {
        target: TargetSummary::from(&target),
        image_bytes: ready.description.image().bytes,
        image_sha256: hex::encode(ready.description.image().sha256),
        description_digest: hex::encode(ready.description.digest()),
        challenge: ready.description.challenge().into(),
        source_count,
        original_handles_closed: true,
    };
    let mut pending = ready.description.into_confirmation();
    active(ask(transport, prepared)?, Phase::AwaitingConfirmation)?;
    let receipt = loop {
        match active(
            ask(transport, ServerMessage::AwaitConfirmation)?,
            Phase::AwaitingConfirmation,
        )? {
            ClientMessage::Continue => thread::sleep(Duration::from_millis(250)),
            ClientMessage::Confirm {
                description_digest,
                challenge,
            } => {
                break pending
                    .confirm(
                        &protocol::decode_sha256(&description_digest).map_err(invalid)?,
                        &target,
                        &challenge,
                    )
                    .map_err(|e| JobFailure::failed(Phase::AwaitingConfirmation, e))?;
            }
            _ => return Err(invalid("Expected confirmation")),
        }
    };
    work(
        transport,
        Phase::CheckingReadiness,
        true,
        cancel,
        move |cancel, progress| E::write(ready.value, receipt, cancel, progress),
    )
}

fn bounded_message(text: &str) -> String {
    let mut result = String::new();
    for ch in text.chars().filter(|ch| !ch.is_control()) {
        if result.len() + ch.len_utf8() > 2048 {
            break;
        }
        result.push(ch);
    }
    if result.is_empty() {
        "Preparation failed".into()
    } else {
        result
    }
}
pub(crate) fn run<E: Executor>(transport: &mut impl Transport, executor: E) -> Result<(), String> {
    let terminal = match run_job(transport, executor) {
        Ok(report) => ServerMessage::Terminal {
            outcome: Outcome::Succeeded,
            phase: Phase::Complete,
            message: "Image written and complete device readback SHA-256 verified".into(),
            bytes_written: report.bytes_written,
            bytes_verified: report.bytes_verified,
            target_may_be_incomplete: false,
            sha256: Some(hex::encode(report.sha256)),
        },
        Err(RunError::Failure(f)) => ServerMessage::Terminal {
            outcome: f.outcome,
            phase: f.phase,
            message: bounded_message(&f.message),
            bytes_written: f.bytes_written,
            bytes_verified: 0,
            target_may_be_incomplete: f.target_may_be_incomplete,
            sha256: None,
        },
        Err(RunError::Transport(error)) => return Err(error),
    };
    ask(transport, terminal).map_err(|e| match e {
        RunError::Transport(e) => e,
        RunError::Failure(e) => e.message,
    })?;
    transport.finish()
}

#[cfg(test)]
mod tests;
