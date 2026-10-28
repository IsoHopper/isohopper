// SPDX-License-Identifier: GPL-3.0-or-later
//! One native-owned session. The renderer supplies opaque selections only.
use super::{ACTIVE, Job, Snapshot, inputs::Inputs, jobs, protocol::ClientSession, targets};
use crate::elevation::{Launched, launch_preparation};
use isohopper_helper::prepare_protocol::{ClientMessage, Outcome, ServerFrame, ServerMessage};
use std::{
    fs::File,
    os::windows::io::AsRawHandle,
    path::{Path, PathBuf},
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

struct ActiveGuard {
    _native: crate::NativeJob,
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.store(false, Ordering::Release);
    }
}

pub fn start(
    native: crate::NativeJob,
    owner: std::sync::mpsc::Receiver<Result<usize, String>>,
    directory: PathBuf,
    target_token: String,
    source_ids: Vec<String>,
    archive_token: String,
) -> Result<Snapshot, String> {
    let target = targets::resolve(&target_token)?;
    let inputs = Inputs::lease(source_ids, archive_token)?;
    let job = Arc::new(Job::new(targets::token()?));
    let snapshot = job.snapshot()?;
    *jobs()
        .lock()
        .map_err(|_| "Preparation state is unavailable")? = Some(Arc::clone(&job));
    ACTIVE.store(true, Ordering::Release);
    let guard = ActiveGuard { _native: native };
    let thread_job = Arc::clone(&job);
    std::thread::Builder::new()
        .name("preparation".into())
        .spawn(move || {
            let _guard = guard;
            let job = thread_job;
            let result = owner
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| "Could not obtain Studio owner window".to_string())
                .and_then(|r| r)
                .and_then(|owner| run(&job, inputs, &target, owner, &directory));
            let _ = job.finish(result);
        })
        .map_err(|e| {
            let _ = job.update(|s| {
                s.active = false;
                s.phase = "failed".into();
                s.message = "Preparation thread could not start".into();
            });
            e.to_string()
        })?;
    Ok(snapshot)
}

struct Channel {
    launched: Launched,
    protocol: ClientSession,
    current: Option<ServerFrame>,
    terminal_received: bool,
}
impl Channel {
    fn receive(&mut self, job: &Job) -> Result<(), String> {
        self.launched
            .local
            .revalidate()
            .map_err(|e| e.to_string())?;
        let bytes = self
            .launched
            .connection
            .as_mut()
            .ok_or("Helper connection is closed")?
            .read_frame(Instant::now() + Duration::from_secs(30), &job.abort)
            .map_err(|e| e.to_string())?
            .ok_or("Helper closed before a terminal response")?;
        let frame = ServerFrame::decode(&bytes).map_err(|e| e.to_string())?;
        self.protocol.accept(&frame)?;
        self.current = Some(frame);
        Ok(())
    }
    fn finish_terminal(&mut self, job: &Job) -> Result<(), String> {
        let ServerMessage::Terminal {
            outcome,
            message,
            bytes_written,
            bytes_verified,
            target_may_be_incomplete,
            sha256,
            ..
        } = self.body()?.clone()
        else {
            return Err("Missing terminal response".into());
        };
        job.update(|s| {
            s.phase = match outcome {
                Outcome::Succeeded => "succeeded",
                Outcome::Cancelled => "cancelled",
                Outcome::Failed => "failed",
            }
            .into();
            s.message = message;
            s.bytes_written = bytes_written;
            s.bytes_verified = bytes_verified;
            s.target_may_be_incomplete = target_may_be_incomplete;
            if sha256.is_some() {
                s.image_sha256 = sha256;
            }
        })?;
        self.reply(job, ClientMessage::FinishAck)?;
        self.terminal_received = true;
        Ok(())
    }
    fn body(&self) -> Result<&ServerMessage, String> {
        self.current
            .as_ref()
            .map(|f| &f.body)
            .ok_or("Missing helper request".into())
    }
    fn reply(&mut self, job: &Job, body: ClientMessage) -> Result<(), String> {
        let frame = self.current.take().ok_or("Missing helper request")?;
        let response = self.protocol.reply(&frame, body)?;
        // Mark uncertainty before attempting to send confirmation: a failed
        // write cannot prove that the helper received none of this frame.
        job.note_reply(&response.body)?;
        self.launched
            .local
            .revalidate()
            .map_err(|e| e.to_string())?;
        self.launched
            .connection
            .as_mut()
            .ok_or("Helper connection is closed")?
            .write_frame(
                &response.encode().map_err(|e| e.to_string())?,
                Instant::now() + Duration::from_secs(30),
                &job.abort,
            )
            .map_err(|e| e.to_string())
    }
}
fn remote_handle(file: &File) -> Result<u64, String> {
    let value = file.as_raw_handle() as usize as u64;
    if value == 0 || value > u32::MAX as u64 {
        return Err("Source handle cannot be transferred".into());
    }
    Ok(value)
}
fn cancelled(job: &Job) -> Result<bool, String> {
    Ok(job.snapshot()?.cancel_requested)
}
fn expected(
    channel: &mut Channel,
    job: &Job,
    check: impl FnOnce(&ServerMessage) -> bool,
) -> Result<(), String> {
    let body = channel.body()?;
    if check(body) {
        return Ok(());
    }
    if matches!(body, ServerMessage::Terminal { .. }) {
        channel.finish_terminal(job)?;
        return Err("Helper finished before all sources were transferred".into());
    }
    Err("Unexpected helper request during source transfer".into())
}

fn run(
    job: &Job,
    mut inputs: Inputs,
    target: &str,
    owner: usize,
    directory: &Path,
) -> Result<(), String> {
    let mut channel: Option<Channel> = None;
    let result = (|| {
        let count = u16::try_from(inputs.source_ids.len()).map_err(|_| "Too many source files")?;
        let mut index = 0_u16;
        job.transfer_inputs(
            inputs.sources.as_ref().ok_or("Missing source batch")?,
            inputs.archive.as_ref().ok_or("Missing engine archive")?,
            &mut channel,
            |channel, archive, metadata| {
                if cancelled(job)? {
                    return Err("Preparation cancelled before staging".into());
                }
                job.update(|s| {
                    s.phase = "requesting_elevation".into();
                    s.message = "Waiting for the Windows elevation dialog.".into();
                })?;
                let launched =
                    launch_preparation(owner, directory, env!("ISOHOPPER_HELPER_SHA256"))?
                        .ok_or("Windows elevation was cancelled")?;
                *channel = Some(Channel {
                    launched,
                    protocol: ClientSession::new(count),
                    current: None,
                    terminal_received: false,
                });
                let connection = channel.as_mut().ok_or("Missing helper channel")?;
                connection.receive(job)?;
                expected(connection, job, |v| matches!(v, ServerMessage::Hello))?;
                connection.reply(
                    job,
                    ClientMessage::Begin {
                        target_selector: target.into(),
                        source_count: count,
                    },
                )?;
                connection.receive(job)?;
                expected(connection, job, |v| matches!(v, ServerMessage::NeedArchive))?;
                connection.reply(
                    job,
                    ClientMessage::Archive {
                        remote_handle: remote_handle(archive)?,
                        bytes: metadata.bytes,
                        sha256: metadata.verification.digest.clone(),
                    },
                )?;
                connection.receive(job)
            },
            |connection, file, info| {
                if cancelled(job)? {
                    return Err("Preparation cancelled before staging".into());
                }
                expected(connection, job, |v| {
                    matches!(v, ServerMessage::NeedSource { index: requested } if *requested == index)
                })?;
                connection.reply(
                    job,
                    ClientMessage::Source {
                        index,
                        source_id: info.source_id.clone(),
                        relative_path: info.relative_path.clone(),
                        bytes: info.bytes,
                        sha256: info.verification.digest.clone(),
                        remote_handle: remote_handle(file)?,
                    },
                )?;
                index += 1;
                connection.receive(job)
            },
        )?;
        let connection = channel.as_mut().ok_or("Missing helper channel")?;
        expected(connection, job, |v| matches!(v, ServerMessage::InputsReady))?;
        connection.reply(
            job,
            if cancelled(job)? {
                ClientMessage::Cancel
            } else {
                ClientMessage::SourcesComplete
            },
        )?;
        loop {
            connection.receive(job)?;
            let body = connection.body()?.clone();
            let response = match body {
                ServerMessage::Progress {
                    phase,
                    completed_bytes,
                    total_bytes,
                    ..
                } => {
                    let phase = serde_json::to_value(phase)
                        .map_err(|e| e.to_string())?
                        .as_str()
                        .ok_or("Invalid phase")?
                        .to_owned();
                    job.update(|s| {
                        s.phase = phase.clone();
                        s.message = if s.cancel_requested {
                            "Cancellation requested; waiting for safe helper cleanup.".into()
                        } else {
                            format!("Helper: {}", phase.replace('_', " "))
                        };
                        s.completed_bytes = completed_bytes;
                        s.total_bytes = total_bytes;
                    })?;
                    if cancelled(job)? {
                        ClientMessage::Cancel
                    } else {
                        ClientMessage::Continue
                    }
                }
                ServerMessage::Prepared {
                    target,
                    image_bytes,
                    image_sha256,
                    description_digest,
                    challenge,
                    ..
                } => {
                    if cancelled(job)? {
                        ClientMessage::Cancel
                    } else {
                        inputs.release_after_seal()?;
                        job.update(|s| {
                            s.phase = "sealed".into();
                            s.message =
                                "Staged image verified. Original source handles released.".into();
                            s.sources_released = true;
                            s.target = serde_json::to_value(target).ok();
                            s.image_sha256 = Some(image_sha256);
                            s.description_digest = Some(description_digest);
                            s.challenge = Some(challenge);
                            s.total_bytes = image_bytes;
                        })?;
                        ClientMessage::SourcesReleased
                    }
                }
                ServerMessage::AwaitConfirmation => {
                    job.update(|s| { s.phase = "await_confirmation".into(); s.message = if crate::PHYSICAL_PREPARATION_ENABLED { "Review the exact target and staged image, then type the full challenge to write.".into() } else { "Staged image ready. Physical writing is disabled in this build; cancel to clean up.".into() }; })?;
                    let mut state = job
                        .state
                        .lock()
                        .map_err(|_| "Preparation state is unavailable")?;
                    if state.snapshot.cancel_requested {
                        ClientMessage::Cancel
                    } else if crate::PHYSICAL_PREPARATION_ENABLED {
                        state
                            .confirmation
                            .take()
                            .map_or(ClientMessage::Continue, |v| ClientMessage::Confirm {
                                description_digest: v.digest,
                                challenge: v.challenge,
                            })
                    } else {
                        ClientMessage::Continue
                    }
                }
                ServerMessage::Terminal { .. } => {
                    connection.finish_terminal(job)?;
                    break;
                }
                _ => return Err("Unexpected helper preparation state".into()),
            };
            connection.reply(job, response)?;
        }
        Ok(())
    })();
    // Do not make the UI available for another operation while the helper is
    // still unwinding a formatter/copy/write. No force-kill or early detach.
    if let Some(mut connection) = channel {
        if result.is_err() && !connection.terminal_received {
            let _ =
                job.update(|s| s.message = "Helper session stopped; waiting for cleanup.".into());
        }
        let cleanup = connection.launched.close_and_wait();
        if connection.terminal_received {
            cleanup
        } else {
            result.and(cleanup)
        }
    } else {
        result
    }
}
