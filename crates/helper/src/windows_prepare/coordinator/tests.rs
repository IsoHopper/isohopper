// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    raw_image_job::{BootArtifactFingerprint, ImageFingerprint, RawImageDescription},
    writer::{DeviceSnapshot, Geometry},
};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

struct Wire {
    replies: VecDeque<ClientMessage>,
    events: Arc<Mutex<Vec<&'static str>>>,
    fail_progress: Option<Phase>,
    cancel_progress: Option<Phase>,
    terminal: Option<ServerMessage>,
}
impl Transport for Wire {
    fn exchange(&mut self, body: ServerMessage) -> Result<ClientMessage, String> {
        if matches!(body, ServerMessage::Terminal { .. }) {
            self.terminal = Some(body.clone());
        }
        match body {
            ServerMessage::Progress { phase, .. } => {
                if self.fail_progress == Some(phase) {
                    Err("lost connection".into())
                } else if self.cancel_progress == Some(phase) {
                    Ok(ClientMessage::Cancel)
                } else {
                    Ok(ClientMessage::Continue)
                }
            }
            ServerMessage::Prepared { .. } => {
                self.events.lock().unwrap().push("prepared");
                Ok(self.replies.pop_front().unwrap())
            }
            ServerMessage::Terminal { outcome, .. } => {
                self.events.lock().unwrap().push(match outcome {
                    Outcome::Succeeded => "success",
                    Outcome::Cancelled => "cancelled",
                    Outcome::Failed => "failed",
                });
                Ok(ClientMessage::FinishAck)
            }
            _ => Ok(self.replies.pop_front().unwrap()),
        }
    }
    fn receive(&mut self, _: u64) -> Result<std::fs::File, String> {
        Ok(tempfile::tempfile().unwrap())
    }
    fn finish(&mut self) -> Result<(), String> {
        Ok(())
    }
}
fn description() -> PreparedRawImage {
    PreparedRawImage::new(RawImageDescription {
        target: DeviceSnapshot {
            device_number: 3,
            serial: "SERIAL".into(),
            device_id: None,
            bus_type: 7,
            geometry: Geometry {
                size_bytes: 1 << 20,
                logical_sector_size: 512,
                physical_sector_size: 4096,
            },
        },
        image: ImageFingerprint {
            bytes: 1 << 20,
            sha256: [2; 32],
        },
        boot_artifacts: vec![BootArtifactFingerprint {
            role: "fixture".into(),
            version: None,
            bytes: 1,
            sha256: [3; 32],
        }],
    })
    .unwrap()
}
struct Backend {
    events: Arc<Mutex<Vec<&'static str>>>,
    wait_cancel: bool,
    source_count: usize,
}
impl Executor for Backend {
    type Ready = Arc<Mutex<Vec<&'static str>>>;
    fn prepare(
        self,
        inputs: Inputs,
        cancel: &AtomicBool,
        _: &SyncSender<ServerMessage>,
    ) -> Result<Ready<Self::Ready>, JobFailure> {
        assert_eq!(inputs.selector, "selector");
        assert_eq!(inputs.sources.len(), self.source_count);
        assert!(inputs.archive.metadata().unwrap().is_file());
        drop(inputs);
        if self.wait_cancel {
            while !cancel.load(Ordering::Acquire) {
                thread::sleep(Duration::from_millis(1));
            }
            self.events.lock().unwrap().push("worker_finished");
            return Err(JobFailure::cancelled(Phase::BuildingSeed));
        }
        self.events.lock().unwrap().push("staged");
        Ok(Ready {
            value: self.events,
            description: description(),
        })
    }
    fn write(
        value: Self::Ready,
        _: ConfirmationReceipt,
        _: &AtomicBool,
        _: &SyncSender<ServerMessage>,
    ) -> Result<crate::writer::Report, JobFailure> {
        value.lock().unwrap().push("write");
        Ok(crate::writer::Report {
            bytes_written: 1 << 20,
            bytes_verified: 1 << 20,
            sha256: [2; 32],
        })
    }
}
fn wire(events: Arc<Mutex<Vec<&'static str>>>, last: Vec<ClientMessage>) -> Wire {
    let mut replies = VecDeque::from(vec![
        ClientMessage::Begin {
            target_selector: "selector".into(),
            source_count: 1,
        },
        ClientMessage::Archive {
            remote_handle: 4,
            bytes: isohopper_core::engine::archive::ARCHIVE_BYTES as u64,
            sha256: isohopper_core::engine::archive::ARCHIVE_SHA256.into(),
        },
        ClientMessage::Source {
            index: 0,
            source_id: "id".into(),
            relative_path: "Linux/boot.iso".into(),
            bytes: 512,
            sha256: hex::encode([1; 32]),
            remote_handle: 5,
        },
        ClientMessage::SourcesComplete,
    ]);
    replies.extend(last);
    Wire {
        replies,
        events,
        fail_progress: None,
        cancel_progress: None,
        terminal: None,
    }
}
#[test]
fn release_and_exact_confirmation_precede_write() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let d = description();
    let mut wire = wire(
        events.clone(),
        vec![
            ClientMessage::SourcesReleased,
            ClientMessage::Confirm {
                description_digest: hex::encode(d.digest()),
                challenge: d.challenge().into(),
            },
        ],
    );
    run(
        &mut wire,
        Backend {
            events: events.clone(),
            source_count: 1,
            wait_cancel: false,
        },
    )
    .unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        ["staged", "prepared", "write", "success"]
    );
}
#[test]
fn missing_release_or_changed_confirmation_never_writes() {
    for replies in [
        vec![ClientMessage::Confirm {
            description_digest: hex::encode(description().digest()),
            challenge: "WIPE SERIAL".into(),
        }],
        vec![
            ClientMessage::SourcesReleased,
            ClientMessage::Confirm {
                description_digest: hex::encode([9; 32]),
                challenge: "WIPE SERIAL".into(),
            },
        ],
        vec![
            ClientMessage::SourcesReleased,
            ClientMessage::Confirm {
                description_digest: hex::encode(description().digest()),
                challenge: "WIPE RIAL".into(),
            },
        ],
        vec![ClientMessage::Cancel],
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut wire = wire(events.clone(), replies);
        let _ = run(
            &mut wire,
            Backend {
                events: events.clone(),
                source_count: 1,
                wait_cancel: false,
            },
        );
        assert!(!events.lock().unwrap().contains(&"write"));
    }
}
#[test]
fn disconnected_pipe_cancels_and_joins_worker_before_return() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut wire = wire(events.clone(), vec![]);
    wire.fail_progress = Some(Phase::CheckingTarget);
    assert!(
        run(
            &mut wire,
            Backend {
                events: events.clone(),
                source_count: 1,
                wait_cancel: true
            }
        )
        .is_err()
    );
    assert!(events.lock().unwrap().contains(&"worker_finished"));
}

struct WaitingWrite(Backend);
impl Executor for WaitingWrite {
    type Ready = Arc<Mutex<Vec<&'static str>>>;
    fn prepare(
        self,
        inputs: Inputs,
        cancel: &AtomicBool,
        progress: &SyncSender<ServerMessage>,
    ) -> Result<Ready<Self::Ready>, JobFailure> {
        self.0.prepare(inputs, cancel, progress)
    }
    fn write(
        events: Self::Ready,
        _: ConfirmationReceipt,
        cancel: &AtomicBool,
        _: &SyncSender<ServerMessage>,
    ) -> Result<crate::writer::Report, JobFailure> {
        events.lock().unwrap().push("write_started");
        while !cancel.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(1));
        }
        events.lock().unwrap().push("write_finished");
        Err(JobFailure {
            outcome: Outcome::Cancelled,
            phase: Phase::WritingTarget,
            message: "Cancelled after partial write".into(),
            bytes_written: 512,
            target_may_be_incomplete: true,
        })
    }
}

#[test]
fn cancellation_waits_for_write_cleanup_and_preserves_incomplete_counts() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let d = description();
    let mut wire = wire(
        events.clone(),
        vec![
            ClientMessage::SourcesReleased,
            ClientMessage::Confirm {
                description_digest: hex::encode(d.digest()),
                challenge: d.challenge().into(),
            },
        ],
    );
    wire.cancel_progress = Some(Phase::CheckingReadiness);
    run(
        &mut wire,
        WaitingWrite(Backend {
            events: events.clone(),
            source_count: 1,
            wait_cancel: false,
        }),
    )
    .unwrap();
    assert_eq!(
        *events.lock().unwrap(),
        [
            "staged",
            "prepared",
            "write_started",
            "write_finished",
            "cancelled"
        ]
    );
    assert!(matches!(
        wire.terminal,
        Some(ServerMessage::Terminal {
            outcome: Outcome::Cancelled,
            bytes_written: 512,
            bytes_verified: 0,
            target_may_be_incomplete: true,
            ..
        })
    ));
}

#[test]
fn losing_pipe_after_confirmation_joins_the_writer_before_return() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let d = description();
    let mut wire = wire(
        events.clone(),
        vec![
            ClientMessage::SourcesReleased,
            ClientMessage::Confirm {
                description_digest: hex::encode(d.digest()),
                challenge: d.challenge().into(),
            },
        ],
    );
    wire.fail_progress = Some(Phase::CheckingReadiness);
    assert!(
        run(
            &mut wire,
            WaitingWrite(Backend {
                events: events.clone(),
                source_count: 1,
                wait_cancel: false
            })
        )
        .is_err()
    );
    assert!(events.lock().unwrap().contains(&"write_finished"));
    assert!(wire.terminal.is_none());
}

#[test]
fn empty_media_still_requires_release_and_exact_confirmation_before_write() {
    for confirm in [false, true] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let d = description();
        let last = if confirm {
            vec![
                ClientMessage::SourcesReleased,
                ClientMessage::Confirm {
                    description_digest: hex::encode(d.digest()),
                    challenge: d.challenge().into(),
                },
            ]
        } else {
            vec![ClientMessage::Cancel]
        };
        let mut wire = wire(events.clone(), last);
        wire.replies[0] = ClientMessage::Begin {
            target_selector: "selector".into(),
            source_count: 0,
        };
        wire.replies.remove(2); // No source handle is requested or transferred.
        run(
            &mut wire,
            Backend {
                events: events.clone(),
                wait_cancel: false,
                source_count: 0,
            },
        )
        .unwrap();
        assert_eq!(events.lock().unwrap().contains(&"write"), confirm);
        assert!(
            matches!(
                wire.terminal,
                Some(ServerMessage::Terminal {
                    outcome: Outcome::Succeeded,
                    ..
                })
            ) == confirm
        );
    }
}
