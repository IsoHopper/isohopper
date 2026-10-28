// SPDX-License-Identifier: GPL-3.0-or-later
//! Strict client-side progression, independent of native transport.

use isohopper_helper::prepare_protocol::{
    ClientFrame, ClientMessage, Outcome, Phase, ServerFrame, ServerMessage, VERSION,
};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Next {
    Hello,
    Archive,
    Source(u16),
    Inputs,
    Working,
    Confirmation,
    Committed,
    Terminal,
    Closed,
}
pub(super) struct ClientSession {
    job: Option<String>,
    sequence: u64,
    next: Next,
    pending: bool,
    count: u16,
    prepared: Option<(u64, String)>,
    committed: bool,
}
impl ClientSession {
    pub fn new(count: u16) -> Self {
        Self {
            job: None,
            sequence: 0,
            next: Next::Hello,
            pending: false,
            count,
            prepared: None,
            committed: false,
        }
    }
    pub fn accept(&mut self, frame: &ServerFrame) -> Result<(), String> {
        frame.validate().map_err(|e| e.to_string())?;
        if self.pending
            || frame.sequence != self.sequence
            || self.job.as_ref().is_some_and(|id| id != &frame.job_id)
        {
            return Err("Unexpected helper job or sequence".into());
        }
        let okay = match (&frame.body, self.next) {
            (ServerMessage::Hello, Next::Hello)
            | (ServerMessage::NeedArchive, Next::Archive)
            | (ServerMessage::InputsReady, Next::Inputs)
            | (ServerMessage::AwaitConfirmation, Next::Confirmation) => true,
            (ServerMessage::NeedSource { index }, Next::Source(expected)) => *index == expected,
            (ServerMessage::Progress { phase, .. }, Next::Working) => !matches!(
                phase,
                Phase::CheckingReadiness
                    | Phase::LockingTarget
                    | Phase::WritingTarget
                    | Phase::VerifyingTarget
                    | Phase::FlushingTarget
                    | Phase::Complete
            ),
            (ServerMessage::Progress { .. }, Next::Committed | Next::Terminal) => true,
            (ServerMessage::Prepared { source_count, .. }, Next::Working) => {
                *source_count == self.count
            }
            (
                ServerMessage::Terminal {
                    outcome,
                    bytes_written,
                    bytes_verified,
                    sha256,
                    ..
                },
                next,
            ) if next != Next::Closed => {
                if *outcome == Outcome::Succeeded {
                    self.committed
                        && self.prepared.as_ref().is_some_and(|(bytes, hash)| {
                            *bytes_written == *bytes
                                && *bytes_verified == *bytes
                                && sha256.as_ref() == Some(hash)
                        })
                } else {
                    self.committed || (*bytes_written == 0 && *bytes_verified == 0)
                }
            }
            _ => false,
        };
        if !okay {
            return Err("Helper message is invalid for the current preparation state".into());
        }
        self.job.get_or_insert_with(|| frame.job_id.clone());
        self.pending = true;
        Ok(())
    }
    pub fn reply(
        &mut self,
        frame: &ServerFrame,
        body: ClientMessage,
    ) -> Result<ClientFrame, String> {
        if !self.pending
            || frame.sequence != self.sequence
            || self.job.as_ref() != Some(&frame.job_id)
        {
            return Err("No current helper request".into());
        }
        let reply = ClientFrame {
            version: VERSION,
            job_id: frame.job_id.clone(),
            reply_to: frame.sequence,
            body,
        };
        frame.validate_reply(&reply).map_err(|e| e.to_string())?;
        self.next = match &reply.body {
            ClientMessage::Cancel => Next::Terminal,
            ClientMessage::Begin { source_count, .. } if *source_count == self.count => {
                Next::Archive
            }
            ClientMessage::Archive { .. } => Next::Source(0),
            ClientMessage::Source { index, .. } => {
                if index + 1 == self.count {
                    Next::Inputs
                } else {
                    Next::Source(index + 1)
                }
            }
            ClientMessage::SourcesComplete => Next::Working,
            ClientMessage::SourcesReleased => {
                let ServerMessage::Prepared {
                    image_bytes,
                    image_sha256,
                    ..
                } = &frame.body
                else {
                    return Err("Missing prepared image".into());
                };
                self.prepared = Some((*image_bytes, image_sha256.clone()));
                Next::Confirmation
            }
            ClientMessage::Confirm { .. } => {
                self.committed = true;
                Next::Committed
            }
            ClientMessage::Continue => self.next,
            ClientMessage::FinishAck => Next::Closed,
            _ => return Err("Invalid preparation response".into()),
        };
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or("Helper sequence overflow")?;
        self.pending = false;
        Ok(reply)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame(sequence: u64, body: ServerMessage) -> ServerFrame {
        ServerFrame {
            version: VERSION,
            job_id: "a".repeat(64),
            sequence,
            body,
        }
    }
    #[test]
    fn full_transfer_requires_seal_release_and_exact_terminal_image() {
        let mut session = ClientSession::new(1);
        let exchanges = [
            (
                ServerMessage::Hello,
                ClientMessage::Begin {
                    target_selector: "selector".into(),
                    source_count: 1,
                },
            ),
            (
                ServerMessage::NeedArchive,
                ClientMessage::Archive {
                    remote_handle: 7,
                    bytes: isohopper_core::engine::archive::ARCHIVE_BYTES as u64,
                    sha256: "a".repeat(64),
                },
            ),
            (
                ServerMessage::NeedSource { index: 0 },
                ClientMessage::Source {
                    index: 0,
                    source_id: "source".into(),
                    relative_path: "Windows/boot.iso".into(),
                    bytes: 1,
                    sha256: "b".repeat(64),
                    remote_handle: 8,
                },
            ),
            (ServerMessage::InputsReady, ClientMessage::SourcesComplete),
        ];
        for (sequence, (body, response)) in exchanges.into_iter().enumerate() {
            let request = frame(sequence as u64, body);
            session.accept(&request).unwrap();
            session.reply(&request, response).unwrap();
        }
        let bytes = 8 * 1024 * 1024 * 1024;
        let prepared = frame(
            4,
            ServerMessage::Prepared {
                target: isohopper_helper::prepare_protocol::TargetSummary {
                    device_number: 7,
                    serial: "serial".into(),
                    device_id: None,
                    bus_type: 7,
                    size_bytes: bytes,
                    logical_sector_size: 512,
                    physical_sector_size: 512,
                },
                image_bytes: bytes,
                image_sha256: "c".repeat(64),
                description_digest: "d".repeat(64),
                challenge: "WIPE serial".into(),
                source_count: 1,
                original_handles_closed: true,
            },
        );
        session.accept(&prepared).unwrap();
        assert!(
            session
                .reply(
                    &prepared,
                    ClientMessage::Confirm {
                        description_digest: "d".repeat(64),
                        challenge: "WIPE serial".into()
                    }
                )
                .is_err()
        );
        session
            .reply(&prepared, ClientMessage::SourcesReleased)
            .unwrap();
        assert!(session.accept(&frame(5, prepared.body.clone())).is_err());
        let confirm = frame(5, ServerMessage::AwaitConfirmation);
        session.accept(&confirm).unwrap();
        session
            .reply(
                &confirm,
                ClientMessage::Confirm {
                    description_digest: "d".repeat(64),
                    challenge: "WIPE serial".into(),
                },
            )
            .unwrap();
        let terminal = |hash| {
            frame(
                6,
                ServerMessage::Terminal {
                    outcome: Outcome::Succeeded,
                    phase: Phase::Complete,
                    message: "complete".into(),
                    bytes_written: bytes,
                    bytes_verified: bytes,
                    target_may_be_incomplete: false,
                    sha256: Some(hash),
                },
            )
        };
        assert!(session.accept(&terminal("e".repeat(64))).is_err());
        let done = terminal("c".repeat(64));
        session.accept(&done).unwrap();
        session.reply(&done, ClientMessage::FinishAck).unwrap();
    }
    #[test]
    fn rejects_replayed_sequence_and_changed_job() {
        let mut session = ClientSession::new(1);
        let hello = frame(0, ServerMessage::Hello);
        session.accept(&hello).unwrap();
        session
            .reply(
                &hello,
                ClientMessage::Begin {
                    target_selector: "selector".into(),
                    source_count: 1,
                },
            )
            .unwrap();
        assert!(session.accept(&hello).is_err());
        let mut wrong = frame(1, ServerMessage::NeedArchive);
        wrong.job_id = "b".repeat(64);
        assert!(session.accept(&wrong).is_err());
        session
            .accept(&frame(1, ServerMessage::NeedArchive))
            .unwrap();
    }
    #[test]
    fn no_progress_or_success_before_input_acknowledgement() {
        let mut session = ClientSession::new(1);
        assert!(
            session
                .accept(&frame(
                    0,
                    ServerMessage::Progress {
                        phase: Phase::WritingTarget,
                        completed_bytes: 0,
                        total_bytes: 1,
                        file_index: None
                    }
                ))
                .is_err()
        );
        assert!(
            session
                .accept(&frame(
                    0,
                    ServerMessage::Terminal {
                        outcome: Outcome::Succeeded,
                        phase: Phase::Complete,
                        message: "complete".into(),
                        bytes_written: 1,
                        bytes_verified: 1,
                        target_may_be_incomplete: false,
                        sha256: Some("a".repeat(64))
                    }
                ))
                .is_err()
        );
    }
    #[test]
    fn cancellation_permits_only_terminal_and_cannot_become_success() {
        let mut session = ClientSession::new(1);
        let hello = frame(0, ServerMessage::Hello);
        session.accept(&hello).unwrap();
        session.reply(&hello, ClientMessage::Cancel).unwrap();
        assert!(
            session
                .accept(&frame(1, ServerMessage::NeedArchive))
                .is_err()
        );
        assert!(
            session
                .accept(&frame(
                    1,
                    ServerMessage::Terminal {
                        outcome: Outcome::Succeeded,
                        phase: Phase::Complete,
                        message: "complete".into(),
                        bytes_written: 1,
                        bytes_verified: 1,
                        target_may_be_incomplete: false,
                        sha256: Some("a".repeat(64))
                    }
                ))
                .is_err()
        );
        let terminal = frame(
            1,
            ServerMessage::Terminal {
                outcome: Outcome::Cancelled,
                phase: Phase::Receiving,
                message: "cancelled".into(),
                bytes_written: 0,
                bytes_verified: 0,
                target_may_be_incomplete: false,
                sha256: None,
            },
        );
        session.accept(&terminal).unwrap();
        session.reply(&terminal, ClientMessage::FinishAck).unwrap();
        assert!(session.accept(&frame(2, ServerMessage::Hello)).is_err());
    }
}
