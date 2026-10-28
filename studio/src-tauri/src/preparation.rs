// SPDX-License-Identifier: GPL-3.0-or-later
//! Native-owned preparation state. Renderer state is never a write capability.
// Windows runner state is also compiled by portable regression tests.
#![cfg_attr(not(windows), allow(dead_code))]
#[path = "preparation/inputs.rs"]
pub mod inputs;
#[path = "preparation/protocol.rs"]
mod protocol;
#[path = "preparation/targets.rs"]
pub mod targets;
#[cfg(windows)]
#[path = "preparation/windows.rs"]
mod windows;

use serde::Serialize;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub job_id: String,
    pub phase: String,
    pub message: String,
    pub active: bool,
    pub cancel_requested: bool,
    pub completed_bytes: u64,
    pub total_bytes: u64,
    pub bytes_written: u64,
    pub bytes_verified: u64,
    pub target_may_be_incomplete: bool,
    pub sources_released: bool,
    pub target: Option<serde_json::Value>,
    pub image_sha256: Option<String>,
    pub description_digest: Option<String>,
    pub challenge: Option<String>,
}
#[derive(Clone)]
struct Confirmation {
    digest: String,
    challenge: String,
}
struct State {
    snapshot: Snapshot,
    confirmation: Option<Confirmation>,
    confirmation_queued: bool,
}
struct Job {
    state: Mutex<State>,
    abort: AtomicBool,
}
impl Job {
    fn note_reply(
        &self,
        body: &isohopper_helper::prepare_protocol::ClientMessage,
    ) -> Result<(), String> {
        if matches!(
            body,
            isohopper_helper::prepare_protocol::ClientMessage::Confirm { .. }
        ) {
            self.update(|snapshot| snapshot.target_may_be_incomplete = true)?;
        }
        Ok(())
    }
    fn new(id: String) -> Self {
        Self {
            state: Mutex::new(State {
                snapshot: Snapshot {
                    job_id: id,
                    phase: "verifying_sources".into(),
                    message: "Rechecking retained source files before starting the helper.".into(),
                    active: true,
                    cancel_requested: false,
                    completed_bytes: 0,
                    total_bytes: 0,
                    bytes_written: 0,
                    bytes_verified: 0,
                    target_may_be_incomplete: false,
                    sources_released: false,
                    target: None,
                    image_sha256: None,
                    description_digest: None,
                    challenge: None,
                },
                confirmation: None,
                confirmation_queued: false,
            }),
            abort: AtomicBool::new(false),
        }
    }
    fn snapshot(&self) -> Result<Snapshot, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "Preparation state is unavailable")?
            .snapshot
            .clone())
    }
    fn update(&self, change: impl FnOnce(&mut Snapshot)) -> Result<(), String> {
        change(
            &mut self
                .state
                .lock()
                .map_err(|_| "Preparation state is unavailable")?
                .snapshot,
        );
        Ok(())
    }
    fn cancel(&self) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Preparation state is unavailable")?;
        if !state.snapshot.active {
            return Err("Preparation is already finished".into());
        }
        state.snapshot.cancel_requested = true;
        state.confirmation = None;
        Ok(())
    }
    fn confirm(&self, digest: String, challenge: String) -> Result<(), String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "Preparation state is unavailable")?;
        if !state.snapshot.active
            || state.snapshot.phase != "await_confirmation"
            || state.snapshot.cancel_requested
            || state.confirmation_queued
            || state.snapshot.description_digest.as_ref() != Some(&digest)
            || state.snapshot.challenge.as_ref() != Some(&challenge)
        {
            return Err("Confirmation does not match the current prepared job".into());
        }
        state.confirmation = Some(Confirmation { digest, challenge });
        state.confirmation_queued = true;
        Ok(())
    }
}

static JOB: OnceLock<Mutex<Option<Arc<Job>>>> = OnceLock::new();
static ACTIVE: AtomicBool = AtomicBool::new(false);
fn jobs() -> &'static Mutex<Option<Arc<Job>>> {
    JOB.get_or_init(|| Mutex::new(None))
}
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}
pub fn status() -> Result<Option<Snapshot>, String> {
    jobs()
        .lock()
        .map_err(|_| "Preparation state is unavailable")?
        .as_ref()
        .map(|j| j.snapshot())
        .transpose()
}
fn selected(id: &str) -> Result<Arc<Job>, String> {
    let job = jobs()
        .lock()
        .map_err(|_| "Preparation state is unavailable")?
        .as_ref()
        .cloned()
        .ok_or("No preparation job exists")?;
    if job.snapshot()?.job_id != id {
        return Err("Unknown preparation job".into());
    }
    Ok(job)
}
pub fn confirm(id: &str, digest: String, challenge: String) -> Result<(), String> {
    selected(id)?.confirm(digest, challenge)
}
pub fn cancel(id: &str) -> Result<(), String> {
    selected(id)?.cancel()
}

#[cfg(windows)]
pub use windows::start;

#[cfg(test)]
mod tests {
    use super::*;
    fn pending() -> Job {
        let job = Job::new("local-job".into());
        job.update(|s| {
            s.phase = "await_confirmation".into();
            s.description_digest = Some("a".repeat(64));
            s.challenge = Some("WIPE Serial-AbC".into());
        })
        .unwrap();
        job
    }
    #[test]
    fn terminal_success_stays_complete_after_finish_ack() {
        use isohopper_helper::prepare_protocol::ClientMessage;
        let job = pending();
        job.note_reply(&ClientMessage::Confirm {
            description_digest: "a".repeat(64),
            challenge: "WIPE Serial-AbC".into(),
        })
        .unwrap();
        assert!(job.snapshot().unwrap().target_may_be_incomplete);
        // A validated terminal response supplies the final physical state.
        job.update(|s| {
            s.phase = "succeeded".into();
            s.target_may_be_incomplete = false;
        })
        .unwrap();
        job.note_reply(&ClientMessage::FinishAck).unwrap();
        assert!(!job.snapshot().unwrap().target_may_be_incomplete);
    }
    #[test]
    fn confirmation_requires_exact_current_state_and_can_only_be_queued_once() {
        let job = pending();
        assert!(
            job.confirm("b".repeat(64), "WIPE Serial-AbC".into())
                .is_err()
        );
        assert!(
            job.confirm("a".repeat(64), "WIPE SERIAL-ABC".into())
                .is_err()
        );
        job.confirm("a".repeat(64), "WIPE Serial-AbC".into())
            .unwrap();
        assert!(
            job.confirm("a".repeat(64), "WIPE Serial-AbC".into())
                .is_err()
        );
        let mut state = job.state.lock().unwrap();
        assert_eq!(
            state.confirmation.take().unwrap().challenge,
            "WIPE Serial-AbC"
        );
        drop(state);
        assert!(
            job.confirm("a".repeat(64), "WIPE Serial-AbC".into())
                .is_err()
        );
    }
    #[test]
    fn cancel_supersedes_queued_confirmation_without_claiming_completion() {
        let job = pending();
        job.confirm("a".repeat(64), "WIPE Serial-AbC".into())
            .unwrap();
        job.cancel().unwrap();
        assert!(job.state.lock().unwrap().confirmation.is_none());
        assert!(job.snapshot().unwrap().active);
        assert!(job.snapshot().unwrap().cancel_requested);
        assert!(
            job.confirm("a".repeat(64), "WIPE Serial-AbC".into())
                .is_err()
        );
    }
}
