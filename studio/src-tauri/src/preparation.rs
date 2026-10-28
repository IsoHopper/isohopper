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

use crate::imports::source_catalog::{SourceBatch, SourceInfo};
use serde::Serialize;
use std::fs::File;
use std::sync::{
    Arc, Mutex, OnceLock,
    atomic::{AtomicBool, Ordering},
};

/// Review metadata only. It cannot reopen or lease a catalogue source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SourceManifestEntry {
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: String,
}

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
    pub source_manifest: Vec<SourceManifestEntry>,
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
    /// Publish metadata only after every transfer callback and the final source
    /// stability checks succeed. Earlier callbacks may already have sent handles
    /// on failure, but the UI never receives a partial or unverified manifest.
    fn transfer_sources(
        &self,
        sources: &SourceBatch,
        transfer: impl FnMut(&File, &SourceInfo) -> Result<(), String>,
    ) -> Result<(), String> {
        let manifest = sources
            .visit_verified(transfer)?
            .into_iter()
            .map(|source| SourceManifestEntry {
                relative_path: source.relative_path,
                bytes: source.bytes,
                sha256: source.verification.digest,
            })
            .collect();
        self.update(|snapshot| snapshot.source_manifest = manifest)
    }

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
                    source_manifest: Vec::new(),
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
    use crate::imports::source_catalog::{PreparedSource, SourceCatalog};
    use std::fs::File;

    #[test]
    fn transferred_manifest_survives_catalogue_release_and_terminal_snapshots() {
        let root = tempfile::tempdir().unwrap();
        let mut catalogue = SourceCatalog::default();
        let mut sources = Vec::new();
        for (name, bytes) in [("Mac/boot.iso", b"abc"), ("Windows/boot.iso", b"xyz")] {
            let path = root.path().join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, bytes).unwrap();
            sources.push(PreparedSource::new(File::open(path).unwrap(), name).unwrap());
        }
        let infos = catalogue.insert_batch(sources).unwrap();
        let ids = [infos[1].source_id.clone(), infos[0].source_id.clone()];
        let batch = catalogue.lease_batch(&ids).unwrap();
        let job = Job::new("manifest-job".into());
        let mut transferred = Vec::new();
        job.transfer_sources(&batch, |file, info| {
            assert_eq!(file.metadata().unwrap().len(), info.bytes);
            transferred.push(info.relative_path.clone());
            Ok(())
        })
        .unwrap();
        assert_eq!(transferred, ["Windows/boot.iso", "Mac/boot.iso"]);
        let manifest = job.snapshot().unwrap().source_manifest;
        assert_eq!(manifest[0].relative_path, infos[1].relative_path);
        assert_eq!(manifest[0].bytes, infos[1].bytes);
        assert_eq!(manifest[0].sha256, infos[1].verification.digest);
        assert_eq!(manifest[1].sha256, infos[0].verification.digest);
        drop(batch);
        catalogue.release_sources(&ids).unwrap();
        assert!(catalogue.list_sources().is_empty());
        job.update(|s| {
            s.sources_released = true;
            s.phase = "await_confirmation".into();
        })
        .unwrap();
        assert_eq!(job.snapshot().unwrap().source_manifest, manifest);
        job.update(|s| {
            s.active = false;
            s.phase = "succeeded".into();
        })
        .unwrap();
        let receipt = serde_json::to_value(job.snapshot().unwrap()).unwrap();
        assert_eq!(
            receipt["source_manifest"][0]["relative_path"],
            "Windows/boot.iso"
        );
        assert_eq!(job.snapshot().unwrap().source_manifest, manifest);
        let serialized = receipt.to_string();
        assert!(!serialized.contains("source_id"));
        assert!(!serialized.contains(&root.path().display().to_string()));
        assert!(catalogue.lease(&ids[0]).is_err());
    }

    #[test]
    fn failed_transfer_does_not_publish_a_partial_source_manifest() {
        let root = tempfile::tempdir().unwrap();
        let mut catalogue = SourceCatalog::default();
        let mut sources = Vec::new();
        for name in ["first.iso", "last.iso"] {
            let path = root.path().join(name);
            std::fs::write(&path, name).unwrap();
            sources.push(PreparedSource::new(File::open(path).unwrap(), name).unwrap());
        }
        let infos = catalogue.insert_batch(sources).unwrap();
        let ids: Vec<_> = infos.iter().map(|info| info.source_id.clone()).collect();
        let batch = catalogue.lease_batch(&ids).unwrap();
        let job = Job::new("failed-job".into());
        let mut count = 0;
        let error = job
            .transfer_sources(&batch, |_, _| {
                count += 1;
                if count == 2 {
                    Err("receiver rejected final source".into())
                } else {
                    Ok(())
                }
            })
            .unwrap_err();
        assert_eq!(error, "receiver rejected final source");
        assert_eq!(count, 2);
        assert!(job.snapshot().unwrap().source_manifest.is_empty());
        assert!(catalogue.release_sources(&ids).is_err());
        drop(batch);
        catalogue.release_sources(&ids).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn final_source_stability_failure_does_not_publish_a_manifest() {
        let root = tempfile::tempdir().unwrap();
        let mut catalogue = SourceCatalog::default();
        let mut sources = Vec::new();
        for name in ["first.iso", "last.iso"] {
            let path = root.path().join(name);
            std::fs::write(&path, name).unwrap();
            sources.push(PreparedSource::new(File::open(path).unwrap(), name).unwrap());
        }
        let infos = catalogue.insert_batch(sources).unwrap();
        let ids: Vec<_> = infos.iter().map(|info| info.source_id.clone()).collect();
        let batch = catalogue.lease_batch(&ids).unwrap();
        let job = Job::new("changed-job".into());
        let mut count = 0;
        let result = job.transfer_sources(&batch, |_, _| {
            count += 1;
            if count == 2 {
                // First source already passed its callback and local post-check.
                // The final all-source check must still catch this mutation.
                std::fs::write(root.path().join("first.iso"), b"changed-length").unwrap();
            }
            Ok(())
        });
        assert_eq!(count, 2);
        assert!(result.is_err());
        assert!(job.snapshot().unwrap().source_manifest.is_empty());
    }

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
