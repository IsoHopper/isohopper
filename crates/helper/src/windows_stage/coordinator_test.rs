// SPDX-License-Identifier: GPL-3.0-or-later
//! Reuse the expensive genuine stage build for a real owned-VHD confirmation,
//! lock, raw write and persisted readback. Only input handoff is simulated here;
//! process/pipe source transfer has its own native cross-process fixture.
use super::*;
use crate::{
    prepare_protocol::{ClientMessage, Outcome, ServerMessage},
    raw_image_job::{
        BootArtifactFingerprint, ConfirmationReceipt, PreparedRawImage, RawImageDescription,
    },
    windows_prepare::coordinator::{self, Executor, Inputs, JobFailure, Ready, Transport},
    windows_target::BoundTarget,
    writer,
};
use std::sync::mpsc::SyncSender;

struct FixtureReady {
    target: BoundTarget,
    stage: TargetBoundStage,
    owner: OwnedStageDisk,
    entries: Vec<CopyEntry>,
}
struct Fixture {
    ready: Ready<FixtureReady>,
}
impl Executor for Fixture {
    type Ready = FixtureReady;
    fn prepare(
        self,
        inputs: Inputs,
        _: &AtomicBool,
        _: &SyncSender<ServerMessage>,
    ) -> Result<Ready<FixtureReady>, JobFailure> {
        // The same production build already consumed/closed its real originals.
        // These inert descriptors exercise protocol sequencing only.
        drop(inputs);
        Ok(self.ready)
    }
    fn write(
        value: FixtureReady,
        receipt: ConfirmationReceipt,
        cancel: &AtomicBool,
        _: &SyncSender<ServerMessage>,
    ) -> Result<writer::Report, JobFailure> {
        let FixtureReady {
            target,
            mut stage,
            mut owner,
            entries,
        } = value;
        let expected = receipt.description().target();
        assert_eq!(expected, &target.observation().handle.device);
        assert_eq!(receipt.description().image(), stage.fingerprint());
        let identity = target.observation().handle.identity.clone();
        stage.revalidate_readiness(expected).unwrap();
        // This is the exact production CM-path-to-writable-handle handoff.
        // No physical policy is bypassed publicly; this target is our new VHD.
        let mut device = target.lock_for_preparation().unwrap();
        let report = writer::write_image(
            &mut device,
            &mut stage,
            expected,
            receipt.description().image().sha256,
            cancel,
            |_| {},
        )
        .unwrap();
        drop(device);
        owner.detach().unwrap();
        owner.attach(true).unwrap();
        let mut view = View::open(&owner).unwrap();
        view.same_disk(expected, &identity).unwrap();
        view.read_only().unwrap();
        let mut digest = Sha256::new();
        let mut bytes = 0u64;
        let mut buffer = vec![0; 1024 * 1024];
        while bytes < report.bytes_written {
            view.check().unwrap();
            let count = (report.bytes_written - bytes).min(buffer.len() as u64) as usize;
            view.file.read_exact(&mut buffer[..count]).unwrap();
            digest.update(&buffer[..count]);
            bytes += count as u64;
        }
        assert_eq!(<[u8; 32]>::from(digest.finalize()), report.sha256);
        let data = select(&view, stage.engine(), cancel).unwrap();
        let root = device::root(&data).unwrap();
        verify_files(&root, &entries, cancel).unwrap();
        drop(root);
        drop(view);
        owner.close().unwrap();
        drop(stage);
        Ok(report)
    }
}
#[derive(Default)]
struct Wire {
    digest: Option<String>,
    challenge: Option<String>,
    finished: bool,
}
impl Transport for Wire {
    fn exchange(&mut self, body: ServerMessage) -> Result<ClientMessage, String> {
        Ok(match body {
            ServerMessage::Hello => ClientMessage::Begin {
                target_selector: "owned-vhd-fixture".into(),
                source_count: 1,
            },
            ServerMessage::NeedArchive => ClientMessage::Archive {
                remote_handle: 1,
                bytes: engine::archive::ARCHIVE_BYTES as u64,
                sha256: engine::archive::ARCHIVE_SHA256.into(),
            },
            ServerMessage::NeedSource { index } => ClientMessage::Source {
                index,
                source_id: "fixture-already-staged".into(),
                relative_path: "fixture.iso".into(),
                bytes: 512,
                sha256: hex::encode([0; 32]),
                remote_handle: 2,
            },
            ServerMessage::InputsReady => ClientMessage::SourcesComplete,
            ServerMessage::Progress { .. } => ClientMessage::Continue,
            ServerMessage::Prepared {
                description_digest,
                challenge,
                original_handles_closed,
                ..
            } => {
                assert!(original_handles_closed);
                self.digest = Some(description_digest);
                self.challenge = Some(challenge);
                ClientMessage::SourcesReleased
            }
            ServerMessage::AwaitConfirmation => ClientMessage::Confirm {
                description_digest: self.digest.take().unwrap(),
                challenge: self.challenge.take().unwrap(),
            },
            ServerMessage::Terminal {
                outcome,
                bytes_written,
                bytes_verified,
                target_may_be_incomplete,
                ..
            } => {
                assert_eq!(outcome, Outcome::Succeeded);
                assert_eq!(bytes_written, 256 << 20);
                assert_eq!(bytes_written, bytes_verified);
                assert!(!target_may_be_incomplete);
                self.finished = true;
                ClientMessage::FinishAck
            }
        })
    }
    fn receive(&mut self, _: u64) -> Result<File, String> {
        tempfile::tempfile().map_err(|e| e.to_string())
    }
    fn finish(&mut self) -> Result<(), String> {
        assert!(self.finished);
        Ok(())
    }
}
pub(super) fn exercise(sealed: SealedStage, root: Root, entries: Vec<CopyEntry>) {
    let geometry = Geometry {
        size_bytes: sealed.fingerprint().bytes,
        logical_sector_size: 512,
        physical_sector_size: 4096,
    };
    let mut owner = OwnedStageDisk::create_under(root, geometry).unwrap();
    owner.attach(false).unwrap();
    let mut view = View::open(&owner).unwrap();
    view.verify_blank(&AtomicBool::new(false)).unwrap();
    let expected = view.snapshot.clone();
    // SAFETY: read-only synchronous handle from this exact newly owned VHD.
    let target =
        unsafe { BoundTarget::from_owned_handle(view.file.try_clone().unwrap().into(), &expected) }
            .unwrap();
    assert!(target.observation().coverage.partitions.is_empty());
    assert!([0, 2].contains(&target.observation().coverage.partition_style));
    drop(view);
    let stage = sealed.bind_target(&expected).unwrap();
    let description = || {
        PreparedRawImage::new(RawImageDescription {
            target: expected.clone(),
            image: stage.fingerprint().clone(),
            boot_artifacts: vec![BootArtifactFingerprint {
                role: "engine-archive".into(),
                version: Some(engine::VERSION.into()),
                bytes: engine::archive::ARCHIVE_BYTES as u64,
                sha256: crate::prepare_protocol::decode_sha256(engine::archive::ARCHIVE_SHA256)
                    .unwrap(),
            }],
        })
        .unwrap()
    };
    let mut invalid = description().into_confirmation();
    let correct = description();
    assert!(
        invalid
            .confirm(&[0; 32], &expected, correct.challenge())
            .is_err()
    );
    assert!(
        invalid
            .confirm(&correct.digest(), &expected, "WIPE wrong")
            .is_err()
    );
    let mut changed = expected.clone();
    changed.device_number += 1;
    assert!(
        invalid
            .confirm(&correct.digest(), &changed, correct.challenge())
            .is_err()
    );
    let mut view = View::open(&owner).unwrap();
    let mut untouched = [0; 512];
    view.file.read_exact(&mut untouched).unwrap();
    assert_eq!(untouched, [0; 512]);
    drop(view);
    let ready = Ready {
        value: FixtureReady {
            target,
            stage,
            owner,
            entries,
        },
        description: correct,
    };
    let mut wire = Wire::default();
    coordinator::run(&mut wire, Fixture { ready }).unwrap();
    assert!(wire.finished);
    println!(
        "OWNED_COORDINATOR_OK stage_host_bound=true confirmation=true cm_write_handoff=true persisted_raw_sha256=true nested_files=true physical_target=false"
    );
}
