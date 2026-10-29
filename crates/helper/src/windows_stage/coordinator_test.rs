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
use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

/// Production staging lives under the machine installation, not the runner's
/// environment-selected scratch disk. Keep this fixture on the Windows volume
/// too, without changing the process environment or relaxing host binding.
pub(super) fn temp_root() -> tempfile::TempDir {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

    let mut buffer = [0u16; 32768];
    // SAFETY: bounded writable buffer remains live for this synchronous query.
    let count = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) };
    assert!(
        count > 0 && (count as usize) < buffer.len(),
        "system directory query failed"
    );
    let system = PathBuf::from(OsString::from_wide(&buffer[..count as usize]));
    assert!(system.is_absolute(), "system directory must be absolute");
    let parent = system
        .parent()
        .expect("system directory requires a parent")
        .join("Temp");
    // These are read-only observations, not permission to use either host.
    // bind_target below must still establish all production evidence itself.
    let temp = tempfile::Builder::new()
        .prefix("isohopper-stage-")
        .tempdir_in(parent)
        .expect("create unique fixture beneath existing Windows Temp");
    diagnose_host("default_temp", &std::env::temp_dir());
    diagnose_host("system_temp", temp.path());
    assert!(
        directory_volume(temp.path()).expect("fixture volume")
            == directory_volume(&system).expect("Windows volume"),
        "fixture must remain on the Windows volume"
    );
    temp
}

fn directory_volume(path: &Path) -> Result<String, &'static str> {
    // Resolve the directory as tempfile does, including any redirected parent.
    // This is a zero-access observation, never a target or write capability.
    let directory = OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|_| "directory_open")?;
    crate::windows_sources::source_guid(&directory).map_err(|_| "volume_guid")
}

fn diagnose_host(location: &'static str, path: &Path) {
    use crate::{
        windows_preparation_target::require_stage_host_pool, windows_sources::volume_extents,
    };
    use isohopper_inventory::{windows::collect_evidence, windows_pools};

    let observation = (|| -> Result<serde_json::Value, &'static str> {
        let guid = directory_volume(path)?;
        let volume = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&guid[..guid.len() - 1])
            .map_err(|_| "volume_open")?;
        // SAFETY: retained synchronous access-zero volume handle from its GUID.
        let extents = unsafe { volume_extents(&volume) }.map_err(|_| "volume_extents")?;
        let [extent] = extents.as_slice() else {
            return Err("multiple_extents");
        };
        let inventory = collect_evidence().map_err(|_| "disk_inventory")?;
        let mut matches = inventory
            .disks
            .iter()
            .filter(|disk| disk.number == extent.disk_number);
        let disk = matches.next().ok_or("host_missing")?;
        if matches.next().is_some() {
            return Err("host_ambiguous");
        }
        let pools = windows_pools::collect().map_err(|_| "pool_inventory")?;
        let matched_pools: Vec<_> = pools
            .physical_disks
            .iter()
            .filter(|pool| disk.unique_id.as_deref() == Some(pool.unique_id.as_str()))
            .collect();
        let known = |value: Option<&str>| value.is_some_and(|value| !value.trim().is_empty());
        let native = disk
            .path
            .as_deref()
            .and_then(|selector| BoundTarget::open_present_interface(selector).ok());
        Ok(serde_json::json!({
            "status": "observed",
            "disk_number": disk.number,
            "serial_known": known(disk.serial_number.as_deref()),
            "native_bound": native.is_some(),
            "native_serial_known": native.as_ref().map(|host| !host.observation().handle.device.serial.trim().is_empty()),
            "bus_type": disk.bus_type,
            "size_bytes": disk.size,
            "unique_id_format": disk.unique_id_format,
            "pool_matches": matched_pools.len(),
            "pool_serial_known": (matched_pools.len() == 1).then(|| known(matched_pools[0].serial_number.as_deref())),
            "stage_host_pool_supported": require_stage_host_pool(disk, &pools).is_ok(),
        }))
    })();
    let mut value =
        observation.unwrap_or_else(|stage| serde_json::json!({"status":"error", "stage":stage}));
    value["location"] = location.into();
    // No paths, serials or unique IDs are emitted. All strings above are fixed.
    println!("OWNED_STAGE_HOST_DIAGNOSTIC {value}");
}

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
        // Explicit expectation independent of build_under's verification list:
        // the exported image must carry the application's real boot theme.
        verify_files(&root, &theme::entries(), cancel).unwrap();
        let config: serde_json::Value =
            serde_json::from_slice(&root.read("ventoy/ventoy.json").unwrap()).unwrap();
        assert_eq!(config["theme"]["file"], "/ventoy/isohopper/theme.txt");
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
    fn receive(&mut self, _: u64) -> Result<Result<File, String>, String> {
        Ok(tempfile::tempfile().map_err(|e| e.to_string()))
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
    println!("OWNED_THEME_STAGE_OK theme=true persisted=true physical_target=false");
}
