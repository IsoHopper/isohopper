// SPDX-License-Identifier: GPL-3.0-or-later
use super::super::{
    StageInput, StageProgress,
    build_policy::{self, SelectedVolume},
    format,
};
use super::device::{self, View, context};
use super::*;
use crate::{raw_image_job::ImageFingerprint, writer::write_image};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions as CapOptions};
use isohopper_core::engine::{self, Image, Payloads, Plan};
use isohopper_media::copy::{CopyEntry, copy_one, validate_manifest};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    sync::atomic::{AtomicBool, Ordering},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ID_INFO, FileIdInfo, GetFileInformationByHandleEx, ReOpenFile,
    },
};

const SEED: &str = "seed.img";
const FINAL: &str = "final.img";
#[path = "host.rs"]
mod host;
pub use host::TargetBoundStage;
#[cfg(test)]
#[path = "coordinator_test.rs"]
mod coordinator_test;
fn cancelled(cancel: &AtomicBool) -> Result<(), StageError> {
    if cancel.load(Ordering::Relaxed) {
        Err(StageError::Invalid("staging cancelled"))
    } else {
        Ok(())
    }
}
fn hash(file: &mut File, bytes: u64, cancel: &AtomicBool) -> Result<[u8; 32], StageError> {
    file.rewind().map_err(|e| error("rewind stage file", e))?;
    if file.metadata().map_err(|e| error("stage length", e))?.len() != bytes {
        return Err(StageError::Invalid("stage file length differs"));
    }
    let mut left = bytes;
    let mut buffer = [0u8; 65536];
    let mut hash = Sha256::new();
    while left > 0 {
        cancelled(cancel)?;
        let n = left.min(buffer.len() as u64) as usize;
        file.read_exact(&mut buffer[..n])
            .map_err(|e| error("hash stage file", e))?;
        hash.update(&buffer[..n]);
        left -= n as u64;
    }
    if file
        .read(&mut [0])
        .map_err(|e| error("stage end of file", e))?
        != 0
    {
        return Err(StageError::Invalid("stage file grew"));
    }
    file.rewind().map_err(|e| error("rewind stage file", e))?;
    Ok(hash.finalize().into())
}
#[derive(PartialEq, Eq)]
struct Stamp {
    volume: u64,
    id: [u8; 16],
    len: u64,
    modified: std::time::SystemTime,
}
fn stamp(file: &File) -> Result<Stamp, StageError> {
    check_stage_object(file, false).map_err(StageError::Installation)?;
    file_stamp(file)
}
fn file_stamp(file: &File) -> Result<Stamp, StageError> {
    let metadata = file.metadata().map_err(|e| error("sealed metadata", e))?;
    let mut id = FILE_ID_INFO::default();
    // SAFETY: fixed SDK output with synchronous retained file handle.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            (&mut id as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    } == 0
    {
        return Err(error("sealed file identity", io::Error::last_os_error()));
    }
    Ok(Stamp {
        volume: id.VolumeSerialNumber,
        id: id.FileId.Identifier,
        len: metadata.len(),
        modified: metadata
            .modified()
            .map_err(|e| error("sealed modification time", e))?,
    })
}
fn reopen(file: &File, share: u32) -> Result<File, StageError> {
    // SAFETY: live regular-file handle; reopen is synchronous and read-only.
    let handle = unsafe {
        ReOpenFile(
            file.as_raw_handle(),
            GENERIC_READ,
            share,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(error("seal read-only reopen", io::Error::last_os_error()));
    }
    Ok(unsafe { File::from_raw_handle(handle) })
}
fn seal(
    writer: File,
    expected: [u8; 32],
    bytes: u64,
    cancel: &AtomicBool,
) -> Result<File, StageError> {
    let before = stamp(&writer)?;
    // A share-read-only reopen conflicts while the write file object exists.
    let bridge = reopen(&writer, FILE_SHARE_READ | FILE_SHARE_WRITE)?;
    if stamp(&bridge)? != before {
        return Err(StageError::Invalid("seal bridge identity differs"));
    }
    drop(writer);
    let closed = stamp(&bridge)?;
    if closed.volume != before.volume || closed.id != before.id || closed.len != before.len {
        return Err(StageError::Invalid("writer close changed file identity"));
    }
    let mut reader = reopen(&bridge, FILE_SHARE_READ)?;
    if stamp(&reader)? != closed {
        return Err(StageError::Invalid("sealed reader identity differs"));
    }
    drop(bridge);
    if hash(&mut reader, bytes, cancel)? != expected || stamp(&reader)? != closed {
        return Err(StageError::Invalid("sealed bytes changed"));
    }
    Ok(reader)
}
fn create_file(owner: &mut OwnedStageDisk, name: &'static str) -> Result<File, StageError> {
    owner.revalidate()?;
    let path = wide(&owner.directory.join(name))?;
    let sd = Descriptor::private()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    };
    // SAFETY: fixed filename under retained protected directory, explicit final
    // descriptor, exclusive creation, synchronous noninheritable ownership.
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            &attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(error(
            "create private stage file",
            io::Error::last_os_error(),
        ));
    }
    owner.owned_files.push(name);
    let file = unsafe { File::from_raw_handle(handle) };
    check_stage_object(&file, false).map_err(StageError::Installation)?;
    Ok(file)
}
fn select(
    view: &View<'_>,
    image: &Image,
    cancel: &AtomicBool,
) -> Result<SelectedVolume, StageError> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        cancelled(cancel)?;
        let result = view
            .coverage()
            .and_then(|c| build_policy::select_data(image.plan(), image.identifiers(), &c));
        match result {
            Ok(v) => {
                device::no_mounts(&v)?;
                return Ok(v);
            }
            Err(e) if Instant::now() >= deadline => return Err(e),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}
fn verify_files(root: &Dir, entries: &[CopyEntry], cancel: &AtomicBool) -> Result<(), StageError> {
    for entry in entries {
        cancelled(cancel)?;
        let parts: Vec<_> = entry.relative_path.split('/').collect();
        let mut parent = root
            .try_clone()
            .map_err(|e| error("retain verification root", e))?;
        for part in &parts[..parts.len() - 1] {
            parent = parent
                .open_dir_nofollow(part)
                .map_err(|e| error("open persisted parent", e))?;
        }
        let mut options = CapOptions::new();
        options.read(true).follow(FollowSymlinks::No);
        let mut file = parent
            .open_with(parts[parts.len() - 1], &options)
            .map_err(|e| error("open persisted file", e))?
            .into_std();
        if !file
            .metadata()
            .map_err(|e| error("persisted file kind", e))?
            .is_file()
            || hash(&mut file, entry.bytes, cancel)? != entry.sha256
        {
            return Err(StageError::Invalid("persisted data differs"));
        }
    }
    Ok(())
}

/// The final reader owns its protected job until dropped. It exposes neither
/// raw device handles nor VHDX/container bytes. This proves staging only, not
/// host-storage independence, physical-target safety, or OS boot compatibility.
pub struct SealedStage {
    reader: File,
    owner: OwnedStageDisk,
    fingerprint: ImageFingerprint,
    engine: Image,
    stamp: Stamp,
}
impl SealedStage {
    pub fn fingerprint(&self) -> &ImageFingerprint {
        &self.fingerprint
    }
    pub fn engine(&self) -> &Image {
        &self.engine
    }
    pub fn revalidate(&self) -> Result<(), StageError> {
        self.owner.revalidate()?;
        let value = stamp(&self.reader)?;
        if value != self.stamp || value.len != self.fingerprint.bytes {
            return Err(StageError::Invalid("sealed length changed"));
        }
        Ok(())
    }
}
impl Read for SealedStage {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.revalidate().map_err(io::Error::other)?;
        self.reader.read(bytes)
    }
}
impl Seek for SealedStage {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.revalidate().map_err(io::Error::other)?;
        self.reader.seek(pos)
    }
}

/// Fully build and persist one private image, without selecting or writing any
/// physical target. Inputs must already belong to the authenticated backend.
/// Config files are ordinary verified inputs; this does not translate settings.
/// Cancellation is observed between I/O calls; an in-flight provider format is
/// waited out before cleanup. Requires prior privilege bootstrap, never UAC.
pub fn build(
    installation: Arc<MachineInstallation>,
    plan: &Plan,
    payloads: &Payloads<'_>,
    geometry: Geometry,
    inputs: Vec<StageInput>,
    cancel: &AtomicBool,
    progress: impl FnMut(StageProgress),
) -> Result<SealedStage, StageError> {
    build_under(
        Root::Installation(installation),
        plan,
        payloads,
        geometry,
        inputs,
        cancel,
        progress,
    )
}
fn build_under(
    root: Root,
    plan: &Plan,
    payloads: &Payloads<'_>,
    geometry: Geometry,
    mut inputs: Vec<StageInput>,
    cancel: &AtomicBool,
    mut progress: impl FnMut(StageProgress),
) -> Result<SealedStage, StageError> {
    let entries: Vec<_> = inputs.iter().map(|v| v.entry.clone()).collect();
    build_policy::admit(plan, &geometry, &entries)?;
    cancelled(cancel)?;
    for item in &inputs {
        let meta = item
            .file
            .metadata()
            .map_err(|e| error("source metadata", e))?;
        if !meta.is_file() || meta.len() != item.entry.bytes {
            return Err(StageError::Invalid("source length or kind differs"));
        }
    }
    root.revalidate()?;
    let budget = geometry
        .size_bytes
        .checked_mul(2)
        .and_then(|v| v.checked_add(256 * 1024 * 1024))
        .ok_or(StageError::Invalid("stage space budget overflow"))?;
    if device::space(root.path())? < budget {
        return Err(StageError::Invalid("insufficient private staging space"));
    }
    let mut owner = OwnedStageDisk::create_under(root, geometry.clone())?;
    let seed_path = owner.directory.join(SEED);
    progress(StageProgress {
        phase: "building_seed",
        completed_bytes: 0,
        total_bytes: geometry.size_bytes,
        file_index: None,
    });
    let mut seed = create_file(&mut owner, SEED)?;
    let image = engine::initialize_empty_file(&mut seed, plan, payloads)
        .map_err(|e| context("build pinned engine seed", e))?;
    let digest = hash(&mut seed, geometry.size_bytes, cancel)?;
    owner.attach(false)?;
    let mut view = View::open(&owner)?;
    view.verify_blank(cancel)?;
    let facts = view.facts();
    let mut writer = view.writer()?;
    write_image(
        &mut writer,
        &mut seed,
        &view.snapshot,
        digest,
        cancel,
        |v| {
            progress(StageProgress {
                phase: match v.phase {
                    crate::writer::Phase::CheckingSource => "checking_seed",
                    crate::writer::Phase::Writing => "seeding_vhd",
                    crate::writer::Phase::Flushing => "flushing_seed",
                    crate::writer::Phase::Verifying => "verifying_seed",
                    crate::writer::Phase::Complete => "seeded",
                },
                completed_bytes: v.completed_bytes,
                total_bytes: geometry.size_bytes,
                file_index: None,
            })
        },
    )
    .map_err(|e| context("seed owned VHD", e))?;
    drop(writer);
    view.check()?;
    drop(view);
    drop(seed);
    std::fs::remove_file(&seed_path).map_err(|e| error("remove seed", e))?;
    owner.owned_files.retain(|n| *n != SEED);
    owner.detach()?;
    owner.attach(false)?;
    let view = View::open(&owner)?;
    view.same_disk(&facts.0, &facts.1)?;
    let data = select(&view, &image, cancel)?;
    cancelled(cancel)?;
    progress(StageProgress {
        phase: "formatting_data",
        completed_bytes: 0,
        total_bytes: 0,
        file_index: None,
    });
    view.check()?;
    format::format_owned(&data)?;
    view.check()?;
    cancelled(cancel)?;
    if select(&view, &image, cancel)? != data {
        return Err(StageError::Invalid("formatted volume identity changed"));
    }
    let destination = device::root(&data)?;
    let (available, unit) = device::data_space(&data)?;
    validate_manifest(&entries, available.saturating_sub(1024 * 1024), unit)
        .map_err(|e| context("formatted data capacity", e))?;
    for (index, input) in inputs.iter_mut().enumerate() {
        view.check()?;
        copy_one(&destination, &mut input.file, &input.entry, cancel, |v| {
            progress(StageProgress {
                phase: match v.phase {
                    isohopper_media::copy::Phase::CheckingSource => "checking_source",
                    isohopper_media::copy::Phase::Writing => "copying_data",
                    isohopper_media::copy::Phase::Flushing => "flushing_data",
                    isohopper_media::copy::Phase::Verifying => "verifying_data",
                    isohopper_media::copy::Phase::Complete => "copied",
                },
                completed_bytes: v.completed_bytes,
                total_bytes: v.total_bytes,
                file_index: Some(index),
            })
        })
        .map_err(|e| context("copy staged source", e))?;
    }
    verify_files(&destination, &entries, cancel)?;
    drop(destination);
    device::flush(&data)?;
    view.check()?;
    drop(view);
    drop(inputs);
    owner.detach()?;
    owner.attach(true)?;
    let view = View::open(&owner)?;
    view.same_disk(&facts.0, &facts.1)?;
    view.read_only()?;
    let data = select(&view, &image, cancel)?;
    let destination = device::root(&data)?;
    verify_files(&destination, &entries, cancel)?;
    drop(destination);
    // Close the verified view to create a private fixed output, then bind a new
    // read-only view to the same retained VHD before exporting logical bytes.
    drop(view);
    let mut output = create_file(&mut owner, FINAL)?;
    let final_path = owner.directory.join(FINAL);
    let mut view = View::open(&owner)?;
    view.same_disk(&facts.0, &facts.1)?;
    view.read_only()?;
    let mut left = geometry.size_bytes;
    let mut buffer = vec![0u8; crate::writer::CHUNK_BYTES];
    let mut exported = Sha256::new();
    while left > 0 {
        cancelled(cancel)?;
        view.check()?;
        let n = left.min(buffer.len() as u64) as usize;
        view.file
            .read_exact(&mut buffer[..n])
            .map_err(|e| error("read logical VHD bytes", e))?;
        output
            .write_all(&buffer[..n])
            .map_err(|e| error("write raw stage image", e))?;
        exported.update(&buffer[..n]);
        left -= n as u64;
        progress(StageProgress {
            phase: "exporting_raw",
            completed_bytes: geometry.size_bytes - left,
            total_bytes: geometry.size_bytes,
            file_index: None,
        });
    }
    output.sync_all().map_err(|e| error("flush raw image", e))?;
    view.check()?;
    view.read_only()?;
    drop(view);
    owner.detach()?;
    drop(owner.disk.take());
    std::fs::remove_file(owner.directory.join(BACKING_NAME))
        .map_err(|e| error("remove completed VHDX", e))?;
    owner.owned_files.retain(|n| *n != BACKING_NAME);
    let expected: [u8; 32] = exported.finalize().into();
    if hash(&mut output, geometry.size_bytes, cancel)? != expected {
        return Err(StageError::Invalid("raw image readback differs"));
    }
    engine::verify(&final_path, &image).map_err(|e| context("persisted engine regions", e))?;
    let reader = seal(output, expected, geometry.size_bytes, cancel)?;
    owner.revalidate()?;
    progress(StageProgress {
        phase: "sealed",
        completed_bytes: geometry.size_bytes,
        total_bytes: geometry.size_bytes,
        file_index: None,
    });
    let saved_stamp = stamp(&reader)?;
    Ok(SealedStage {
        stamp: saved_stamp,
        reader,
        owner,
        fingerprint: ImageFingerprint {
            bytes: geometry.size_bytes,
            sha256: expected,
        },
        engine: image,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore = "requires elevated Windows and pinned engine archive; owns its new disposable VHD only"]
    fn native_stage_builds_persists_and_seals_pinned_engine() {
        let archive_path = std::env::var_os("ISOHOPPER_ENGINE_ARCHIVE")
            .expect("set pinned upstream Linux archive path");
        let archive = std::fs::read(archive_path).unwrap();
        let imported = engine::archive::import(&archive).unwrap();
        let payloads = imported.payloads();
        let _privilege = super::super::tests::Privilege::set(true);
        let token_stamp = super::super::tests::modified_id();
        let temp = coordinator_test::temp_root();
        let path = temp.path().join("private-build");
        let descriptor = Descriptor::private().unwrap();
        let handle = create_private_directory(&path, &descriptor).unwrap();
        let make_root = || Root::Fixture {
            path: path.clone(),
            handle: handle.try_clone().unwrap(),
        };
        let plan = Plan::new(256 << 20, 512).unwrap();
        let geometry = Geometry {
            size_bytes: 256 << 20,
            logical_sector_size: 512,
            physical_sector_size: 4096,
        };
        let mut inputs = Vec::new();
        let mut original_paths = Vec::new();
        for (index, name) in [
            "Windows/Win11.iso",
            "Mac/MacOS.img",
            "Linux tools/日本語.img",
            "ventoy/ventoy.json",
        ]
        .iter()
        .enumerate()
        {
            let data = if index == 3 {
                b"{}".to_vec()
            } else {
                (0..8193 + index)
                    .map(|v| ((v + index) % 251) as u8)
                    .collect()
            };
            let source = temp.path().join(format!("source-{index}"));
            std::fs::write(&source, &data).unwrap();
            inputs.push(StageInput {
                file: File::open(&source).unwrap(),
                entry: CopyEntry {
                    relative_path: name.to_string(),
                    bytes: data.len() as u64,
                    sha256: Sha256::digest(&data).into(),
                },
            });
            original_paths.push(source);
        }
        let cancelled_input = StageInput {
            file: inputs[0].file.try_clone().unwrap(),
            entry: inputs[0].entry.clone(),
        };
        assert!(
            build_under(
                make_root(),
                &plan,
                &payloads,
                geometry.clone(),
                vec![cancelled_input],
                &AtomicBool::new(true),
                |_| {}
            )
            .is_err()
        );
        assert_eq!(std::fs::read_dir(&path).unwrap().count(), 0);
        let entries: Vec<_> = inputs.iter().map(|input| input.entry.clone()).collect();
        let mut phases = Vec::new();
        let mut sealed = build_under(
            make_root(),
            &plan,
            &payloads,
            geometry.clone(),
            inputs,
            &AtomicBool::new(false),
            |p| phases.push(p.phase),
        )
        .unwrap();
        assert!(phases.contains(&"formatting_data"));
        assert!(phases.contains(&"verifying_seed"));
        assert!(phases.contains(&"verifying_data"));
        assert_eq!(phases.last(), Some(&"sealed"));
        let final_path = sealed.owner.directory.join(FINAL);
        let denied = OpenOptions::new()
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&final_path)
            .unwrap_err();
        assert_eq!(denied.raw_os_error(), Some(32));
        assert!(!sealed.owner.directory.join(BACKING_NAME).exists());
        assert!(!sealed.owner.directory.join(SEED).exists());
        for source in original_paths {
            std::fs::write(source, b"changed after seal").unwrap();
        }
        let fingerprint = sealed.fingerprint.clone();
        assert_eq!(
            hash(
                &mut sealed.reader,
                fingerprint.bytes,
                &AtomicBool::new(false)
            )
            .unwrap(),
            fingerprint.sha256
        );
        let mut signature = [0; 8];
        sealed.seek(SeekFrom::Start(512)).unwrap();
        sealed.read_exact(&mut signature).unwrap();
        assert_eq!(&signature, b"EFI PART");
        sealed.revalidate().unwrap();
        let directory = sealed.owner.directory.clone();
        coordinator_test::exercise(sealed, make_root(), entries);
        assert!(!directory.exists());
        // A bootable blank library follows the same formatter/export path.
        // No source file or synthetic placeholder is required.
        let mut empty = build_under(
            make_root(),
            &plan,
            &payloads,
            geometry,
            Vec::new(),
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        let empty_fingerprint = empty.fingerprint.clone();
        assert_eq!(
            hash(
                &mut empty.reader,
                empty_fingerprint.bytes,
                &AtomicBool::new(false)
            )
            .unwrap(),
            empty_fingerprint.sha256
        );
        empty
            .seek(SeekFrom::Start(
                plan.layout().partitions[0].start_lba * 512 + 3,
            ))
            .unwrap();
        let mut filesystem = [0; 8];
        empty.read_exact(&mut filesystem).unwrap();
        assert_eq!(&filesystem, b"EXFAT   ");
        let empty_directory = empty.owner.directory.clone();
        drop(empty);
        assert!(!empty_directory.exists());
        println!(
            "OWNED_EMPTY_STAGE_OK sources=0 exfat=true persisted_raw_sha256=true physical_write=false"
        );
        drop(handle);
        std::fs::remove_dir(&path).unwrap();
        assert_eq!(super::super::tests::modified_id(), token_stamp);
        println!(
            "OWNED_STAGE_SEALED_OK nested_files=4 persisted=true raw_sha256=true engine_regions=true physical_write=false"
        );
    }
}
