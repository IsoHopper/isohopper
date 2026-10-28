// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::writer::{
    CHUNK_BYTES, DeviceSnapshot, Failure, Geometry, Phase, RetainedDevice, StableDeviceId,
    write_image,
};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    io::{self, Cursor, Read, Seek, SeekFrom},
    rc::Rc,
    sync::atomic::{AtomicBool, Ordering},
};

fn image() -> Vec<u8> {
    (0..CHUNK_BYTES + 8192).map(|i| (i % 251) as u8).collect()
}

fn snapshot(size: u64, logical: u32, physical: u32) -> DeviceSnapshot {
    DeviceSnapshot {
        device_number: 7,
        serial: "TEST-USB-1234".into(),
        device_id: None,
        bus_type: 7,
        geometry: Geometry {
            size_bytes: size,
            logical_sector_size: logical,
            physical_sector_size: physical,
        },
    }
}

fn device_id(last: u8) -> StableDeviceId {
    let mut bytes = [0x23; 16];
    bytes[0] = 0x60;
    bytes[15] = last;
    StableDeviceId::from_naa128(bytes).unwrap()
}

struct Device {
    current: DeviceSnapshot,
    bytes: Vec<u8>,
    writes: usize,
    reads: usize,
    flushed: bool,
    snapshots: usize,
    fault: &'static str,
}

impl Device {
    fn new(current: DeviceSnapshot) -> Self {
        Self {
            bytes: vec![0xa5; current.geometry.size_bytes as usize],
            current,
            writes: 0,
            reads: 0,
            flushed: false,
            snapshots: 0,
            fault: "",
        }
    }

    fn check_io(&self, offset: u64, pointer: usize, len: usize) {
        assert!(len > 0 && len <= CHUNK_BYTES);
        assert_eq!(
            offset % u64::from(self.current.geometry.logical_sector_size),
            0
        );
        assert_eq!(len % self.current.geometry.logical_sector_size as usize, 0);
        assert_eq!(
            pointer % self.current.geometry.physical_sector_size as usize,
            0
        );
        assert!(offset + len as u64 <= self.current.geometry.size_bytes);
    }
}

impl RetainedDevice for Device {
    fn snapshot(&mut self) -> io::Result<DeviceSnapshot> {
        self.snapshots += 1;
        let mut result = self.current.clone();
        if self.fault == "identity_after_write" && self.writes > 0 {
            result.serial.push('X');
        }
        if self.fault == "identity_before_write" && self.snapshots > 1 {
            result.serial.push('X');
        }
        if (self.fault == "device_id_before_write" && self.snapshots > 1)
            || (self.fault == "device_id_after_write" && self.writes > 0)
        {
            result.device_id = Some(device_id(2));
        }
        if (self.fault == "device_id_missing_before_write" && self.snapshots > 1)
            || (self.fault == "device_id_missing_after_write" && self.writes > 0)
        {
            result.device_id = None;
        }
        Ok(result)
    }

    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        assert!(self.flushed, "readback must follow flush");
        self.check_io(offset, buffer.as_ptr() as usize, buffer.len());
        self.reads += 1;
        if self.fault == "read_error" {
            return Err(io::Error::other("device removed"));
        }
        buffer.copy_from_slice(&self.bytes[offset as usize..offset as usize + buffer.len()]);
        if self.fault == "corrupt" {
            buffer[0] ^= 1;
        }
        Ok(if self.fault == "short_read" {
            buffer.len() - 1
        } else {
            buffer.len()
        })
    }

    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> io::Result<usize> {
        assert!(!self.flushed);
        self.check_io(offset, buffer.as_ptr() as usize, buffer.len());
        self.writes += 1;
        if self.fault == "write_error" {
            return Err(io::Error::other("device removed"));
        }
        let count = if self.fault == "short_write" {
            buffer.len() - 1
        } else {
            buffer.len()
        };
        self.bytes[offset as usize..offset as usize + count].copy_from_slice(&buffer[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.fault == "flush" {
            return Err(io::Error::other("flush failed"));
        }
        self.flushed = true;
        Ok(())
    }
}

#[test]
fn writes_and_verifies_every_byte_with_aligned_bounded_chunks() {
    let image = image();
    let digest: [u8; 32] = Sha256::digest(&image).into();
    for (logical, physical) in [(512, 512), (512, 4096), (4096, 4096), (4096, 65536)] {
        let expected = snapshot(image.len() as u64, logical, physical);
        let mut device = Device::new(expected.clone());
        let mut events = Vec::new();
        let report = write_image(
            &mut device,
            &mut Cursor::new(&image),
            &expected,
            digest,
            &AtomicBool::new(false),
            |event| events.push(event),
        )
        .unwrap();
        assert_eq!(device.bytes, image);
        assert_eq!(device.writes, 2);
        assert_eq!(device.reads, 2);
        assert_eq!(report.bytes_written, image.len() as u64);
        assert_eq!(report.bytes_verified, image.len() as u64);
        assert_eq!(report.sha256, digest);
        assert_eq!(events.last().unwrap().phase, Phase::Complete);
        assert!(events.iter().all(|e| e.completed_bytes <= e.total_bytes));
    }
}

#[test]
fn identity_geometry_size_and_digest_fail_before_any_write() {
    let image = image();
    let digest: [u8; 32] = Sha256::digest(&image).into();
    let good = snapshot(image.len() as u64, 512, 4096);
    let mut cases = Vec::new();
    for field in [
        "number",
        "serial",
        "device_id",
        "bus",
        "size",
        "logical",
        "physical",
    ] {
        let mut changed = good.clone();
        match field {
            "number" => changed.device_number += 1,
            "serial" => changed.serial.push('X'),
            "device_id" => changed.device_id = Some(device_id(1)),
            "bus" => changed.bus_type += 1,
            "size" => changed.geometry.size_bytes += 512,
            "logical" => changed.geometry.logical_sector_size = 4096,
            "physical" => changed.geometry.physical_sector_size = 512,
            _ => unreachable!(),
        }
        cases.push(changed);
    }
    for expected in cases {
        let mut device = Device::new(good.clone());
        let error = write_image(
            &mut device,
            &mut Cursor::new(&image),
            &expected,
            digest,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(error.failure, Failure::IdentityChanged));
        assert!(!error.target_may_be_incomplete);
        assert_eq!(device.writes, 0);
    }
    for (source, hash) in [(&image[..image.len() - 1], digest), (&image[..], [0; 32])] {
        let mut device = Device::new(good.clone());
        let error = write_image(
            &mut device,
            &mut Cursor::new(source),
            &good,
            hash,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(
            error.failure,
            Failure::SourceSize | Failure::SourceDigest
        ));
        assert!(!error.target_may_be_incomplete);
        assert_eq!(device.writes, 0);
    }
}

#[test]
fn validated_device_identity_allows_actual_absent_serial_but_not_malformed_serial() {
    let image = image();
    let digest: [u8; 32] = Sha256::digest(&image).into();
    let mut expected = snapshot(image.len() as u64, 512, 4096);
    expected.device_id = Some(device_id(1));
    for serial in [String::new(), "ACTUAL-SERIAL".into()] {
        expected.serial = serial;
        let mut device = Device::new(expected.clone());
        let report = write_image(
            &mut device,
            &mut Cursor::new(&image),
            &expected,
            digest,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        assert_eq!(report.sha256, digest);
        assert_eq!(device.bytes, image);
    }
    for serial in [" ".into(), "\n".into(), "a".repeat(4097)] {
        expected.serial = serial;
        let mut device = Device::new(expected.clone());
        let error = write_image(
            &mut device,
            &mut Cursor::new(&image),
            &expected,
            digest,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(error.failure, Failure::Identity));
        assert_eq!(device.snapshots, 0);
        assert_eq!(device.writes, 0);
    }
    for nibble in 0..16 {
        let mut bytes = [0x23; 16];
        bytes[0] = nibble << 4;
        assert_eq!(StableDeviceId::from_naa128(bytes).is_ok(), nibble == 6);
    }
    assert_eq!(device_id(1).as_bytes()[15], 1);
}

#[test]
fn device_id_changes_or_disappearance_never_allow_success() {
    let image = image();
    let digest: [u8; 32] = Sha256::digest(&image).into();
    for serial in ["", "ACTUAL-SERIAL"] {
        let mut expected = snapshot(image.len() as u64, 512, 4096);
        expected.serial = serial.into();
        expected.device_id = Some(device_id(1));
        for fault in [
            "device_id_before_write",
            "device_id_after_write",
            "device_id_missing_before_write",
            "device_id_missing_after_write",
        ] {
            let mut device = Device::new(expected.clone());
            device.fault = fault;
            let mut completed = false;
            let error = write_image(
                &mut device,
                &mut Cursor::new(&image),
                &expected,
                digest,
                &AtomicBool::new(false),
                |e| completed |= e.phase == Phase::Complete,
            )
            .unwrap_err();
            assert!(matches!(error.failure, Failure::IdentityChanged), "{fault}");
            assert!(!completed);
            assert_eq!(
                error.target_may_be_incomplete,
                fault.ends_with("after_write")
            );
            assert_eq!(device.writes == 0, fault.ends_with("before_write"));
        }
    }
}

#[test]
fn invalid_geometry_and_missing_identity_fail_without_device_io() {
    let image = image();
    let good = snapshot(image.len() as u64, 512, 4096);
    for (size, logical, physical) in [
        (0, 512, 512),
        (u64::MAX, 512, 4096),
        (i64::MAX as u64 + 1, 512, 4096),
        (123, 512, 4096),
        (4096, 0, 4096),
        (4096, 1024, 4096),
        (4096, 4096, 512),
        (4096, 512, 3000),
        (4096, 512, 65536),
        (4096, 512, 2 * CHUNK_BYTES as u32),
    ] {
        let mut device = Device::new(good.clone());
        let expected = snapshot(size, logical, physical);
        let error = write_image(
            &mut device,
            &mut Cursor::new(&image),
            &expected,
            [0; 32],
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap_err();
        assert!(matches!(error.failure, Failure::Geometry));
        assert!(!error.target_may_be_incomplete);
        assert_eq!(device.writes, 0);
    }
    let mut device = Device::new(good.clone());
    let mut missing = good;
    missing.serial.clear();
    let error = write_image(
        &mut device,
        &mut Cursor::new(&image),
        &missing,
        [0; 32],
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(error.failure, Failure::Identity));
    assert_eq!(device.writes, 0);
}

#[test]
fn cancellation_is_distinguished_before_and_after_writing() {
    let image = image();
    let digest: [u8; 32] = Sha256::digest(&image).into();
    let expected = snapshot(image.len() as u64, 512, 4096);
    for during in [Phase::CheckingSource, Phase::Writing, Phase::Verifying] {
        let mut device = Device::new(expected.clone());
        let cancel = AtomicBool::new(false);
        let error = write_image(
            &mut device,
            &mut Cursor::new(&image),
            &expected,
            digest,
            &cancel,
            |event| {
                if event.phase == during && event.completed_bytes > 0 {
                    cancel.store(true, Ordering::Release);
                }
            },
        )
        .unwrap_err();
        assert!(matches!(error.failure, Failure::Cancelled));
        assert_eq!(
            error.target_may_be_incomplete,
            during != Phase::CheckingSource
        );
        assert_eq!(device.writes == 0, during == Phase::CheckingSource);
    }
}

#[test]
fn failed_or_partial_writes_and_readback_never_report_success() {
    let image = image();
    let digest: [u8; 32] = Sha256::digest(&image).into();
    let expected = snapshot(image.len() as u64, 512, 4096);
    for fault in [
        "write_error",
        "short_write",
        "flush",
        "read_error",
        "short_read",
        "corrupt",
        "identity_after_write",
    ] {
        let mut device = Device::new(expected.clone());
        device.fault = fault;
        let mut completed = false;
        let error = write_image(
            &mut device,
            &mut Cursor::new(&image),
            &expected,
            digest,
            &AtomicBool::new(false),
            |e| completed |= e.phase == Phase::Complete,
        )
        .unwrap_err();
        assert!(error.target_may_be_incomplete, "{fault}");
        assert!(!completed, "{fault}");
        assert!(device.writes > 0);
        match fault {
            "short_write" => assert!(matches!(error.failure, Failure::ShortWrite)),
            "short_read" => assert!(matches!(error.failure, Failure::ShortRead)),
            "corrupt" => assert!(matches!(error.failure, Failure::ReadbackDigest)),
            "identity_after_write" => assert!(matches!(error.failure, Failure::IdentityChanged)),
            _ => assert!(matches!(error.failure, Failure::Io(_))),
        }
    }
}

#[test]
fn revalidation_after_source_check_and_initial_cancellation_prevent_writes() {
    let image = image();
    let digest: [u8; 32] = Sha256::digest(&image).into();
    let expected = snapshot(image.len() as u64, 512, 4096);
    let mut device = Device::new(expected.clone());
    device.fault = "identity_before_write";
    let error = write_image(
        &mut device,
        &mut Cursor::new(&image),
        &expected,
        digest,
        &AtomicBool::new(false),
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(error.failure, Failure::IdentityChanged));
    assert!(!error.target_may_be_incomplete);
    assert_eq!(device.writes, 0);
    let mut device = Device::new(expected.clone());
    let error = write_image(
        &mut device,
        &mut Cursor::new(&image),
        &expected,
        digest,
        &AtomicBool::new(true),
        |_| {},
    )
    .unwrap_err();
    assert!(matches!(error.failure, Failure::Cancelled));
    assert_eq!(device.snapshots, 0);
    assert_eq!(device.writes, 0);
}

struct SharedSource(Rc<RefCell<Cursor<Vec<u8>>>>);
impl Read for SharedSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        // Force normal partial source reads without exposing partial device I/O.
        let count = buffer.len().min(137);
        self.0.borrow_mut().read(&mut buffer[..count])
    }
}
impl Seek for SharedSource {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.0.borrow_mut().seek(position)
    }
}

#[test]
fn source_mutation_growth_or_shrinkage_after_preflight_is_incomplete() {
    let image = image();
    let digest: [u8; 32] = Sha256::digest(&image).into();
    let expected = snapshot(image.len() as u64, 512, 4096);
    for mutation in ["none", "content", "grow", "shrink"] {
        let mut device = Device::new(expected.clone());
        let inner = Rc::new(RefCell::new(Cursor::new(image.clone())));
        let mut source = SharedSource(Rc::clone(&inner));
        let mut changed = false;
        let result = write_image(
            &mut device,
            &mut source,
            &expected,
            digest,
            &AtomicBool::new(false),
            |event| {
                if !changed && event.phase == Phase::Writing && event.completed_bytes > 0 {
                    changed = true;
                    let mut file = inner.borrow_mut();
                    match mutation {
                        "content" => *file.get_mut().last_mut().unwrap() ^= 1,
                        "grow" => file.get_mut().extend_from_slice(&[0; 512]),
                        "shrink" => file.get_mut().truncate(CHUNK_BYTES),
                        _ => {}
                    }
                }
            },
        );
        if mutation == "none" {
            assert!(result.is_ok());
        } else {
            let error = result.unwrap_err();
            assert!(error.target_may_be_incomplete);
            assert!(matches!(
                error.failure,
                Failure::SourceSize | Failure::SourceDigest
            ));
            assert!(!device.flushed);
        }
    }
}
