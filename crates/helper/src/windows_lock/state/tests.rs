// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::writer::Geometry;
use std::{cell::RefCell, collections::BTreeMap, rc::Rc};

fn target() -> DeviceSnapshot {
    DeviceSnapshot {
        device_number: 7,
        serial: "OWNED-TEST-DISK".into(),
        device_id: None,
        bus_type: 7,
        geometry: Geometry {
            size_bytes: 64 * 1024 * 1024,
            logical_sector_size: 512,
            physical_sector_size: 4096,
        },
    }
}

fn name(n: u32) -> VolumeName {
    VolumeName::parse(&format!(r"\\?\Volume{{00000000-0000-0000-0000-{n:012x}}}\")).unwrap()
}

fn extent(disk: u32, start: u64) -> Extent {
    Extent {
        disk,
        start,
        length: 1024 * 1024,
    }
}

fn layout() -> DiskLayout {
    DiskLayout {
        style: 1,
        identity: [1; 16],
        partitions: vec![
            Partition {
                number: 1,
                start: 1024 * 1024,
                length: 1024 * 1024,
                kind: [1; 16],
                identity: [2; 16],
            },
            Partition {
                number: 2,
                start: 2 * 1024 * 1024,
                length: 1024 * 1024,
                kind: [1; 16],
                identity: [3; 16],
            },
        ],
    }
}

#[derive(Default)]
struct Events {
    entries: Vec<String>,
    active: usize,
}
struct FakeVolume {
    name: VolumeName,
    extents: Option<Vec<Extent>>,
    events: Rc<RefCell<Events>>,
    fail: &'static str,
    locked: bool,
}
impl Volume for FakeVolume {
    fn extents(&mut self) -> Result<Option<Vec<Extent>>, LockError> {
        Ok(self.extents.clone())
    }
    fn lock(&mut self) -> Result<(), LockError> {
        self.events
            .borrow_mut()
            .entries
            .push(format!("lock:{}", self.name.0));
        if self.fail == "lock" {
            return Err(LockError::MissingEvidence("injected lock failure"));
        }
        self.locked = true;
        self.events.borrow_mut().active += 1;
        Ok(())
    }
    fn dismount(&mut self) -> Result<(), LockError> {
        assert!(self.locked, "dismount may only follow successful lock");
        self.events
            .borrow_mut()
            .entries
            .push(format!("dismount:{}", self.name.0));
        if self.fail == "dismount" {
            Err(LockError::MissingEvidence("injected dismount failure"))
        } else {
            Ok(())
        }
    }
}
impl Drop for FakeVolume {
    fn drop(&mut self) {
        if self.locked {
            self.events.borrow_mut().active -= 1;
        }
    }
}
struct Fake {
    events: Rc<RefCell<Events>>,
    layout: DiskLayout,
    volumes: BTreeMap<VolumeName, Option<Vec<Extent>>>,
    fault: &'static str,
    snapshots: usize,
    enumerations: usize,
    writable_opens: usize,
    opens: BTreeMap<VolumeName, usize>,
}
impl Fake {
    fn new(fault: &'static str) -> Self {
        Self {
            events: Rc::default(),
            layout: layout(),
            volumes: BTreeMap::from([
                (name(1), Some(vec![extent(7, 1024 * 1024)])),
                (name(2), Some(vec![extent(7, 2 * 1024 * 1024)])),
                (name(3), Some(vec![extent(99, 1024 * 1024)])),
                (name(4), None), // independently identified CD-ROM
            ]),
            fault,
            snapshots: 0,
            enumerations: 0,
            writable_opens: 0,
            opens: BTreeMap::new(),
        }
    }
}
impl Backend for Fake {
    type Volume = FakeVolume;
    fn snapshot(&mut self) -> Result<DeviceSnapshot, LockError> {
        self.snapshots += 1;
        let mut value = target();
        if self.fault == "identity" || (self.fault == "identity_after" && self.snapshots > 2) {
            value.serial.push('x');
        }
        Ok(value)
    }
    fn layout(&mut self) -> Result<DiskLayout, LockError> {
        let mut result = self.layout.clone();
        if self.fault == "layout_after" && self.enumerations > 1 {
            result.identity[0] ^= 1;
        }
        Ok(result)
    }
    fn enumerate(&mut self) -> Result<Vec<VolumeName>, LockError> {
        self.enumerations += 1;
        if self.fault == "enumerate" {
            return Err(LockError::MissingEvidence("injected enumeration failure"));
        }
        let mut result: Vec<_> = self.volumes.keys().cloned().collect();
        if self.fault == "arrival" && self.enumerations > 1 {
            result.push(name(5));
        }
        if self.fault == "duplicate" {
            result.push(name(1));
        }
        if self.fault == "volume_limit" {
            result = (0..=MAX_VOLUMES).map(|index| name(index as u32)).collect();
        }
        Ok(result)
    }
    fn open(&mut self, name: &VolumeName, write: bool) -> Result<Self::Volume, LockError> {
        let opens = self.opens.entry(name.clone()).or_default();
        *opens += 1;
        let reopened_read_only = !write && *opens > 1;
        if write {
            self.writable_opens += 1;
        }
        if self.fault == "unclassifiable" && name == &self::name(3) {
            return Err(LockError::MissingEvidence("unknown volume"));
        }
        let mut extents = self
            .volumes
            .get(name)
            .ok_or(LockError::MissingEvidence("injected new volume"))?
            .clone();
        if (self.fault == "reopen" || (self.fault == "reopen_second" && name == &self::name(2)))
            && write
        {
            extents.as_mut().unwrap()[0].disk = 99;
        }
        if self.fault == "probe_reopen" && reopened_read_only {
            extents.as_mut().unwrap()[0].disk = 99;
        }
        if self.fault == "foreign_volume_changed" && self.enumerations > 1 && name == &self::name(3)
        {
            extents.as_mut().unwrap()[0].disk = 7;
        }
        let fail = if name == &self::name(2) {
            self.fault
        } else {
            ""
        };
        Ok(FakeVolume {
            name: name.clone(),
            extents,
            events: self.events.clone(),
            fail,
            locked: false,
        })
    }
}

#[test]
fn capability_retains_only_target_locks_and_unwinds_on_drop() {
    let mut backend = Fake::new("");
    let held = acquire(&mut backend, &target()).unwrap();
    assert_eq!(held.len(), 2);
    assert_eq!(backend.events.borrow().active, 2);
    assert_eq!(backend.events.borrow().entries.len(), 4);
    drop(held);
    assert_eq!(backend.events.borrow().active, 0);
}

#[test]
fn read_only_probe_retains_exact_coverage_without_writable_opens_or_locks() {
    let mut backend = Fake::new("");
    let mut observed = probe(&mut backend, &target()).unwrap();
    assert_eq!(observed.held.len(), 2);
    assert_eq!(observed.coverage.device, target());
    assert_eq!(observed.coverage.partition_style, 1);
    assert_eq!(observed.coverage.layout_identity, [1; 16]);
    assert_eq!(observed.coverage.partitions.len(), 2);
    let first = &observed.coverage.partitions[0];
    assert_eq!(first.partition_number, 1);
    assert_eq!(first.start_offset, 1024 * 1024);
    assert_eq!(first.length_bytes, 1024 * 1024);
    assert_eq!(first.partition_type, [1; 16]);
    assert_eq!(first.partition_identity, [2; 16]);
    assert_eq!(first.volume_guid, Some(name(1).0));
    assert!(first.volume_required);
    let target_opens = [backend.opens[&name(1)], backend.opens[&name(2)]];
    revalidate_probe(&mut backend, &mut observed).unwrap();
    assert_eq!(
        [backend.opens[&name(1)], backend.opens[&name(2)]],
        target_opens.map(|count| count + 1)
    );
    assert_eq!(backend.writable_opens, 0);
    assert_eq!(backend.events.borrow().active, 0);
    assert!(backend.events.borrow().entries.is_empty());
}

#[test]
fn read_only_probe_rejects_rebound_guid_with_unchanged_retained_handle() {
    let mut backend = Fake::new("");
    let mut observed = probe(&mut backend, &target()).unwrap();
    let original = observed.held[0].volume.extents().unwrap();
    backend
        .volumes
        .insert(name(1), Some(vec![extent(99, 1024 * 1024)]));

    assert_eq!(observed.held[0].volume.extents().unwrap(), original);
    assert!(matches!(
        revalidate_probe(&mut backend, &mut observed),
        Err(LockError::VolumeChanged)
    ));
    assert_eq!(observed.held[0].volume.extents().unwrap(), original);
    assert_eq!(backend.writable_opens, 0);
    assert_eq!(backend.events.borrow().active, 0);
    assert!(backend.events.borrow().entries.is_empty());
}

#[test]
fn read_only_probe_rejects_retained_extent_or_topology_changes() {
    for change in 0..7 {
        let mut backend = Fake::new("");
        let mut observed = probe(&mut backend, &target()).unwrap();
        match change {
            0 => backend.fault = "identity",
            1 => backend.layout.identity[0] ^= 1,
            2 => backend.layout.partitions[0].identity[0] ^= 1,
            3 => {
                observed.held[0].volume.extents.as_mut().unwrap()[0].start += 512;
            }
            4 => {
                backend.volumes.remove(&name(1));
            }
            5 => {
                let extents = backend.volumes.remove(&name(1)).unwrap();
                backend.volumes.insert(name(5), extents);
            }
            6 => {
                backend
                    .volumes
                    .insert(name(5), Some(vec![extent(99, 1024 * 1024)]));
            }
            _ => unreachable!(),
        }
        assert!(
            revalidate_probe(&mut backend, &mut observed).is_err(),
            "change {change}"
        );
        assert_eq!(backend.writable_opens, 0);
        assert_eq!(backend.events.borrow().active, 0);
        assert!(backend.events.borrow().entries.is_empty());
    }
}

#[test]
fn read_only_probe_preserves_blank_and_reserved_partition_evidence() {
    let mut backend = Fake::new("");
    backend.layout = DiskLayout {
        style: 2,
        identity: [0; 16],
        partitions: vec![],
    };
    backend.volumes.retain(|name, _| name > &self::name(2));
    let mut observed = probe(&mut backend, &target()).unwrap();
    assert!(observed.held.is_empty());
    assert!(observed.coverage.partitions.is_empty());
    assert_eq!(observed.coverage.partition_style, 2);
    revalidate_probe(&mut backend, &mut observed).unwrap();

    for guid in [
        "21686148-6449-6e6f-744e-656564454649",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae",
    ] {
        backend.layout = parse_layout(&table(1, &gpt_type(guid)), &target().geometry).unwrap();
        let observed = probe(&mut backend, &target()).unwrap();
        assert!(observed.held.is_empty());
        assert_eq!(observed.coverage.partitions.len(), 1);
        assert_eq!(observed.coverage.partitions[0].volume_guid, None);
        assert!(!observed.coverage.partitions[0].volume_required);
    }
    assert_eq!(backend.writable_opens, 0);
    assert!(backend.events.borrow().entries.is_empty());
}

#[test]
fn read_only_probe_refuses_incomplete_or_changing_discovery_without_actions() {
    for fault in [
        "identity",
        "identity_after",
        "layout_after",
        "arrival",
        "foreign_volume_changed",
        "probe_reopen",
        "enumerate",
        "unclassifiable",
        "duplicate",
        "volume_limit",
    ] {
        let mut backend = Fake::new(fault);
        assert!(probe(&mut backend, &target()).is_err(), "{fault}");
        assert_eq!(backend.writable_opens, 0, "{fault}");
        assert!(backend.events.borrow().entries.is_empty(), "{fault}");
    }
    let mut backend = Fake::new("");
    backend.volumes.remove(&name(2));
    assert!(probe(&mut backend, &target()).is_err());
    assert_eq!(backend.writable_opens, 0);
    assert!(backend.events.borrow().entries.is_empty());
}

#[test]
fn read_only_probe_requires_stable_identity_before_discovery() {
    for serial in [
        String::new(),
        " ".into(),
        "bad\nserial".into(),
        "x".repeat(4097),
    ] {
        let mut expected = target();
        expected.serial = serial;
        let mut backend = Fake::new("");
        assert!(matches!(
            probe(&mut backend, &expected),
            Err(LockError::MissingEvidence("stable target identity"))
        ));
        assert_eq!(backend.snapshots, 0);
        assert_eq!(backend.writable_opens, 0);
        assert!(backend.events.borrow().entries.is_empty());
    }
}

fn assert_unmapped_partition_refused(backend: &mut Fake) {
    assert!(matches!(
        acquire(backend, &target()),
        Err(LockError::MissingEvidence(_))
    ));
    assert_eq!(backend.writable_opens, 0);
    assert_eq!(backend.events.borrow().active, 0);
    assert!(backend.events.borrow().entries.is_empty());
}

#[test]
fn incomplete_partition_coverage_refuses_before_writable_opens_or_locks() {
    for missing in 0..4 {
        let mut backend = Fake::new("");
        match missing {
            0 => {
                backend.volumes.remove(&name(2));
            }
            1 => backend.volumes.clear(),
            2 => backend.volumes.retain(|name, _| name > &self::name(2)),
            3 => {
                backend.volumes.insert(name(2), None);
            }
            _ => unreachable!(),
        }
        assert_unmapped_partition_refused(&mut backend);
    }
}

fn gpt_type(guid: &str) -> [u8; 16] {
    let mut bytes: [u8; 16] = hex::decode(guid.replace('-', ""))
        .unwrap()
        .try_into()
        .unwrap();
    // GUID wire representation uses little endian for the first three fields.
    bytes[..4].reverse();
    bytes[4..6].reverse();
    bytes[6..8].reverse();
    bytes
}

#[test]
fn unknown_linux_efi_recovery_and_hidden_partitions_still_require_volumes() {
    for guid in [
        "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", // basic data
        "c12a7328-f81f-11d2-ba4b-00a0c93ec93b", // EFI filesystem
        "de94bba4-06d1-4d40-a16a-bfd50179d6ac", // Windows recovery
        "0fc63daf-8483-4772-8e79-3d69d8477de4", // Linux filesystem
        "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", // Linux swap
        "ffffffff-ffff-ffff-ffff-ffffffffffff", // unknown
        "21686148-6449-6e6f-744e-656564454648", // not BIOS Boot
        "e3c9e316-0b5c-4db8-817d-f92df00215af", // not MSR
    ] {
        for attributes in [0u64, 1 << 62, 1 << 63] {
            let mut bytes = table(1, &gpt_type(guid));
            bytes[112..120].copy_from_slice(&attributes.to_le_bytes());
            let mut backend = Fake::new("");
            backend.layout = parse_layout(&bytes, &target().geometry).unwrap();
            backend.volumes.clear();
            assert_unmapped_partition_refused(&mut backend);
        }
    }
    for kind in [0x07, 0x17, 0x27, 0x82, 0x83, 0xef] {
        let mut backend = Fake::new("");
        backend.layout = parse_layout(&table(0, &[kind]), &target().geometry).unwrap();
        backend.volumes.clear();
        assert_unmapped_partition_refused(&mut backend);
    }
}

#[test]
fn exact_bios_boot_and_msr_types_need_no_volume_but_discovered_volumes_are_locked() {
    for guid in [
        "21686148-6449-6e6f-744e-656564454649",
        "e3c9e316-0b5c-4db8-817d-f92df00215ae",
    ] {
        for discovered in [false, true] {
            let mut backend = Fake::new("");
            backend.layout = parse_layout(&table(1, &gpt_type(guid)), &target().geometry).unwrap();
            backend
                .volumes
                .retain(|name, _| name > &self::name(2) || (discovered && name == &self::name(1)));
            let held = acquire(&mut backend, &target()).unwrap();
            let count = usize::from(discovered);
            assert_eq!(held.len(), count);
            assert_eq!(backend.writable_opens, count);
            assert_eq!(backend.events.borrow().active, count);
            assert_eq!(backend.events.borrow().entries.len(), 2 * count);
            drop(held);
            assert_eq!(backend.events.borrow().active, 0);
        }

        let mut backend = Fake::new("");
        let mut reserved = parse_layout(&table(1, &gpt_type(guid)), &target().geometry)
            .unwrap()
            .partitions
            .remove(0);
        reserved.number = 3;
        reserved.start = 3 * 1024 * 1024;
        backend.layout.partitions.push(reserved);
        let held = acquire(&mut backend, &target()).unwrap();
        assert_eq!(held.len(), 2);
        drop(held);

        backend.events.borrow_mut().entries.clear();
        backend.writable_opens = 0;
        backend.volumes.remove(&name(2));
        assert_unmapped_partition_refused(&mut backend);
    }
}

#[test]
fn raw_blank_disk_requires_no_volume_locks() {
    let mut bytes = [0; 48];
    bytes[..4].copy_from_slice(&2u32.to_le_bytes());
    let mut backend = Fake::new("");
    backend.layout = parse_layout(&bytes, &target().geometry).unwrap();
    backend.volumes.retain(|name, _| name > &self::name(2));
    assert!(acquire(&mut backend, &target()).unwrap().is_empty());
    assert_eq!(backend.writable_opens, 0);
    assert!(backend.events.borrow().entries.is_empty());

    backend
        .volumes
        .insert(name(1), Some(vec![extent(7, 1024 * 1024)]));
    assert!(matches!(
        acquire(&mut backend, &target()),
        Err(LockError::UnsupportedLayout)
    ));
    assert_eq!(backend.writable_opens, 0);
    assert!(backend.events.borrow().entries.is_empty());
}

#[test]
fn failures_release_all_locks_and_never_force_dismount() {
    for fault in [
        "lock",
        "dismount",
        "identity_after",
        "layout_after",
        "arrival",
        "foreign_volume_changed",
    ] {
        let mut backend = Fake::new(fault);
        assert!(acquire(&mut backend, &target()).is_err(), "{fault}");
        assert_eq!(backend.events.borrow().active, 0, "{fault}");
        if fault == "lock" {
            assert_eq!(
                backend
                    .events
                    .borrow()
                    .entries
                    .iter()
                    .filter(|e| e.starts_with("dismount:"))
                    .count(),
                0
            );
        }
    }
}

#[test]
fn incomplete_wrong_or_shared_identity_fails_before_dismount() {
    for fault in [
        "identity",
        "enumerate",
        "unclassifiable",
        "reopen",
        "reopen_second",
        "duplicate",
        "volume_limit",
    ] {
        let mut backend = Fake::new(fault);
        assert!(acquire(&mut backend, &target()).is_err(), "{fault}");
        assert!(backend.events.borrow().entries.is_empty(), "{fault}");
    }
    for extents in [
        vec![extent(7, 1024 * 1024), extent(99, 1024 * 1024)],
        vec![extent(7, 1024 * 1024), extent(7, 2 * 1024 * 1024)],
        vec![extent(7, 3 * 1024 * 1024)],
    ] {
        let mut backend = Fake::new("");
        backend.volumes.insert(name(1), Some(extents));
        assert!(acquire(&mut backend, &target()).is_err());
        assert!(backend.events.borrow().entries.is_empty());
    }
    let mut backend = Fake::new("");
    backend
        .volumes
        .insert(name(5), backend.volumes[&name(1)].clone());
    assert!(acquire(&mut backend, &target()).is_err());
    assert!(backend.events.borrow().entries.is_empty());
}

#[test]
fn volume_names_accept_only_canonical_guid_paths() {
    assert_eq!(
        VolumeName::parse(r"\\?\Volume{ABCDEF01-0000-0000-0000-000000000000}\")
            .unwrap()
            .0,
        r"\\?\Volume{abcdef01-0000-0000-0000-000000000000}\"
    );
    for invalid in [
        r"C:\",
        r"\\.\PhysicalDrive0",
        r"\\?\Volume{..}\",
        r"\\?\Volume{00000000-0000-0000-0000-000000000000}\file",
        "",
        "\0",
    ] {
        assert!(VolumeName::parse(invalid).is_err());
    }
}

fn extents_bytes(values: &[Extent]) -> Vec<u8> {
    let mut bytes = vec![0; 8 + values.len() * 24];
    bytes[..4].copy_from_slice(&(values.len() as u32).to_le_bytes());
    for (i, value) in values.iter().enumerate() {
        let base = 8 + i * 24;
        bytes[base..base + 4].copy_from_slice(&value.disk.to_le_bytes());
        bytes[base + 8..base + 16].copy_from_slice(&value.start.to_le_bytes());
        bytes[base + 16..base + 24].copy_from_slice(&value.length.to_le_bytes());
    }
    bytes
}

#[test]
fn extent_parser_bounds_counts_signed_offsets_and_overflow() {
    let good = extents_bytes(&[extent(7, 1024 * 1024)]);
    assert_eq!(parse_extents(&good).unwrap(), vec![extent(7, 1024 * 1024)]);
    for length in 0..good.len() {
        assert!(parse_extents(&good[..length]).is_err());
    }
    for (offset, value) in [(8, u64::MAX), (16, 0), (16, u64::MAX)] {
        let mut bad = good.clone();
        bad[8 + offset..8 + offset + 8].copy_from_slice(&value.to_le_bytes());
        assert!(parse_extents(&bad).is_err());
    }
    let mut excessive = good.clone();
    excessive[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_extents(&excessive).is_err());
    assert!(parse_extents(&extents_bytes(&[])).is_err());
    let overflow = extents_bytes(&[Extent {
        disk: 7,
        start: i64::MAX as u64,
        length: 1,
    }]);
    assert!(parse_extents(&overflow).is_err());
    let excessive = extents_bytes(&vec![extent(7, 1024); MAX_EXTENTS + 1]);
    assert!(parse_extents(&excessive).is_err());
}

fn table(style: u32, kind: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; 48 + 144];
    bytes[..4].copy_from_slice(&style.to_le_bytes());
    bytes[4..8].copy_from_slice(&1u32.to_le_bytes());
    bytes[48..52].copy_from_slice(&style.to_le_bytes());
    bytes[56..64].copy_from_slice(&(1024u64 * 1024).to_le_bytes());
    bytes[64..72].copy_from_slice(&(1024u64 * 1024).to_le_bytes());
    bytes[72..76].copy_from_slice(&1u32.to_le_bytes());
    bytes[80..80 + kind.len()].copy_from_slice(kind);
    bytes
}

#[test]
fn layout_parser_rejects_dynamic_unknown_truncated_and_out_of_bounds_tables() {
    assert_eq!(
        parse_layout(&table(0, &[7]), &target().geometry)
            .unwrap()
            .partitions
            .len(),
        1
    );
    for bytes in [
        table(0, &[0x42]),
        table(0, &[0x87]),
        table(1, &LDM_DATA),
        table(1, &LDM_METADATA),
        table(2, &[1]),
        table(77, &[1]),
    ] {
        assert!(parse_layout(&bytes, &target().geometry).is_err());
    }
    let good = table(0, &[7]);
    for length in 0..good.len() {
        assert!(parse_layout(&good[..length], &target().geometry).is_err());
    }
    let mut bad = good.clone();
    bad[56..64].copy_from_slice(&target().geometry.size_bytes.to_le_bytes());
    assert!(parse_layout(&bad, &target().geometry).is_err());
    bad = good.clone();
    bad[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(parse_layout(&bad, &target().geometry).is_err());
}

#[test]
fn mbr_extended_layouts_and_nonempty_unused_slots_are_unsupported() {
    for kind in [0x05, 0x0f, 0x85] {
        assert!(matches!(
            parse_layout(&table(0, &[kind]), &target().geometry),
            Err(LockError::UnsupportedLayout)
        ));
    }
    let mut empty = table(0, &[0]);
    empty[56..72].fill(0);
    assert!(
        parse_layout(&empty, &target().geometry)
            .unwrap()
            .partitions
            .is_empty()
    );
    for (start, length) in [(512u64, 0u64), (0, 512), (512, 512)] {
        let mut malformed = empty.clone();
        malformed[56..64].copy_from_slice(&start.to_le_bytes());
        malformed[64..72].copy_from_slice(&length.to_le_bytes());
        assert!(matches!(
            parse_layout(&malformed, &target().geometry),
            Err(LockError::UnsupportedLayout)
        ));
    }
}
