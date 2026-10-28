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
    volumes: BTreeMap<VolumeName, Option<Vec<Extent>>>,
    fault: &'static str,
    snapshots: usize,
    enumerations: usize,
}
impl Fake {
    fn new(fault: &'static str) -> Self {
        Self {
            events: Rc::default(),
            volumes: BTreeMap::from([
                (name(1), Some(vec![extent(7, 1024 * 1024)])),
                (name(2), Some(vec![extent(7, 2 * 1024 * 1024)])),
                (name(3), Some(vec![extent(99, 1024 * 1024)])),
                (name(4), None), // independently identified CD-ROM
            ]),
            fault,
            snapshots: 0,
            enumerations: 0,
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
        let mut result = layout();
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
