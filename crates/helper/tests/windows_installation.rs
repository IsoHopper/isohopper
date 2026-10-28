// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::{windows_installation::InstalledRole, windows_peer::PeerError};
#[path = "../src/windows_peer/installed.rs"]
mod installed;
#[path = "../src/windows_installation/state.rs"]
mod state;

#[test]
fn installed_roles_have_only_fixed_executable_names() {
    assert_eq!(InstalledRole::Studio.filename(), "isohopper-studio.exe");
    assert_eq!(InstalledRole::Helper.filename(), "isohopper-helper.exe");
}

fn metadata() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut id = vec![0; 24];
    id[0] = 1;
    id[8] = 2;
    let mut basic = vec![0; 40];
    basic[0] = 3;
    basic[16] = 4;
    basic[24] = 5;
    basic[32] = 0x20;
    let mut standard = vec![0; 24];
    standard[0..8].copy_from_slice(&4096i64.to_le_bytes());
    standard[8..16].copy_from_slice(&1234i64.to_le_bytes());
    standard[16] = 1;
    (id, basic, standard)
}

#[test]
fn installed_image_stamp_preserves_identity_and_change_sentinels() {
    let (id, basic, standard) = metadata();
    let baseline = state::image_stamp(&id, &basic, &standard).unwrap();
    assert_eq!(baseline.volume, 1);
    assert_eq!(baseline.id[0], 2);
    assert_eq!(baseline.bytes, 1234);
    for (field, offset) in [
        (0, 0),
        (0, 8),
        (1, 0),
        (1, 16),
        (1, 24),
        (1, 32),
        (2, 0),
        (2, 8),
        (2, 16),
    ] {
        let mut values = [id.clone(), basic.clone(), standard.clone()];
        values[field][offset] += 1;
        assert_ne!(
            baseline,
            state::image_stamp(&values[0], &values[1], &values[2]).unwrap()
        );
    }
    let mut access_changed = basic.clone();
    access_changed[8] = 99; // Reading an image can update access time.
    assert_eq!(
        baseline,
        state::image_stamp(&id, &access_changed, &standard).unwrap()
    );
}

#[test]
fn installed_image_stamp_rejects_non_files_empty_and_malformed_metadata() {
    let (id, basic, standard) = metadata();
    for field in 0..3 {
        let mut values = [id.clone(), basic.clone(), standard.clone()];
        values[field].pop();
        assert!(state::image_stamp(&values[0], &values[1], &values[2]).is_err());
    }
    for mask in [0x10u32, 0x40, 0x400] {
        let mut changed = basic.clone();
        changed[32..36].copy_from_slice(&mask.to_le_bytes());
        assert!(state::image_stamp(&id, &changed, &standard).is_err());
    }
    for (offset, bytes) in [
        (0, (-1i64).to_le_bytes()),
        (8, (-1i64).to_le_bytes()),
        (8, 0i64.to_le_bytes()),
    ] {
        let mut changed = standard.clone();
        changed[offset..offset + 8].copy_from_slice(&bytes);
        assert!(state::image_stamp(&id, &basic, &changed).is_err());
    }
    for (offset, value) in [(16, 0), (20, 1), (20, 255), (21, 1), (21, 255)] {
        let mut changed = standard.clone();
        changed[offset] = value;
        assert!(state::image_stamp(&id, &basic, &changed).is_err());
    }
}

#[test]
fn native_names_require_exact_bounded_terminated_utf16() {
    let good: Vec<u16> =
        "\\Device\\HarddiskVolume1\\Program Files\\IsoHopper\\isohopper-studio.exe\0"
            .encode_utf16()
            .collect();
    assert_eq!(
        state::wide_name(&good, good.len() - 1).unwrap(),
        good[..good.len() - 1]
    );
    for length in [0, good.len(), good.len() + 1] {
        assert!(state::wide_name(&good, length).is_err());
    }
    let mut bad = good.clone();
    bad[5] = 0;
    assert!(state::wide_name(&bad, bad.len() - 1).is_err());
    bad = good.clone();
    *bad.last_mut().unwrap() = 1;
    assert!(state::wide_name(&bad, bad.len() - 1).is_err());
    bad = vec![1; 32769];
    *bad.last_mut().unwrap() = 0;
    assert!(state::wide_name(&bad, bad.len() - 1).is_err());
    assert!(state::wide_name(&[0xd800, 0], 1).is_err());
}

struct Binding {
    expected: Vec<u16>,
    actual: Vec<u16>,
    events: Vec<&'static str>,
    fail: Option<usize>,
}
impl Binding {
    fn new() -> Self {
        Self {
            expected: "\\Device\\HarddiskVolume1\\Program Files\\IsoHopper\\isohopper-studio.exe"
                .encode_utf16()
                .collect(),
            actual: "\\Device\\HarddiskVolume1\\Program Files\\IsoHopper\\isohopper-studio.exe"
                .encode_utf16()
                .collect(),
            events: Vec::new(),
            fail: None,
        }
    }
    fn step(&mut self, event: &'static str) -> Result<(), PeerError> {
        self.events.push(event);
        if self.fail == Some(self.events.len()) {
            Err(PeerError::Changed)
        } else {
            Ok(())
        }
    }
}
impl installed::Backend for Binding {
    fn peer(&mut self) -> Result<(), PeerError> {
        self.step("peer")
    }
    fn installation(&mut self) -> Result<(), PeerError> {
        self.step("installation")
    }
    fn process_image(&mut self) -> Result<Vec<u16>, PeerError> {
        self.step("name")?;
        Ok(self.actual.clone())
    }
    fn installed_image(&self) -> &[u16] {
        &self.expected
    }
}

#[test]
fn installed_binding_brackets_exact_image_name_with_peer_and_installation_checks() {
    let mut b = Binding::new();
    installed::check(&mut b).unwrap();
    assert_eq!(
        b.events,
        ["peer", "installation", "name", "installation", "peer"]
    );
    for actual in [
        "\\Device\\HarddiskVolume1\\Program Files\\IsoHopper\\isohopper-helper.exe",
        "\\Device\\HarddiskVolume2\\Program Files\\IsoHopper\\isohopper-studio.exe",
        "\\Device\\HarddiskVolume1\\Program Files\\IsoHopper2\\isohopper-studio.exe",
        "\\Device\\HarddiskVolume1\\Program Files\\IsoHopper\\ISOHOPPER-STUDIO.EXE",
        "\\Device\\HarddiskVolume1\\PROGRA~1\\IsoHopper\\isohopper-studio.exe",
        "",
    ] {
        let mut b = Binding::new();
        b.actual = actual.encode_utf16().collect();
        assert!(installed::check(&mut b).is_err(), "{actual}");
    }
}

#[test]
fn installed_binding_never_accepts_failed_or_changed_evidence() {
    for fail in 1..=5 {
        let mut b = Binding::new();
        b.fail = Some(fail);
        assert!(matches!(installed::check(&mut b), Err(PeerError::Changed)));
        assert_eq!(b.events.len(), fail);
    }
}
