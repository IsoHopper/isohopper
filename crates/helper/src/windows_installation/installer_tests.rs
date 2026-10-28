// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::{fs, path::PathBuf};
struct Fixture {
    root: tempfile::TempDir,
    fail: Option<usize>,
    steps: usize,
    busy: bool,
    fail_restore: bool,
    partial_stage: bool,
    fail_finish: bool,
}
impl Fixture {
    fn new(existing: &[usize]) -> Self {
        let root = tempfile::tempdir().unwrap();
        for index in existing {
            fs::write(root.path().join(FILES[*index]), format!("old-{index}")).unwrap();
        }
        fs::write(root.path().join("user-data"), b"preserve").unwrap();
        Self {
            root,
            fail: None,
            steps: 0,
            busy: false,
            fail_restore: false,
            partial_stage: false,
            fail_finish: false,
        }
    }
    fn path(&self, index: usize, suffix: &str) -> PathBuf {
        self.root.path().join(format!("{}{suffix}", FILES[index]))
    }
    fn step(&mut self) -> Result<(), String> {
        self.steps += 1;
        if self.fail == Some(self.steps) {
            Err("injected I/O failure".into())
        } else {
            Ok(())
        }
    }
    fn original(&self, existing: &[usize]) {
        for i in 0..3 {
            if existing.contains(&i) {
                assert_eq!(
                    fs::read(self.path(i, "")).unwrap(),
                    format!("old-{i}").as_bytes()
                );
            } else {
                assert!(!self.path(i, "").exists());
            }
            assert!(!self.path(i, ".new").exists());
            assert!(!self.path(i, ".old").exists());
        }
        assert_eq!(
            fs::read(self.root.path().join("user-data")).unwrap(),
            b"preserve"
        );
    }
}
impl Backend for Fixture {
    fn preflight(&mut self) -> Result<(), Error> {
        if self.busy { Err(Error::Busy) } else { Ok(()) }
    }
    fn stage(&mut self, i: usize) -> Result<(), String> {
        self.step()?;
        fs::write(self.path(i, ".new"), format!("new-{i}")).map_err(|e| e.to_string())?;
        if self.partial_stage && i == 1 {
            Err("copy interrupted".into())
        } else {
            Ok(())
        }
    }
    fn backup(&mut self, i: usize) -> Result<bool, String> {
        self.step()?;
        if self.path(i, "").exists() {
            fs::rename(self.path(i, ""), self.path(i, ".old")).map_err(|e| e.to_string())?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn publish(&mut self, i: usize) -> Result<(), String> {
        self.step()?;
        fs::rename(self.path(i, ".new"), self.path(i, "")).map_err(|e| e.to_string())
    }
    fn remove_new(&mut self, i: usize) -> Result<(), String> {
        fs::remove_file(self.path(i, "")).map_err(|e| e.to_string())
    }
    fn restore_old(&mut self, i: usize) -> Result<(), String> {
        if self.fail_restore {
            return Err("restore failure".into());
        }
        fs::rename(self.path(i, ".old"), self.path(i, "")).map_err(|e| e.to_string())
    }
    fn cleanup_staged(&mut self, i: usize) -> Result<(), String> {
        if self.path(i, ".new").exists() {
            fs::remove_file(self.path(i, ".new")).map_err(|e| e.to_string())?;
        }
        Ok(())
    }
    fn finish(&mut self) -> Result<(), String> {
        for i in 0..3 {
            if self.fail_finish && i == 1 {
                return Err("cleanup failed".into());
            }
            if self.path(i, ".old").exists() {
                fs::remove_file(self.path(i, ".old")).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }
}
#[test]
fn fresh_upgrade_and_partial_repair_replace_only_fixed_files() {
    for existing in [&[][..], &[0, 1, 2][..], &[1][..]] {
        let mut f = Fixture::new(existing);
        run(&mut f).unwrap();
        for i in 0..3 {
            assert_eq!(
                fs::read(f.path(i, "")).unwrap(),
                format!("new-{i}").as_bytes()
            );
            assert!(!f.path(i, ".old").exists());
        }
        assert_eq!(
            fs::read(f.root.path().join("user-data")).unwrap(),
            b"preserve"
        );
    }
}
#[test]
fn every_transaction_failure_restores_existing_files() {
    for existing in [&[][..], &[0, 1, 2][..], &[1][..]] {
        for step in 1..=9 {
            let mut f = Fixture::new(existing);
            f.fail = Some(step);
            assert_eq!(run(&mut f).unwrap_err().code(), 13, "step {step}");
            f.original(existing);
        }
    }
}
#[test]
fn busy_preflight_never_mutates_existing_files() {
    let mut f = Fixture::new(&[0, 1, 2]);
    f.busy = true;
    assert_eq!(run(&mut f).unwrap_err().code(), 10);
    assert_eq!(f.steps, 0);
    f.original(&[0, 1, 2]);
}
#[test]
fn failed_rollback_retains_recovery_files() {
    let mut f = Fixture::new(&[0, 1, 2]);
    f.fail = Some(8);
    f.fail_restore = true;
    assert_eq!(run(&mut f).unwrap_err().code(), 14);
    assert!(f.path(0, ".old").exists());
}
#[test]
fn interrupted_copy_cleans_its_partial_file() {
    let mut fixture = Fixture::new(&[0, 1, 2]);
    fixture.partial_stage = true;
    assert_eq!(run(&mut fixture).unwrap_err().code(), 13);
    fixture.original(&[0, 1, 2]);
}
#[test]
fn cleanup_failure_keeps_complete_new_installation_and_remaining_backups() {
    let mut fixture = Fixture::new(&[0, 1, 2]);
    fixture.fail_finish = true;
    assert_eq!(run(&mut fixture).unwrap_err().code(), 14);
    for i in 0..3 {
        assert_eq!(
            fs::read(fixture.path(i, "")).unwrap(),
            format!("new-{i}").as_bytes()
        );
    }
    assert!(!fixture.path(0, ".old").exists());
    assert!(fixture.path(1, ".old").exists());
    assert!(fixture.path(2, ".old").exists());
}
#[test]
fn payload_path_requires_fixed_protected_sibling_and_guid() {
    let base = r"C:\Program Files";
    let windows = r"C:\Windows";
    assert!(
        payload_path(
            r"C:\Program Files\.IsoHopper-setup-{01234567-89ab-cdef-0123-456789abcdef}",
            base,
            windows
        )
        .is_ok()
    );
    for path in [
        r"C:\Users\me\.IsoHopper-setup-{01234567-89ab-cdef-0123-456789abcdef}",
        r"C:\Program Files\.IsoHopper-setup-{01234567-89ab-cdef-0123-456789abcdef}\child",
        r"C:\Program Files\.IsoHopper-setup-{01234567-89ab-cdef-0123-456789abcdeg}",
        r"C:\Program Files\IsoHopper",
        r"C:\Program Files\.IsoHopper-setup-..",
    ] {
        assert!(payload_path(path, base, windows).is_err());
    }
}
