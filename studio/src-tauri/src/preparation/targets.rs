// SPDX-License-Identifier: GPL-3.0-or-later
//! Session-local selection tokens. Provider paths are selectors, never authority.
use isohopper_inventory::windows::WindowsDiskRecord;
use serde::Serialize;
use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize)]
pub struct TargetSelection {
    pub selection_token: String,
    pub display_id: String,
    pub volume_labels: Option<Vec<String>>,
    pub disk: WindowsDiskRecord,
}
struct Selection {
    path: String,
    created: Instant,
}
static TARGETS: OnceLock<Mutex<BTreeMap<String, Selection>>> = OnceLock::new();
fn selections() -> &'static Mutex<BTreeMap<String, Selection>> {
    TARGETS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub fn token() -> Result<String, String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("Create native job identity: {e}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(windows)]
pub fn refresh() -> Result<Vec<TargetSelection>, String> {
    let evidence = isohopper_inventory::windows::collect_evidence().map_err(|e| e.to_string())?;
    let labels = isohopper_inventory::windows_labels::collect_with(
        &isohopper_inventory::NativeCommandRunner,
    )
    .ok();
    let mut next = BTreeMap::new();
    let mut report = Vec::new();
    for disk in evidence.disks {
        let Some(path) = disk
            .path
            .as_ref()
            .filter(|p| !p.is_empty() && p.len() <= 16384)
        else {
            continue;
        };
        let selection_token = token()?;
        if next
            .insert(
                selection_token.clone(),
                Selection {
                    path: path.clone(),
                    created: Instant::now(),
                },
            )
            .is_some()
        {
            return Err("Duplicate random target identity".into());
        }
        report.push(TargetSelection {
            selection_token,
            display_id: format!(r"\\.\PhysicalDrive{}", disk.number),
            volume_labels: labels
                .as_ref()
                .map(|labels| labels.get(&disk.number).cloned().unwrap_or_default()),
            disk,
        });
    }
    *selections()
        .lock()
        .map_err(|_| "Target selections are unavailable")? = next;
    Ok(report)
}
#[cfg(not(windows))]
pub fn refresh() -> Result<Vec<TargetSelection>, String> {
    Err("Physical preparation is available only on Windows".into())
}

pub fn resolve(selection_token: &str) -> Result<String, String> {
    let selections = selections()
        .lock()
        .map_err(|_| "Target selections are unavailable")?;
    let selected = selections
        .get(selection_token)
        .ok_or("Unknown target selection; refresh devices")?;
    if selected.created.elapsed() > Duration::from_secs(300) {
        return Err("Target selection expired; refresh devices".into());
    }
    Ok(selected.path.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn display_disk_paths_are_not_selection_tokens() {
        for input in [
            r"\\.\PhysicalDrive0",
            r"C:\image.img",
            "",
            "src_not_a_target",
        ] {
            assert!(resolve(input).is_err());
        }
    }
}
