// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::{guard, layout};
use serde::Serialize;
use std::fmt::Write;

/// Render discovered facts without treating missing information as safe.
/// Debug string formatting escapes device-provided terminal control characters.
pub fn format_inventory(inventory: &isohopper_inventory::Inventory) -> String {
    let mut output = format!(
        "Source: {:?} | {} device(s)\nRead-only discovery. Physical writes are unavailable.\n",
        inventory.source,
        inventory.disks.len()
    );
    let text = |value: &str| {
        if value.is_empty() {
            "<unknown>".to_owned()
        } else {
            format!("{value:?}")
        }
    };
    let sector = |value: u64| {
        if value == 0 {
            "unknown".to_owned()
        } else {
            value.to_string()
        }
    };
    for disk in &inventory.disks {
        let verdict = guard::evaluate(disk, &guard::Options::default());
        writeln!(
            output,
            "id={} | serial={} | model={} | bus={} | {} bytes | guard={}",
            text(&disk.id),
            text(&disk.serial),
            text(&disk.model),
            text(&disk.bus),
            disk.size_bytes,
            verdict.state
        )
        .unwrap();
        writeln!(
            output,
            "  logical_sector_size={} | physical_sector_size={}",
            sector(disk.logical_sector_size),
            sector(disk.physical_sector_size)
        )
        .unwrap();
        writeln!(output, "  external={} | safety_checks_complete={} | system_disk={} | mounted_system={} | encryption_in_use={} | container_member={}", disk.external, disk.safety_checks_complete, disk.system_disk.map(|value| value.to_string()).unwrap_or_else(|| "unknown".into()), disk.mounted_system, disk.encryption_in_use, disk.container_member).unwrap();
        writeln!(output, "  identity_ambiguous={} | nvme={} | has_data={} | os_like={} | freshly_plugged={} | previously_selected={}", disk.identity_ambiguous, disk.nvme, disk.has_data, disk.os_like, disk.freshly_plugged, disk.previously_selected).unwrap();
        for reason in verdict.hard_blocks.iter().chain(verdict.risks.iter()) {
            writeln!(output, "  Guard {}: {}", reason.code, reason.message).unwrap();
        }
    }
    for warning in &inventory.warnings {
        writeln!(
            output,
            "Warning [{}] {}: {}",
            warning
                .disk_id
                .as_deref()
                .map(&text)
                .unwrap_or_else(|| "all devices".into()),
            text(&warning.code),
            text(&warning.message)
        )
        .unwrap();
    }
    output
}

#[derive(Serialize)]
pub struct DiskView {
    pub disk: guard::Disk,
    pub verdict: guard::Verdict,
    pub challenge: String,
    pub source: &'static str,
}
pub fn demo_disks() -> Vec<DiskView> {
    let disks: Vec<guard::Disk> =
        serde_json::from_str(include_str!("../../../tests/fixtures/disks.json"))
            .expect("embedded disk fixtures are valid");
    disks
        .into_iter()
        .map(|disk| {
            let verdict = guard::evaluate(&disk, &guard::Options::default());
            let challenge = verdict.challenge.clone();
            DiskView {
                disk,
                verdict,
                challenge,
                source: "mock",
            }
        })
        .collect()
}
pub fn demo_plan(id: &str) -> Result<layout::Layout, String> {
    let view = demo_disks()
        .into_iter()
        .find(|v| v.disk.id == id)
        .ok_or("Unknown mock disk")?;
    if !view.verdict.allowed {
        return Err(view
            .verdict
            .hard_blocks
            .iter()
            .map(|r| r.message.as_str())
            .collect::<Vec<_>>()
            .join(" "));
    }
    layout::plan(view.disk.size_bytes, view.disk.logical_sector_size, false)
        .map_err(|e| e.to_string())
}
