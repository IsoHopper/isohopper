// SPDX-License-Identifier: GPL-3.0-or-later
//! Pure classification of scanner evidence. No device enumeration or writes.
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Disk {
    pub id: String,
    pub serial: String,
    pub model: String,
    pub bus: String,
    pub size_bytes: u64,
    pub logical_sector_size: u64,
    pub physical_sector_size: u64,
    pub external: bool,
    pub safety_checks_complete: bool,
    pub system_disk: Option<bool>,
    pub mounted_system: bool,
    pub encryption_in_use: bool,
    pub container_member: bool,
    pub identity_ambiguous: bool,
    pub nvme: bool,
    pub has_data: bool,
    pub os_like: bool,
    pub freshly_plugged: bool,
    pub previously_selected: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Options {
    pub large_disk_threshold_bytes: u64,
    pub disable_nvme_risk: bool,
    pub disable_fresh_plug_risk: bool,
    pub disable_new_selection_risk: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Reason {
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct Verdict {
    pub allowed: bool,
    pub risky: bool,
    pub state: String,
    pub challenge: String,
    pub hard_blocks: Vec<Reason>,
    pub risks: Vec<Reason>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Confirmation {
    pub interactive: bool,
    pub yes: bool,
    pub serial_override: String,
    pub serial_override_set: bool,
    pub challenge: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
#[error("{reason}")]
pub struct GuardError {
    pub code: u8,
    pub reason: String,
}

pub const EXIT_GUARD: u8 = 3;
pub const EXIT_IDENTITY_CHANGED: u8 = 4;

fn reason_if(reasons: &mut Vec<Reason>, condition: bool, code: &str, message: &str) {
    if condition {
        reasons.push(Reason {
            code: code.into(),
            message: message.into(),
        });
    }
}

/// `allowed` means eligible for authorization, never permission to write.
/// Scanner evidence must be complete and independently obtained by the writer.
pub fn evaluate(d: &Disk, options: &Options) -> Verdict {
    let mut v = Verdict::default();
    let blocks = &mut v.hard_blocks;
    reason_if(
        blocks,
        d.id.trim().is_empty() || d.serial.trim().is_empty(),
        "identity_missing",
        "A stable identifier and nonempty serial are required.",
    );
    reason_if(
        blocks,
        d.identity_ambiguous,
        "identity_ambiguous",
        "Disk identity is not unique or reliable.",
    );
    reason_if(
        blocks,
        !d.safety_checks_complete,
        "safety_unknown",
        "Required safety checks have not completed.",
    );
    reason_if(
        blocks,
        d.system_disk.is_none(),
        "system_unknown",
        "System-disk membership is unknown.",
    );
    reason_if(
        blocks,
        !d.external,
        "not_external",
        "The disk is not confirmed external.",
    );
    reason_if(
        blocks,
        d.bus != "usb" && d.bus != "sd",
        "unsupported_bus",
        "Only confirmed USB and SD transport is permitted.",
    );
    reason_if(
        blocks,
        d.system_disk == Some(true),
        "system_disk",
        "The disk contains the running system.",
    );
    reason_if(
        blocks,
        d.mounted_system,
        "system_mount",
        "The disk backs a mounted system volume.",
    );
    reason_if(
        blocks,
        d.encryption_in_use,
        "encryption_in_use",
        "The disk participates in active encryption.",
    );
    reason_if(
        blocks,
        d.container_member,
        "container_member",
        "The disk belongs to a storage container.",
    );
    let geometry = [512, 4096].contains(&d.logical_sector_size)
        && d.size_bytes > 0
        && d.size_bytes.is_multiple_of(d.logical_sector_size)
        && d.physical_sector_size >= d.logical_sector_size
        && d.physical_sector_size <= d.size_bytes
        && d.physical_sector_size.is_power_of_two();
    reason_if(
        blocks,
        !geometry,
        "invalid_geometry",
        "Disk size and sector geometry are missing or inconsistent.",
    );
    let threshold = if options.large_disk_threshold_bytes == 0 {
        256_000_000_000
    } else {
        options.large_disk_threshold_bytes
    };
    reason_if(
        &mut v.risks,
        d.nvme && !options.disable_nvme_risk,
        "nvme",
        "The disk uses NVMe storage.",
    );
    reason_if(
        &mut v.risks,
        d.size_bytes > threshold,
        "large_capacity",
        "The disk exceeds the capacity warning threshold.",
    );
    reason_if(
        &mut v.risks,
        d.has_data,
        "existing_data",
        "The disk contains existing data.",
    );
    reason_if(
        &mut v.risks,
        d.os_like,
        "os_like",
        "The disk contains operating-system signatures.",
    );
    reason_if(
        &mut v.risks,
        !d.freshly_plugged && !options.disable_fresh_plug_risk,
        "not_freshly_plugged",
        "The disk was not newly attached during selection.",
    );
    reason_if(
        &mut v.risks,
        !d.previously_selected && !options.disable_new_selection_risk,
        "new_selection",
        "The disk differs from the previously selected target.",
    );
    v.allowed = v.hard_blocks.is_empty();
    v.risky = !v.risks.is_empty();
    v.state = if !v.allowed {
        "blocked"
    } else if v.risky {
        "confirm"
    } else {
        "ok"
    }
    .into();
    if v.allowed && v.risky {
        v.challenge = challenge(d);
    }
    v
}

pub fn challenge(d: &Disk) -> String {
    if d.size_bytes == 0 || d.serial.trim().is_empty() {
        return String::new();
    }
    let mut size = format!("{}B", d.size_bytes);
    for (divisor, label) in [
        (1_000_000_000_000, "TB"),
        (1_000_000_000, "GB"),
        (1_000_000, "MB"),
        (1_000, "KB"),
    ] {
        if d.size_bytes.is_multiple_of(divisor) {
            size = format!("{}{label}", d.size_bytes / divisor);
            break;
        }
    }
    let mut model = d
        .model
        .split(|c: char| !c.is_alphanumeric())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("-")
        .to_uppercase();
    if model.is_empty() {
        model = "DISK".into();
    }
    let suffix = d
        .serial
        .chars()
        .skip(d.serial.chars().count().saturating_sub(4))
        .collect::<String>()
        .to_uppercase();
    format!("WIPE {size}-{model}-{suffix}")
}

pub fn authorize(d: &Disk, options: &Options, c: &Confirmation) -> Result<(), GuardError> {
    let v = evaluate(d, options);
    let deny = |reason: String| {
        Err(GuardError {
            code: EXIT_GUARD,
            reason,
        })
    };
    if !v.allowed {
        return deny(format!("Target blocked: {}", v.hard_blocks[0].message));
    }
    if c.serial_override_set || !c.serial_override.is_empty() {
        return if !c.serial_override.is_empty() && c.serial_override == d.serial {
            Ok(())
        } else {
            deny("Serial authorization must exactly match the full nonempty serial.".into())
        };
    }
    if v.risky {
        return if c.interactive && c.challenge.to_lowercase() == v.challenge.to_lowercase() {
            Ok(())
        } else {
            deny("Risky target requires the full interactive WIPE challenge or exact full-serial authorization.".into())
        };
    }
    if c.yes {
        Ok(())
    } else {
        deny("Target requires affirmative confirmation.".into())
    }
}

/// Check a fresh observation, then authorize that observation separately.
/// The caller must also bind the approved plan and retain the opened handle.
pub fn revalidate(expected: &Disk, actual: &Disk) -> Result<(), GuardError> {
    if expected.id != actual.id
        || expected.serial != actual.serial
        || expected.size_bytes != actual.size_bytes
        || expected.logical_sector_size != actual.logical_sector_size
        || expected.physical_sector_size != actual.physical_sector_size
        || expected.bus != actual.bus
        || expected.external != actual.external
    {
        return Err(GuardError {
            code: EXIT_IDENTITY_CHANGED,
            reason: "Disk identity, geometry, or transport changed after authorization.".into(),
        });
    }
    let v = evaluate(actual, &Options::default());
    if !v.allowed {
        return Err(GuardError {
            code: EXIT_IDENTITY_CHANGED,
            reason: format!("Disk safety changed: {}", v.hard_blocks[0].message),
        });
    }
    Ok(())
}
