// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only lsblk evidence. A tree cannot establish complete host storage safety.
use crate::{CommandRunner, Inventory, InventoryError, MAX_OUTPUT, Warning, warning};
use isohopper_core::guard::Disk;
use serde::Deserialize;
use std::collections::BTreeMap;

pub(super) const LSBLK: &str = "/usr/bin/lsblk";
pub(super) const ARGS: &[&str] = &[
    "--json",
    "--bytes",
    "--paths",
    "--tree",
    "--output",
    "NAME,KNAME,PATH,TYPE,SIZE,LOG-SEC,PHY-SEC,RM,RO,TRAN,SERIAL,MODEL,MOUNTPOINTS,FSTYPE",
];
const MAX_NODES: usize = 4096;
const MAX_DEPTH: usize = 16;
const MAX_DISKS: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    blockdevices: Vec<Node>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Node {
    name: String,
    kname: Option<String>,
    path: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    size: Option<u64>,
    #[serde(rename = "log-sec")]
    logical: Option<u64>,
    #[serde(rename = "phy-sec")]
    physical: Option<u64>,
    rm: Option<bool>,
    ro: Option<bool>,
    tran: Option<String>,
    serial: Option<String>,
    model: Option<String>,
    mountpoints: Option<Vec<Option<String>>>,
    fstype: Option<String>,
    children: Option<Vec<Node>>,
}

impl Node {
    fn id(&self) -> &str {
        self.path.as_deref().unwrap_or(&self.name)
    }
    fn children(&self) -> &[Node] {
        self.children.as_deref().unwrap_or_default()
    }
}

fn invalid(message: &str) -> InventoryError {
    InventoryError::Invalid(message.into())
}

fn device_path(value: &str) -> bool {
    value.strip_prefix("/dev/").is_some_and(|relative| {
        !relative.is_empty()
            && value.len() <= 1024
            && relative.split('/').all(|part| {
                !part.is_empty()
                    && part != "."
                    && part != ".."
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"._+-".contains(&byte))
            })
    })
}

fn validate_tree(node: &Node, depth: usize, count: &mut usize) -> Result<(), InventoryError> {
    *count += 1;
    if depth > MAX_DEPTH || *count > MAX_NODES {
        return Err(invalid("lsblk tree exceeds depth or node limit"));
    }
    if !device_path(&node.name)
        || node.path.as_deref().is_some_and(|path| !device_path(path))
        || node.kname.as_deref().is_some_and(|path| !device_path(path))
    {
        return Err(invalid("lsblk contains an invalid device path"));
    }
    for value in [
        &node.kind,
        node.tran.as_deref().unwrap_or(""),
        node.fstype.as_deref().unwrap_or(""),
    ] {
        if value.len() > 128 || value.chars().any(char::is_control) {
            return Err(invalid("lsblk contains invalid type or transport metadata"));
        }
    }
    if let Some(mountpoints) = &node.mountpoints
        && (mountpoints.len() > 256
            || mountpoints
                .iter()
                .flatten()
                .any(|path| path.len() > 4096 || path.chars().any(char::is_control)))
    {
        return Err(invalid("lsblk contains invalid or excessive mount points"));
    }
    for child in node.children() {
        validate_tree(child, depth + 1, count)?;
    }
    Ok(())
}

#[derive(Default)]
struct Evidence {
    root: bool,
    system_mount: bool,
    encrypted: bool,
    container: bool,
    incomplete: bool,
}

fn evidence(node: &Node, result: &mut Evidence) {
    if let Some(mountpoints) = &node.mountpoints {
        for path in mountpoints.iter().flatten() {
            result.root |= path == "/";
            result.system_mount |= matches!(path.as_str(), "/" | "/usr" | "/boot" | "/boot/efi");
        }
    } else {
        result.incomplete = true;
    }
    result.encrypted |=
        node.kind == "crypt" || matches!(node.fstype.as_deref(), Some("crypto_LUKS" | "BitLocker"));
    result.container |= matches!(node.kind.as_str(), "crypt" | "lvm" | "mpath" | "md" | "dm")
        || node.kind.starts_with("raid")
        || matches!(
            node.fstype.as_deref(),
            Some("LVM2_member" | "linux_raid_member" | "zfs_member" | "bcache")
        );
    result.incomplete |= !matches!(
        node.kind.as_str(),
        "disk" | "part" | "crypt" | "lvm" | "mpath" | "md" | "dm"
    ) && !node.kind.starts_with("raid");
    for child in node.children() {
        evidence(child, result);
    }
}

fn clean_text(value: Option<&str>) -> String {
    value
        .filter(|text| text.len() <= 1024 && !text.chars().any(char::is_control))
        .unwrap_or("")
        .trim()
        .to_owned()
}

fn record(node: &Node, warnings: &mut Vec<Warning>) -> Disk {
    let mut observed = Evidence::default();
    evidence(node, &mut observed);
    let bus = match node.tran.as_deref() {
        Some("usb") => "usb",
        Some("mmc") if node.rm == Some(true) => "sd",
        Some("mmc") => "mmc",
        Some("nvme") => "nvme",
        Some("sata" | "ata") => "sata",
        Some("sas") => "sas",
        Some("spi") => "spi",
        _ => "unknown",
    };
    let disk = Disk {
        id: node.id().into(),
        serial: clean_text(node.serial.as_deref()),
        model: clean_text(node.model.as_deref()),
        bus: bus.into(),
        size_bytes: node.size.unwrap_or(0),
        logical_sector_size: node.logical.unwrap_or(0),
        physical_sector_size: node.physical.unwrap_or(0),
        external: matches!(bus, "usb" | "sd"),
        // Positive observations propagate; absent root evidence does not prove
        // exclusion from multi-device filesystems, containers, or other namespaces.
        system_disk: observed.root.then_some(true),
        mounted_system: observed.system_mount,
        encryption_in_use: observed.encrypted,
        container_member: observed.container,
        identity_ambiguous: node.path.is_none() || node.name != node.id(),
        nvme: bus == "nvme",
        has_data: true,
        os_like: observed.system_mount,
        safety_checks_complete: false,
        ..Disk::default()
    };
    let mut warn = |code, message| warning(warnings, Some(&disk.id), code, message);
    if disk.serial.is_empty() {
        warn(
            "identity_missing",
            "A nonempty, valid hardware serial was not reported.",
        );
    }
    if disk.identity_ambiguous {
        warn(
            "identity_ambiguous",
            "Device path is missing or differs from the reported name.",
        );
    }
    let geometry = [512, 4096].contains(&disk.logical_sector_size)
        && disk.size_bytes > 0
        && disk.size_bytes <= i64::MAX as u64
        && disk.size_bytes.is_multiple_of(disk.logical_sector_size)
        && disk.physical_sector_size >= disk.logical_sector_size
        && disk.physical_sector_size <= disk.size_bytes
        && disk.physical_sector_size.is_power_of_two();
    if !geometry {
        warn(
            "geometry_unknown",
            "Disk size or sector geometry is missing, inconsistent, or unsupported.",
        );
    }
    if disk.system_disk.is_none() {
        warn(
            "system_unknown",
            "No root mount was observed for this disk; system-disk exclusion is unproven.",
        );
    }
    if observed.incomplete {
        warn(
            "topology_unknown",
            "Mount points or storage relationships are incomplete or unsupported.",
        );
    }
    if node.ro == Some(true) {
        warn("read_only", "The kernel reports this disk as read-only.");
    }
    if node.ro.is_none() {
        warn(
            "write_protection_unknown",
            "Kernel write-protection status was not reported.",
        );
    }
    if bus == "unknown" {
        warn(
            "transport_unknown",
            "A supported transport was not reported.",
        );
    }
    if !disk.external {
        warn(
            "location_unknown",
            "External removable storage was not confirmed.",
        );
    }
    warn(
        "safety_incomplete",
        "Inspection only: lsblk does not prove complete identity, encryption, container, mount, or hotplug safety; preparation remains blocked.",
    );
    disk
}

fn collect(
    node: &Node,
    disks: &mut BTreeMap<String, Disk>,
    warnings: &mut Vec<Warning>,
) -> Result<(), InventoryError> {
    if node.kind == "disk" {
        let incoming = record(node, warnings);
        if let Some(existing) = disks.get_mut(&incoming.id) {
            existing.identity_ambiguous = true;
            existing.system_disk = (existing.system_disk == Some(true)
                || incoming.system_disk == Some(true))
            .then_some(true);
            existing.mounted_system |= incoming.mounted_system;
            existing.encryption_in_use |= incoming.encryption_in_use;
            existing.container_member |= incoming.container_member;
            existing.os_like |= incoming.os_like;
            warning(
                warnings,
                Some(&existing.id),
                "identity_ambiguous",
                "The whole disk appears repeatedly in the storage tree; positive safety observations were combined.",
            );
        } else {
            disks.insert(incoming.id.clone(), incoming);
            if disks.len() > MAX_DISKS {
                return Err(invalid("too many whole disks"));
            }
        }
    }
    for child in node.children() {
        collect(child, disks, warnings)?;
    }
    Ok(())
}

pub(super) fn discover(runner: &impl CommandRunner) -> Result<Inventory, InventoryError> {
    let output = runner
        .run(LSBLK, ARGS)
        .map_err(|_| InventoryError::Command("lsblk could not run".into()))?;
    if !output.success {
        return Err(InventoryError::Command("lsblk returned an error".into()));
    }
    if output.stdout.is_empty()
        || output.stdout.len() > MAX_OUTPUT
        || output.stderr.len() > MAX_OUTPUT
    {
        return Err(invalid("lsblk output is empty or exceeds the size limit"));
    }
    let listing: Listing = serde_json::from_slice(&output.stdout)
        .map_err(|_| invalid("malformed or incorrectly typed lsblk JSON"))?;
    let mut count = 0;
    for node in &listing.blockdevices {
        validate_tree(node, 0, &mut count)?;
    }
    let mut disks = BTreeMap::new();
    let mut warnings = Vec::new();
    if !output.stderr.is_empty() {
        warning(
            &mut warnings,
            None,
            "command_diagnostics",
            "lsblk emitted diagnostics; some observed metadata may be incomplete.",
        );
    }
    for node in &listing.blockdevices {
        collect(node, &mut disks, &mut warnings)?;
    }
    let mut serial_counts = BTreeMap::new();
    for disk in disks.values().filter(|disk| !disk.serial.is_empty()) {
        *serial_counts.entry(disk.serial.clone()).or_insert(0) += 1;
    }
    for disk in disks.values_mut() {
        if serial_counts
            .get(&disk.serial)
            .is_some_and(|count| *count > 1)
        {
            disk.identity_ambiguous = true;
            warning(
                &mut warnings,
                Some(&disk.id),
                "identity_ambiguous",
                "The hardware serial is shared by multiple whole disks.",
            );
        }
    }
    if disks.is_empty() {
        warning(
            &mut warnings,
            None,
            "no_physical_disks",
            "No whole-disk records were reported; loop, optical, and virtual mapping records are not preparation targets.",
        );
    }
    Ok(Inventory {
        source: "linux_lsblk".into(),
        disks: disks.into_values().collect(),
        warnings,
    })
}
