// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{CommandRunner, Inventory, InventoryError, MAX_OUTPUT, Warning, warning};
use isohopper_core::guard::Disk;
use serde::{Deserialize, de::DeserializeOwned};
use std::collections::BTreeSet;

const DISKUTIL: &str = "/usr/sbin/diskutil";

#[derive(Deserialize)]
struct Listing {
    #[serde(rename = "WholeDisks")]
    whole_disks: Vec<String>,
    #[serde(rename = "AllDisksAndPartitions")]
    disks: Vec<ListedDisk>,
}

#[derive(Deserialize)]
struct ListedDisk {
    #[serde(rename = "DeviceIdentifier")]
    id: String,
    #[serde(rename = "Size")]
    size: u64,
    #[serde(rename = "Content")]
    content: Option<String>,
    #[serde(rename = "Partitions")]
    partitions: Option<Vec<Partition>>,
}

#[derive(Deserialize)]
struct Partition {
    #[serde(rename = "DeviceIdentifier")]
    id: String,
    #[serde(rename = "Content")]
    content: Option<String>,
}

#[derive(Deserialize)]
struct DiskInfo {
    #[serde(rename = "DeviceIdentifier")]
    id: String,
    #[serde(rename = "DeviceNode")]
    node: String,
    #[serde(rename = "WholeDisk")]
    whole: bool,
    #[serde(rename = "VirtualOrPhysical")]
    kind: String,
    #[serde(rename = "Internal")]
    internal: Option<bool>,
    #[serde(rename = "MediaName")]
    model: Option<String>,
    #[serde(rename = "BusProtocol")]
    bus: Option<String>,
    #[serde(rename = "DeviceBlockSize")]
    logical_sector: Option<u64>,
    #[serde(rename = "TotalSize")]
    size: Option<u64>,
    #[serde(rename = "FileVault")]
    file_vault: Option<bool>,
    #[serde(rename = "Encryption")]
    encryption: Option<bool>,
    #[serde(rename = "Bootable")]
    bootable: Option<bool>,
    #[serde(rename = "RAIDMaster")]
    raid_master: Option<bool>,
    #[serde(rename = "RAIDSlice")]
    raid_slice: Option<bool>,
}

#[derive(Deserialize)]
struct SystemInfo {
    #[serde(rename = "MountPoint")]
    mount_point: String,
    #[serde(rename = "ParentWholeDisk")]
    parent: Option<String>,
    #[serde(rename = "APFSPhysicalStores")]
    stores: Option<Vec<PhysicalStore>>,
    #[serde(rename = "FileVault")]
    file_vault: Option<bool>,
    #[serde(rename = "Encryption")]
    encryption: Option<bool>,
}

#[derive(Deserialize)]
struct PhysicalStore {
    #[serde(rename = "APFSPhysicalStore")]
    id: String,
}

struct SystemEvidence {
    disks: BTreeSet<String>,
    encrypted: bool,
    apfs: bool,
}

pub(super) fn whole_identifier(id: &str) -> bool {
    id.strip_prefix("disk").is_some_and(|number| {
        !number.is_empty()
            && number.len() <= 6
            && number.bytes().all(|b| b.is_ascii_digit())
            && (number.len() == 1 || !number.starts_with('0'))
    })
}

fn partition_parent(id: &str) -> Option<&str> {
    let (parent, slice) = id.rsplit_once('s')?;
    (whole_identifier(parent)
        && !slice.is_empty()
        && slice.len() <= 6
        && slice.bytes().all(|b| b.is_ascii_digit())
        && !slice.starts_with('0'))
    .then_some(parent)
}

fn invalid(message: &str) -> InventoryError {
    InventoryError::Invalid(message.into())
}

fn query<T: DeserializeOwned>(
    runner: &impl CommandRunner,
    args: &[&str],
) -> Result<T, InventoryError> {
    let output = runner
        .run(DISKUTIL, args)
        .map_err(|_| InventoryError::Command("diskutil could not run".into()))?;
    if !output.success {
        return Err(InventoryError::Command("diskutil returned an error".into()));
    }
    if output.stdout.is_empty()
        || output.stdout.len() > MAX_OUTPUT
        || output.stderr.len() > MAX_OUTPUT
    {
        return Err(invalid("command output is empty or exceeds the size limit"));
    }
    // Diagnostics and raw plist values are deliberately excluded from errors.
    plist::from_bytes(&output.stdout)
        .map_err(|_| invalid("malformed or incorrectly typed property list"))
}

fn validate_listing(list: &Listing) -> Result<BTreeSet<String>, InventoryError> {
    if list.whole_disks.len() > 256 || list.disks.len() > 256 {
        return Err(invalid("too many disks"));
    }
    let mut expected = BTreeSet::new();
    for id in &list.whole_disks {
        if !whole_identifier(id) || !expected.insert(id.clone()) {
            return Err(invalid("invalid or duplicated whole-disk identifier"));
        }
    }
    let mut observed = BTreeSet::new();
    for disk in &list.disks {
        if !whole_identifier(&disk.id)
            || !observed.insert(disk.id.clone())
            || disk.size == 0
            || disk.size > i64::MAX as u64
        {
            return Err(invalid("invalid whole-disk entry"));
        }
        if let Some(parts) = &disk.partitions {
            if parts.len() > 256 {
                return Err(invalid("too many partitions"));
            }
            let mut unique = BTreeSet::new();
            for part in parts {
                if partition_parent(&part.id) != Some(disk.id.as_str()) || !unique.insert(&part.id)
                {
                    return Err(invalid("partition identifier does not belong to its disk"));
                }
            }
        }
    }
    if expected != observed {
        return Err(invalid("whole-disk lists disagree"));
    }
    Ok(expected)
}

fn system_evidence(root: SystemInfo, physical: &BTreeSet<String>) -> Option<SystemEvidence> {
    if root.mount_point != "/" {
        return None;
    }
    let apfs = root.stores.is_some();
    let mut disks = BTreeSet::new();
    if let Some(stores) = root.stores {
        if stores.is_empty() || stores.len() > 256 {
            return None;
        }
        for store in stores {
            disks.insert(partition_parent(&store.id)?.to_owned());
        }
    } else {
        let parent = root.parent?;
        if !whole_identifier(&parent) {
            return None;
        }
        disks.insert(parent);
    }
    if !disks.is_subset(physical) {
        return None;
    }
    Some(SystemEvidence {
        disks,
        encrypted: root.encryption == Some(true) || root.file_vault == Some(true),
        apfs,
    })
}

fn container_content(content: &str) -> bool {
    matches!(
        content,
        "Apple_APFS"
            | "Apple_APFS_ISC"
            | "Apple_APFS_Recovery"
            | "Apple_CoreStorage"
            | "Apple_RAID"
            | "Apple_RAID_Offline"
    )
}

fn os_content(content: &str) -> bool {
    container_content(content)
        || matches!(
            content,
            "Apple_HFS" | "EFI" | "Linux Filesystem" | "Linux Swap" | "Windows Recovery"
        )
}

fn record(listed: &ListedDisk, system: Option<&SystemEvidence>) -> Disk {
    let system_disk = system.map(|s| s.disks.contains(&listed.id));
    let mut contents = vec![listed.content.as_deref().unwrap_or("")];
    if let Some(parts) = &listed.partitions {
        contents.extend(parts.iter().filter_map(|p| p.content.as_deref()));
    }
    Disk {
        id: format!("/dev/{}", listed.id),
        size_bytes: listed.size,
        system_disk,
        mounted_system: system_disk == Some(true),
        encryption_in_use: system.is_some_and(|s| s.encrypted && s.disks.contains(&listed.id)),
        container_member: contents.iter().any(|c| container_content(c))
            || system.is_some_and(|s| s.apfs && s.disks.contains(&listed.id)),
        os_like: contents.iter().any(|c| os_content(c)) || system_disk == Some(true),
        // A partition table cannot prove that a disk contains no user data.
        has_data: true,
        ..Disk::default()
    }
}

fn apply_info(disk: &mut Disk, listed: &ListedDisk, info: DiskInfo, warnings: &mut Vec<Warning>) {
    if info.id != listed.id
        || info.node != disk.id
        || !info.whole
        || !matches!(info.kind.as_str(), "Physical" | "Unknown")
    {
        disk.identity_ambiguous = true;
        warning(
            warnings,
            Some(&disk.id),
            "identity_mismatch",
            "Disk identity changed or is not a physical whole disk.",
        );
        return;
    }
    if info.kind == "Unknown" {
        // Recent macOS versions can return Unknown for a disk selected by
        // `list physical`. Preserve observed fields without asserting safety.
        warning(
            warnings,
            Some(&disk.id),
            "physical_kind_unknown",
            "The physical-disk list and detail query did not independently confirm physical media.",
        );
    }
    if info.size != Some(listed.size) {
        disk.identity_ambiguous = true;
        warning(
            warnings,
            Some(&disk.id),
            "geometry_mismatch",
            "Disk size is missing or changed between inventory commands.",
        );
        return;
    }
    disk.external = info.internal == Some(false);
    disk.logical_sector_size = info.logical_sector.unwrap_or(0);
    disk.model = info
        .model
        .filter(|m| m.len() <= 1024 && !m.chars().any(char::is_control))
        .unwrap_or_default();
    disk.bus = match info.bus.as_deref() {
        Some("USB") => "usb",
        Some("Secure Digital" | "SD") => "sd",
        Some("NVMe") => "nvme",
        Some("PCI-Express") => "pci-express",
        Some("SATA" | "Serial ATA") => "sata",
        Some("FireWire") => "firewire",
        _ => "unknown",
    }
    .into();
    disk.nvme = disk.bus == "nvme";
    disk.encryption_in_use |= info.encryption == Some(true) || info.file_vault == Some(true);
    disk.container_member |= info.raid_master == Some(true) || info.raid_slice == Some(true);
    disk.os_like |= info.bootable == Some(true);
    if info.internal.is_none() {
        warning(
            warnings,
            Some(&disk.id),
            "location_unknown",
            "Internal/external location was not reported.",
        );
    }
    if ![512, 4096].contains(&disk.logical_sector_size) {
        warning(
            warnings,
            Some(&disk.id),
            "logical_sector_unknown",
            "Logical-sector size is missing or unsupported.",
        );
    }
    if disk.bus == "unknown" {
        warning(
            warnings,
            Some(&disk.id),
            "transport_unknown",
            "Storage transport was not recognized.",
        );
    }
}

pub(super) fn discover(runner: &impl CommandRunner) -> Result<Inventory, InventoryError> {
    let list: Listing = query(runner, &["list", "-plist", "physical"])?;
    let physical = validate_listing(&list)?;
    let mut warnings = Vec::new();
    let system = query(runner, &["info", "-plist", "/"])
        .ok()
        .and_then(|root| system_evidence(root, &physical));
    if system.is_none() {
        warning(
            &mut warnings,
            None,
            "system_unknown",
            "The running system could not be mapped to physical disks.",
        );
    }
    let mut disks = Vec::new();
    for listed in list.disks {
        let mut disk = record(&listed, system.as_ref());
        match query(runner, &["info", "-plist", &listed.id]) {
            Ok(info) => apply_info(&mut disk, &listed, info, &mut warnings),
            Err(_) => {
                disk.identity_ambiguous = true;
                warning(
                    &mut warnings,
                    Some(&disk.id),
                    "info_unavailable",
                    "Detailed physical-disk information was unavailable or invalid.",
                );
            }
        }
        warning(
            &mut warnings,
            Some(&disk.id),
            "identity_missing",
            "diskutil does not provide a verified hardware serial; identity is incomplete.",
        );
        warning(
            &mut warnings,
            Some(&disk.id),
            "physical_sector_unknown",
            "Physical-sector size is not verified by this provider.",
        );
        warning(
            &mut warnings,
            Some(&disk.id),
            "safety_incomplete",
            "Mounted descendants, encryption, and storage-container membership have not been exhaustively audited; writes are blocked.",
        );
        // This provider never invents serials, assumes physical-sector size,
        // or promotes incomplete topology/encryption observations to safe.
        disk.safety_checks_complete = false;
        disks.push(disk);
    }
    Ok(Inventory {
        source: "macos_diskutil".into(),
        disks,
        warnings,
    })
}
