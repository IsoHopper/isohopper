// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{CommandRunner, Inventory, InventoryError, MAX_OUTPUT, Warning, warning};
use isohopper_core::guard::Disk;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};

// A logical allowlist token only: the native runner resolves the executable
// through the Windows system-directory API, never through PATH.
pub(super) const POWERSHELL: &str = "powershell.exe";
pub(super) const ARGS: &[&str] = &[
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    SCRIPT,
];
const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$env:PSModulePath = $PSHOME + '\Modules'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Import-Module ($PSHOME + '\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module ($PSHOME + '\Modules\Storage\Storage.psd1') -ErrorAction Stop
# CIM enum display properties can be strings. Project the underlying UInt16
# values explicitly, preserving missing values instead of inventing enum zero.
$disks = @(Storage\Get-Disk -ErrorAction Stop | Microsoft.PowerShell.Utility\Select-Object -First 257 | Microsoft.PowerShell.Core\ForEach-Object {
    $busType = $null
    if ($null -ne $_.CimInstanceProperties['BusType'].Value) {
        $busType = [uint16]$_.CimInstanceProperties['BusType'].Value
    }
    [pscustomobject]@{
        Number=$_.Number; UniqueId=$_.UniqueId; SerialNumber=$_.SerialNumber
        FriendlyName=$_.FriendlyName; Size=$_.Size
        LogicalSectorSize=$_.LogicalSectorSize; PhysicalSectorSize=$_.PhysicalSectorSize
        BusType=$busType; IsBoot=$_.IsBoot; IsSystem=$_.IsSystem
        IsReadOnly=$_.IsReadOnly; IsOffline=$_.IsOffline; IsClustered=$_.IsClustered
        NumberOfPartitions=$_.NumberOfPartitions
    }
})
$complete = $true
$partitions = @()
try {
    $partitions = @(Storage\Get-Partition -ErrorAction Stop | Microsoft.PowerShell.Utility\Select-Object -First 4097 | Microsoft.PowerShell.Core\ForEach-Object {
        $mbrType = $null
        if ($null -ne $_.CimInstanceProperties['MbrType'].Value) {
            $mbrType = [uint16]$_.CimInstanceProperties['MbrType'].Value
        }
        [pscustomobject]@{
            DiskNumber=$_.DiskNumber; PartitionNumber=$_.PartitionNumber
            IsBoot=$_.IsBoot; IsSystem=$_.IsSystem; IsReadOnly=$_.IsReadOnly
            IsOffline=$_.IsOffline; GptType=$_.GptType; MbrType=$mbrType
        }
    })
} catch {
    $complete = $false
}
[pscustomobject]@{ disks = $disks; partitions = $partitions; partitions_complete = $complete } | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 4 -Compress
"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    disks: Vec<ObservedDisk>,
    partitions: Vec<Partition>,
    partitions_complete: bool,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct ObservedDisk {
    number: u32,
    unique_id: Option<String>,
    serial_number: Option<String>,
    friendly_name: Option<String>,
    size: Option<u64>,
    logical_sector_size: Option<u64>,
    physical_sector_size: Option<u64>,
    bus_type: Option<u16>,
    is_boot: Option<bool>,
    is_system: Option<bool>,
    is_read_only: Option<bool>,
    is_offline: Option<bool>,
    is_clustered: Option<bool>,
    number_of_partitions: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct Partition {
    disk_number: u32,
    partition_number: u32,
    is_boot: Option<bool>,
    is_system: Option<bool>,
    is_read_only: Option<bool>,
    is_offline: Option<bool>,
    gpt_type: Option<String>,
    mbr_type: Option<u16>,
}

#[derive(Clone, Copy)]
enum JsonKind {
    String,
    Boolean,
    Unsigned(u8),
    Array,
}

impl JsonKind {
    fn accepts(self, value: &serde_json::Value) -> bool {
        match self {
            Self::String => value.is_string(),
            Self::Boolean => value.is_boolean(),
            Self::Unsigned(bits) => value.as_u64().is_some_and(|n| n <= u64::MAX >> (64 - bits)),
            Self::Array => value.is_array(),
        }
    }

    fn name(self) -> String {
        match self {
            Self::String => "string".into(),
            Self::Boolean => "boolean".into(),
            Self::Unsigned(bits) => format!("unsigned {bits}-bit integer"),
            Self::Array => "array".into(),
        }
    }
}

type JsonField = (&'static str, JsonKind, bool);

fn received_kind(value: Option<&serde_json::Value>) -> &'static str {
    use serde_json::Value;
    match value {
        None => "missing field",
        Some(Value::Null) => "null",
        Some(Value::Bool(_)) => "boolean",
        Some(Value::Number(_)) => "number",
        Some(Value::String(_)) => "string",
        Some(Value::Array(_)) => "array",
        Some(Value::Object(_)) => "object",
    }
}

fn check_json_fields(
    value: &serde_json::Value,
    path: &str,
    fields: &[JsonField],
) -> Option<String> {
    let Some(object) = value.as_object() else {
        return Some(format!(
            "{path} expected object, received {}",
            received_kind(Some(value))
        ));
    };
    for &(name, kind, nullable) in fields {
        let value = object.get(name);
        if nullable && value.is_none_or(serde_json::Value::is_null) {
            continue;
        }
        if !value.is_some_and(|v| kind.accepts(v)) {
            return Some(format!(
                "{path}.{name} expected {}, received {}",
                kind.name(),
                received_kind(value)
            ));
        }
    }
    object
        .keys()
        .any(|key| !fields.iter().any(|(name, _, _)| key == name))
        .then(|| format!("{path} contains an unexpected field (name redacted)"))
}

// Used only after strict deserialization fails. Never print a serde error:
// its message may contain device identifiers or attacker-controlled values.
// This diagnostic pass does not decide whether a snapshot is accepted.
fn json_error(bytes: &[u8], error: &serde_json::Error) -> InventoryError {
    use JsonKind::{Array, Boolean, String as Text, Unsigned as Uint};
    const ROOT: &[JsonField] = &[
        ("disks", Array, false),
        ("partitions", Array, false),
        ("partitions_complete", Boolean, false),
    ];
    const DISK: &[JsonField] = &[
        ("Number", Uint(32), false),
        ("UniqueId", Text, true),
        ("SerialNumber", Text, true),
        ("FriendlyName", Text, true),
        ("Size", Uint(64), true),
        ("LogicalSectorSize", Uint(64), true),
        ("PhysicalSectorSize", Uint(64), true),
        ("BusType", Uint(16), true),
        ("IsBoot", Boolean, true),
        ("IsSystem", Boolean, true),
        ("IsReadOnly", Boolean, true),
        ("IsOffline", Boolean, true),
        ("IsClustered", Boolean, true),
        ("NumberOfPartitions", Uint(32), true),
    ];
    const PARTITION: &[JsonField] = &[
        ("DiskNumber", Uint(32), false),
        ("PartitionNumber", Uint(32), false),
        ("IsBoot", Boolean, true),
        ("IsSystem", Boolean, true),
        ("IsReadOnly", Boolean, true),
        ("IsOffline", Boolean, true),
        ("GptType", Text, true),
        ("MbrType", Uint(16), true),
    ];
    let detail = match serde_json::from_slice::<serde_json::Value>(bytes) {
        Err(_) => "malformed JSON or invalid encoding (content redacted)".into(),
        Ok(value) => check_json_fields(&value, "root", ROOT)
            .or_else(|| {
                for (field, path, schema, limit) in [
                    ("disks", "disks[]", DISK, 257),
                    ("partitions", "partitions[]", PARTITION, 4097),
                ] {
                    if let Some(records) = value.get(field).and_then(|v| v.as_array()) {
                        for record in records.iter().take(limit) {
                            if let Some(detail) = check_json_fields(record, path, schema) {
                                return Some(detail);
                            }
                        }
                    }
                }
                None
            })
            .unwrap_or_else(|| "schema mismatch (content redacted)".into()),
    };
    invalid(&format!(
        "Windows inventory JSON at line {}, column {}: {detail}",
        error.line(),
        error.column()
    ))
}

fn invalid(message: &str) -> InventoryError {
    InventoryError::Invalid(message.into())
}

fn text(value: Option<&str>) -> String {
    value
        .filter(|s| s.len() <= 1024 && !s.chars().any(char::is_control))
        .unwrap_or("")
        .trim()
        .into()
}

fn bus(value: Option<u16>) -> &'static str {
    match value {
        Some(1) => "scsi",
        Some(2) => "atapi",
        Some(3) => "ata",
        Some(4) => "1394",
        Some(6) => "fibre_channel",
        Some(7) => "usb",
        Some(8) => "raid",
        Some(9) => "iscsi",
        Some(10) => "sas",
        Some(11) => "sata",
        Some(12) => "sd",
        Some(13) => "mmc",
        Some(14) => "virtual",
        Some(15) => "file_backed_virtual",
        Some(16) => "spaces",
        Some(17) => "nvme",
        _ => "unknown",
    }
}

fn record(
    observed: &ObservedDisk,
    parts: &[&Partition],
    complete: bool,
    warnings: &mut Vec<Warning>,
) -> Disk {
    let system = observed.is_boot == Some(true)
        || observed.is_system == Some(true)
        || parts
            .iter()
            .any(|p| p.is_boot == Some(true) || p.is_system == Some(true));
    let transport = bus(observed.bus_type);
    let dynamic = parts.iter().any(|p| {
        p.mbr_type == Some(0x42)
            || matches!(
                text(p.gpt_type.as_deref())
                    .trim_matches(['{', '}'])
                    .to_ascii_lowercase()
                    .as_str(),
                "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3" | "af9b60a0-1431-4f62-bc68-3311714a69ad"
            )
    });
    let disk = Disk {
        id: format!(r"\\.\PhysicalDrive{}", observed.number),
        serial: text(observed.serial_number.as_deref()),
        model: text(observed.friendly_name.as_deref()),
        bus: transport.into(),
        size_bytes: observed.size.unwrap_or(0),
        logical_sector_size: observed.logical_sector_size.unwrap_or(0),
        physical_sector_size: observed.physical_sector_size.unwrap_or(0),
        external: matches!(transport, "usb" | "sd"),
        system_disk: system.then_some(true),
        mounted_system: system,
        container_member: dynamic
            || observed.is_clustered == Some(true)
            || matches!(
                transport,
                "raid" | "spaces" | "virtual" | "file_backed_virtual"
            ),
        identity_ambiguous: text(observed.unique_id.as_deref()).is_empty(),
        nvme: transport == "nvme",
        // Get-Disk/Get-Partition do not establish encryption, pagefile, dynamic
        // volume, hotplug, or complete identity safety. No record is writable.
        safety_checks_complete: false,
        has_data: true,
        os_like: system,
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
            "A valid unique identifier was not reported; disk numbers can change across restarts.",
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
    if !system {
        warn(
            "system_unknown",
            "No boot or system membership was observed; complete system-disk exclusion is unproven.",
        );
    }
    if !complete
        || observed.number_of_partitions != Some(parts.len() as u32)
        || observed.is_boot.is_none()
        || observed.is_system.is_none()
        || parts
            .iter()
            .any(|p| p.is_boot.is_none() || p.is_system.is_none())
    {
        warn(
            "topology_unknown",
            "Partition enumeration or system membership is incomplete or inconsistent.",
        );
    }
    if observed.is_read_only == Some(true) || parts.iter().any(|p| p.is_read_only == Some(true)) {
        warn(
            "read_only",
            "Windows reports this disk or a partition as read-only.",
        );
    }
    if observed.is_read_only.is_none() || parts.iter().any(|p| p.is_read_only.is_none()) {
        warn(
            "write_protection_unknown",
            "Disk or partition write-protection status was not reported.",
        );
    }
    if observed.is_offline == Some(true) || parts.iter().any(|p| p.is_offline == Some(true)) {
        warn(
            "offline",
            "Windows reports this disk or a partition as offline.",
        );
    }
    if transport == "unknown" {
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
        "Inspection only: Get-Disk/Get-Partition do not establish complete identity, encryption, dynamic-volume, pagefile, or hotplug safety; preparation remains blocked.",
    );
    disk
}

pub(super) fn discover(runner: &impl CommandRunner) -> Result<Inventory, InventoryError> {
    let output = runner
        .run(POWERSHELL, ARGS)
        .map_err(|_| InventoryError::Command("Windows disk inventory could not run".into()))?;
    if !output.success {
        return Err(InventoryError::Command(
            "Windows disk inventory returned an error".into(),
        ));
    }
    if output.stdout.is_empty()
        || output.stdout.len() > MAX_OUTPUT
        || output.stderr.len() > MAX_OUTPUT
    {
        return Err(invalid(
            "Windows inventory output is empty or exceeds the size limit",
        ));
    }
    let listing: Listing = serde_json::from_slice(&output.stdout)
        .map_err(|error| json_error(&output.stdout, &error))?;
    if listing.disks.len() > 256 || listing.partitions.len() > 4096 {
        return Err(invalid("too many Windows disks or partitions"));
    }
    let mut numbers = BTreeSet::new();
    for disk in &listing.disks {
        if !numbers.insert(disk.number) {
            return Err(invalid("duplicated Windows disk number"));
        }
    }
    let mut partitions = BTreeSet::new();
    let mut by_disk: BTreeMap<u32, Vec<&Partition>> = BTreeMap::new();
    for part in &listing.partitions {
        if part.partition_number == 0
            || !partitions.insert((part.disk_number, part.partition_number))
        {
            return Err(invalid("invalid or duplicated Windows partition number"));
        }
        let parts = by_disk.entry(part.disk_number).or_default();
        parts.push(part);
        if parts.len() > 256 {
            return Err(invalid("too many partitions on a Windows disk"));
        }
    }
    let mut warnings = Vec::new();
    if !output.stderr.is_empty() {
        warning(
            &mut warnings,
            None,
            "command_diagnostics",
            "Windows inventory emitted diagnostics; observed metadata may be incomplete.",
        );
    }
    if by_disk.keys().any(|number| !numbers.contains(number)) {
        warning(
            &mut warnings,
            None,
            "orphan_partition",
            "A partition refers to a disk absent from this snapshot; device enumeration may have changed.",
        );
    }
    let mut serials = BTreeMap::new();
    let mut unique_ids = BTreeMap::new();
    for disk in &listing.disks {
        for (value, map) in [
            (text(disk.serial_number.as_deref()), &mut serials),
            (
                text(disk.unique_id.as_deref()).to_ascii_lowercase(),
                &mut unique_ids,
            ),
        ] {
            if !value.is_empty() {
                *map.entry(value).or_insert(0usize) += 1;
            }
        }
    }
    let mut disks = Vec::new();
    for observed in &listing.disks {
        let parts = by_disk.get(&observed.number).map_or(&[][..], Vec::as_slice);
        let mut disk = record(observed, parts, listing.partitions_complete, &mut warnings);
        if serials.get(&disk.serial).is_some_and(|n| *n > 1)
            || unique_ids
                .get(&text(observed.unique_id.as_deref()).to_ascii_lowercase())
                .is_some_and(|n| *n > 1)
        {
            disk.identity_ambiguous = true;
            warning(
                &mut warnings,
                Some(&disk.id),
                "identity_ambiguous",
                "The hardware serial or unique identifier is shared by multiple disks.",
            );
        }
        disks.push(disk);
    }
    if disks.is_empty() {
        warning(
            &mut warnings,
            None,
            "no_disks",
            "No disk records were reported. Get-Disk may omit dynamic disks and does not prove that the host has no storage.",
        );
    }
    Ok(Inventory {
        source: "windows_powershell".into(),
        disks,
        warnings,
    })
}
