// SPDX-License-Identifier: GPL-3.0-or-later
//! Windows provider observations. These records are not retained device handles
//! or target authorization. Disk and partition queries are sequential, not an
//! atomic snapshot; callers must bind and revalidate them independently.
use crate::{CommandRunner, Inventory, InventoryError, MAX_OUTPUT, Warning, warning};
use isohopper_core::guard::Disk;
use serde::{Deserialize, Serialize};
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
    $uniqueIdFormat = $null
    if ($null -ne $_.CimInstanceProperties['UniqueIdFormat'].Value) {
        $uniqueIdFormat = [uint16]$_.CimInstanceProperties['UniqueIdFormat'].Value
    }
    [pscustomobject]@{
        Number=$_.Number; UniqueId=$_.UniqueId; SerialNumber=$_.SerialNumber
        Path=$_.CimInstanceProperties['Path'].Value; UniqueIdFormat=$uniqueIdFormat
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
        $offset = $null
        if ($null -ne $_.CimInstanceProperties['Offset'].Value) {
            $offset = [uint64]$_.CimInstanceProperties['Offset'].Value
        }
        $size = $null
        if ($null -ne $_.CimInstanceProperties['Size'].Value) {
            $size = [uint64]$_.CimInstanceProperties['Size'].Value
        }
        [pscustomobject]@{
            DiskNumber=$_.DiskNumber; PartitionNumber=$_.PartitionNumber
            Offset=$offset; Size=$size
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
    disks: Vec<WindowsDiskRecord>,
    partitions: Vec<WindowsPartitionRecord>,
    partitions_complete: bool,
}

/// Typed MSFT_Disk values. Strings retain their reported spelling and spacing;
/// unsupported text is removed with an explicit issue. `path` is untrusted data,
/// never a command or proof that an opened handle belongs to this record.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all(deserialize = "PascalCase"), deny_unknown_fields)]
pub struct WindowsDiskRecord {
    pub number: u32,
    pub path: Option<String>,
    pub unique_id: Option<String>,
    pub unique_id_format: Option<u16>,
    pub serial_number: Option<String>,
    pub friendly_name: Option<String>,
    pub size: Option<u64>,
    pub logical_sector_size: Option<u64>,
    pub physical_sector_size: Option<u64>,
    pub bus_type: Option<u16>,
    pub is_boot: Option<bool>,
    pub is_system: Option<bool>,
    pub is_read_only: Option<bool>,
    pub is_offline: Option<bool>,
    pub is_clustered: Option<bool>,
    pub number_of_partitions: Option<u32>,
}

/// Typed MSFT_Partition values, including byte offsets and sizes. Presence does
/// not validate geometry, partition style or membership in a retained device.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all(deserialize = "PascalCase"), deny_unknown_fields)]
pub struct WindowsPartitionRecord {
    pub disk_number: u32,
    pub partition_number: u32,
    pub offset: Option<u64>,
    pub size: Option<u64>,
    pub is_boot: Option<bool>,
    pub is_system: Option<bool>,
    pub is_read_only: Option<bool>,
    pub is_offline: Option<bool>,
    pub gpt_type: Option<String>,
    pub mbr_type: Option<u16>,
}

/// Completeness of this bounded provider response only, never disk safety.
/// `*_fields_present` means reported, not valid geometry, known enum values or
/// independently confirmed identity. Empty record sets make these predicates
/// vacuously true; they do not prove that the machine contains no disks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsEvidenceCompleteness {
    pub partition_query_complete: bool,
    pub partition_membership_consistent: bool,
    pub identity_fields_present: bool,
    pub geometry_fields_present: bool,
    pub status_fields_present: bool,
    pub identity_values_unique: bool,
    pub command_clean: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsTextField {
    Path,
    UniqueId,
    SerialNumber,
    FriendlyName,
    GptType,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WindowsEvidenceIssue {
    InvalidText {
        disk_number: u32,
        partition_number: Option<u32>,
        field: WindowsTextField,
    },
    DuplicateIdentity {
        disk_number: u32,
        field: WindowsTextField,
    },
    OrphanPartition {
        disk_number: u32,
        partition_number: u32,
    },
    PartitionCountMismatch {
        disk_number: u32,
        reported: Option<u32>,
        observed: u32,
    },
}

/// Freshly queried provider records, including orphan partitions and explicit
/// ambiguity. No record is discarded because it failed association with a disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WindowsEvidence {
    pub source: String,
    pub disks: Vec<WindowsDiskRecord>,
    pub partitions: Vec<WindowsPartitionRecord>,
    pub completeness: WindowsEvidenceCompleteness,
    pub issues: Vec<WindowsEvidenceIssue>,
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
        ("Path", Text, true),
        ("UniqueId", Text, true),
        ("UniqueIdFormat", Uint(16), true),
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
        ("Offset", Uint(64), true),
        ("Size", Uint(64), true),
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
    observed: &WindowsDiskRecord,
    parts: &[&WindowsPartitionRecord],
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

/// Query Windows without opening any returned path. Other hosts are unsupported.
pub fn collect_evidence() -> Result<WindowsEvidence, InventoryError> {
    #[cfg(target_os = "windows")]
    {
        collect_evidence_with(&crate::NativeCommandRunner)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(InventoryError::Unsupported(if cfg!(target_os = "macos") {
            crate::Platform::MacOs
        } else if cfg!(target_os = "linux") {
            crate::Platform::Linux
        } else {
            crate::Platform::Other
        }))
    }
}

/// Run the same fixed query as discovery with an injectable command runner.
/// Missing optional fields remain unknown. Values are not repaired or filled
/// from other records. Numeric ranges and identifier formats require independent
/// validation before use; no path is opened or passed to a command here.
pub fn collect_evidence_with(
    runner: &impl CommandRunner,
) -> Result<WindowsEvidence, InventoryError> {
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
    let mut listing: Listing = serde_json::from_slice(&output.stdout)
        .map_err(|error| json_error(&output.stdout, &error))?;
    if listing.disks.len() > 256 || listing.partitions.len() > 4096 {
        return Err(invalid("too many Windows disks or partitions"));
    }
    let mut issues = Vec::new();
    let mut numbers = BTreeSet::new();
    for disk in &mut listing.disks {
        if !numbers.insert(disk.number) {
            return Err(invalid("duplicated Windows disk number"));
        }
        for (field, value, limit) in [
            (WindowsTextField::Path, &mut disk.path, 4096),
            (WindowsTextField::UniqueId, &mut disk.unique_id, 1024),
            (
                WindowsTextField::SerialNumber,
                &mut disk.serial_number,
                1024,
            ),
            (
                WindowsTextField::FriendlyName,
                &mut disk.friendly_name,
                1024,
            ),
        ] {
            bound_text(value, limit, disk.number, None, field, &mut issues);
        }
    }
    let mut partitions = BTreeSet::new();
    let mut counts = BTreeMap::new();
    for part in &mut listing.partitions {
        if part.partition_number == 0
            || !partitions.insert((part.disk_number, part.partition_number))
        {
            return Err(invalid("invalid or duplicated Windows partition number"));
        }
        let count = counts.entry(part.disk_number).or_insert(0u32);
        *count += 1;
        if *count > 256 {
            return Err(invalid("too many partitions on a Windows disk"));
        }
        bound_text(
            &mut part.gpt_type,
            1024,
            part.disk_number,
            Some(part.partition_number),
            WindowsTextField::GptType,
            &mut issues,
        );
        if !numbers.contains(&part.disk_number) {
            issues.push(WindowsEvidenceIssue::OrphanPartition {
                disk_number: part.disk_number,
                partition_number: part.partition_number,
            });
        }
    }
    for disk in &listing.disks {
        let observed = counts.get(&disk.number).copied().unwrap_or(0);
        if disk.number_of_partitions != Some(observed) {
            issues.push(WindowsEvidenceIssue::PartitionCountMismatch {
                disk_number: disk.number,
                reported: disk.number_of_partitions,
                observed,
            });
        }
    }
    // These comparisons detect ambiguous reported values, not physical identity.
    // Keep legacy serial comparison; fold ASCII case for path and VPD strings.
    for field in [
        WindowsTextField::Path,
        WindowsTextField::UniqueId,
        WindowsTextField::SerialNumber,
    ] {
        let mut identities: BTreeMap<String, Vec<u32>> = BTreeMap::new();
        for disk in &listing.disks {
            let value = match field {
                WindowsTextField::Path => disk.path.as_deref(),
                WindowsTextField::UniqueId => disk.unique_id.as_deref(),
                WindowsTextField::SerialNumber => disk.serial_number.as_deref(),
                _ => unreachable!(),
            }
            .map(str::trim)
            .unwrap_or("");
            if !value.is_empty() {
                let key = if field == WindowsTextField::SerialNumber {
                    value.to_owned()
                } else {
                    value.to_ascii_lowercase()
                };
                identities.entry(key).or_default().push(disk.number);
            }
        }
        for duplicates in identities.values().filter(|values| values.len() > 1) {
            for &disk_number in duplicates {
                issues.push(WindowsEvidenceIssue::DuplicateIdentity { disk_number, field });
            }
        }
    }
    let present = |value: &Option<String>| value.as_ref().is_some_and(|s| !s.trim().is_empty());
    let completeness = WindowsEvidenceCompleteness {
        partition_query_complete: listing.partitions_complete,
        partition_membership_consistent: !issues.iter().any(|issue| {
            matches!(
                issue,
                WindowsEvidenceIssue::OrphanPartition { .. }
                    | WindowsEvidenceIssue::PartitionCountMismatch { .. }
            )
        }),
        identity_fields_present: listing.disks.iter().all(|disk| {
            present(&disk.path)
                && present(&disk.unique_id)
                && present(&disk.serial_number)
                && disk.unique_id_format.is_some()
        }),
        geometry_fields_present: listing.disks.iter().all(|disk| {
            disk.size.is_some()
                && disk.logical_sector_size.is_some()
                && disk.physical_sector_size.is_some()
        }) && listing
            .partitions
            .iter()
            .all(|part| part.offset.is_some() && part.size.is_some()),
        status_fields_present: listing.disks.iter().all(|disk| {
            disk.is_boot.is_some()
                && disk.is_system.is_some()
                && disk.is_read_only.is_some()
                && disk.is_offline.is_some()
                && disk.is_clustered.is_some()
        }) && listing.partitions.iter().all(|part| {
            part.is_boot.is_some()
                && part.is_system.is_some()
                && part.is_read_only.is_some()
                && part.is_offline.is_some()
        }),
        identity_values_unique: !issues
            .iter()
            .any(|issue| matches!(issue, WindowsEvidenceIssue::DuplicateIdentity { .. })),
        command_clean: output.stderr.is_empty(),
    };
    Ok(WindowsEvidence {
        source: "windows_powershell".into(),
        disks: listing.disks,
        partitions: listing.partitions,
        completeness,
        issues,
    })
}

fn bound_text(
    value: &mut Option<String>,
    limit: usize,
    disk_number: u32,
    partition_number: Option<u32>,
    field: WindowsTextField,
    issues: &mut Vec<WindowsEvidenceIssue>,
) {
    if value
        .as_ref()
        .is_some_and(|s| s.len() > limit || s.chars().any(char::is_control))
    {
        *value = None;
        issues.push(WindowsEvidenceIssue::InvalidText {
            disk_number,
            partition_number,
            field,
        });
    }
}

pub(super) fn discover(runner: &impl CommandRunner) -> Result<Inventory, InventoryError> {
    let listing = collect_evidence_with(runner)?;
    let mut by_disk: BTreeMap<u32, Vec<&WindowsPartitionRecord>> = BTreeMap::new();
    for part in &listing.partitions {
        by_disk.entry(part.disk_number).or_default().push(part);
    }
    let mut warnings = Vec::new();
    if !listing.completeness.command_clean {
        warning(
            &mut warnings,
            None,
            "command_diagnostics",
            "Windows inventory emitted diagnostics; observed metadata may be incomplete.",
        );
    }
    if listing
        .issues
        .iter()
        .any(|issue| matches!(issue, WindowsEvidenceIssue::OrphanPartition { .. }))
    {
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
        let mut disk = record(
            observed,
            parts,
            listing.completeness.partition_query_complete,
            &mut warnings,
        );
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

#[cfg(test)]
mod projection_tests {
    use super::*;

    // In-memory CIM objects only. Do not use New-CimInstance against a provider:
    // these constructors and properties never contact or modify host storage.
    const CIM_FIXTURES: &str = r#"
function Add-TestProperty {
    param($Instance, [string]$Name, $Value, [Microsoft.Management.Infrastructure.CimType]$Type)
    [void]$Instance.CimInstanceProperties.Add([Microsoft.Management.Infrastructure.CimProperty]::Create($Name, $Value, $Type, [Microsoft.Management.Infrastructure.CimFlags]0))
}
function Get-TestDisk {
    [CmdletBinding()]
    param()
    foreach ($number in 7..8) {
        $record = [Microsoft.Management.Infrastructure.CimInstance]::new('MSFT_Disk', 'root/Microsoft/Windows/Storage')
        Add-TestProperty $record 'Number' ([uint32]$number) 'UInt32'
        Add-TestProperty $record 'NumberOfPartitions' ([uint32]1) 'UInt32'
        Add-TestProperty $record 'IsBoot' $false 'Boolean'
        Add-TestProperty $record 'IsSystem' $false 'Boolean'
        if ($number -eq 7) {
            Add-TestProperty $record 'Path' '\\?\test#disk$(literal);7' 'String'
            Add-TestProperty $record 'UniqueIdFormat' ([uint16]3) 'UInt16'
            Add-TestProperty $record 'BusType' ([uint16]7) 'UInt16'
        } else {
            Add-TestProperty $record 'Path' $null 'String'
            Add-TestProperty $record 'UniqueIdFormat' $null 'UInt16'
            Add-TestProperty $record 'BusType' $null 'UInt16'
        }
        $record
    }
}
function Get-TestPartition {
    [CmdletBinding()]
    param()
    foreach ($number in 7..8) {
        $record = [Microsoft.Management.Infrastructure.CimInstance]::new('MSFT_Partition', 'root/Microsoft/Windows/Storage')
        Add-TestProperty $record 'DiskNumber' ([uint32]$number) 'UInt32'
        Add-TestProperty $record 'PartitionNumber' ([uint32]1) 'UInt32'
        if ($number -eq 7) {
            Add-TestProperty $record 'Offset' ([uint64]4503599627370497) 'UInt64'
            Add-TestProperty $record 'Size' ([uint64]::MaxValue) 'UInt64'
            Add-TestProperty $record 'MbrType' ([uint16]66) 'UInt16'
        } else {
            Add-TestProperty $record 'Offset' $null 'UInt64'
            Add-TestProperty $record 'Size' $null 'UInt64'
            Add-TestProperty $record 'MbrType' $null 'UInt16'
        }
        $record
    }
}
"#;

    fn projected_script() -> String {
        assert_eq!(SCRIPT.matches("Storage\\Get-Disk").count(), 1);
        assert_eq!(SCRIPT.matches("Storage\\Get-Partition").count(), 1);
        assert_eq!(SCRIPT.matches("$disks = @(").count(), 1);
        let projected = SCRIPT
            .replace("Storage\\Get-Disk", "Get-TestDisk")
            .replace("Storage\\Get-Partition", "Get-TestPartition")
            .replacen("$disks = @(", &format!("{CIM_FIXTURES}\n$disks = @("), 1);
        // Fail before execution if a future production edit adds a real query
        // that this test has not replaced with a controlled fixture.
        assert!(!projected.contains("Storage\\Get-"));
        projected
    }

    #[test]
    fn controlled_projection_cannot_reach_real_storage_queries() {
        let projected = projected_script();
        assert!(!projected.contains("Storage\\Get-"));
        assert_eq!(projected.matches("$disks = @(Get-TestDisk").count(), 1);
        assert_eq!(
            projected
                .matches("$partitions = @(Get-TestPartition")
                .count(),
            1
        );
        for field in ["Path", "UniqueIdFormat", "Offset", "Size"] {
            assert!(projected.contains(&format!("$_.CimInstanceProperties['{field}'].Value")));
        }
        assert!(projected.contains("ConvertTo-Json -Depth 4 -Compress"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_projects_typed_disk_evidence_from_controlled_cim() {
        struct ProjectionRunner;
        impl CommandRunner for ProjectionRunner {
            fn run(&self, program: &str, args: &[&str]) -> std::io::Result<crate::CommandOutput> {
                assert_eq!(program, POWERSHELL);
                assert_eq!(args, ARGS);
                let output = crate::native::test_powershell_script(&projected_script())?;
                assert!(
                    output.success,
                    "controlled CIM projection failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                Ok(output)
            }
        }
        let evidence = collect_evidence_with(&ProjectionRunner)
            .expect("production projection must preserve controlled CIM evidence");
        assert_eq!(evidence.disks.len(), 2);
        assert_eq!(evidence.partitions.len(), 2);
        let first = &evidence.disks[0];
        assert_eq!(first.number, 7);
        assert_eq!(first.path.as_deref(), Some(r"\\?\test#disk$(literal);7"));
        assert_eq!(first.unique_id_format, Some(3));
        assert_eq!(first.bus_type, Some(7));
        assert_eq!(first.is_boot, Some(false));
        assert_eq!(first.is_system, Some(false));
        assert_eq!(evidence.partitions[0].offset, Some(4_503_599_627_370_497));
        assert_eq!(evidence.partitions[0].size, Some(u64::MAX));
        assert_eq!(evidence.partitions[0].mbr_type, Some(0x42));
        assert_eq!(evidence.disks[1].path, None);
        assert_eq!(evidence.disks[1].unique_id_format, None);
        assert_eq!(evidence.disks[1].bus_type, None);
        assert_eq!(evidence.partitions[1].offset, None);
        assert_eq!(evidence.partitions[1].size, None);
        assert_eq!(evidence.partitions[1].mbr_type, None);
        assert!(evidence.completeness.partition_query_complete);
        assert!(evidence.completeness.partition_membership_consistent);
        assert!(!evidence.completeness.identity_fields_present);
        assert!(!evidence.completeness.geometry_fields_present);
        assert!(evidence.completeness.command_clean);
    }
}
