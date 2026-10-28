// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only observations from the local Windows Storage Management provider.
//! These records do not authorize writes or bind provider identities to an open
//! physical-disk handle. A later preflight must establish and revalidate that
//! binding; this query is not an atomic snapshot or a generic RAID detector.
//!
//! A primordial pool retains associations even when its disks join a concrete
//! pool. Both kinds must be observed:
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-storagepooltophysicaldisk>
//! ObjectId and UniqueId are opaque provider identities, not disk numbers:
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-storageobject>
//! CanPool describes eligibility to join a pool, not membership:
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-physicaldisk>
use crate::{CommandRunner, InventoryError, MAX_OUTPUT};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::{HashMap, HashSet};

const MAX_DISKS: usize = 256;
const MAX_POOLS_PER_DISK: usize = 64;
const MAX_ASSOCIATIONS: usize = 4096;
const MAX_TEXT: usize = 4096;

pub(super) const ARGS: &[&str] = &[
    "-NoLogo",
    "-NoProfile",
    "-NonInteractive",
    "-Command",
    SCRIPT,
];
// No caller text is interpolated. The runner resolves a trusted PowerShell
// executable and bounds execution time/output. Validate the association class
// even when no disks exist, and never silently accept a truncated enumeration.
const SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
$env:PSModulePath = $PSHOME + '\Modules'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Set-StrictMode -Version 3.0
Import-Module ($PSHOME + '\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Import-Module ($PSHOME + '\Modules\CimCmdlets\CimCmdlets.psd1') -ErrorAction Stop
$namespace = 'root/Microsoft/Windows/Storage'
foreach ($class in @('MSFT_PhysicalDisk', 'MSFT_StoragePool', 'MSFT_StoragePoolToPhysicalDisk')) {
    $classes = @(CimCmdlets\Get-CimClass -Namespace $namespace -ClassName $class -OperationTimeoutSec 5 -ErrorAction Stop)
    if ($classes.Count -ne 1) { throw 'Storage provider class unavailable' }
}
$disks = @(CimCmdlets\Get-CimInstance -Namespace $namespace -ClassName MSFT_PhysicalDisk -OperationTimeoutSec 10 -ErrorAction Stop | Microsoft.PowerShell.Utility\Select-Object -First 257)
if ($disks.Count -gt 256) { throw 'Physical disk count exceeds limit' }
$associationCount = 0
$records = @(foreach ($disk in $disks) {
    $pools = @(CimCmdlets\Get-CimAssociatedInstance -InputObject $disk -Association MSFT_StoragePoolToPhysicalDisk -ResultClassName MSFT_StoragePool -OperationTimeoutSec 10 -ErrorAction Stop | Microsoft.PowerShell.Utility\Select-Object -First 65)
    if ($pools.Count -gt 64) { throw 'Per-disk pool count exceeds limit' }
    $associationCount += $pools.Count
    if ($associationCount -gt 4096) { throw 'Pool association count exceeds limit' }
    $poolRecords = @(foreach ($pool in $pools) {
        [pscustomobject]@{
            ObjectId = $pool.CimInstanceProperties['ObjectId'].Value
            UniqueId = $pool.CimInstanceProperties['UniqueId'].Value
            FriendlyName = $pool.CimInstanceProperties['FriendlyName'].Value
            IsPrimordial = $pool.CimInstanceProperties['IsPrimordial'].Value
        }
    })
    [pscustomobject]@{
        ObjectId = $disk.CimInstanceProperties['ObjectId'].Value
        UniqueId = $disk.CimInstanceProperties['UniqueId'].Value
        UniqueIdFormat = if ($null -ne $disk.CimInstanceProperties['UniqueIdFormat'].Value) { [uint16]$disk.CimInstanceProperties['UniqueIdFormat'].Value } else { $null }
        DeviceId = $disk.CimInstanceProperties['DeviceId'].Value
        SerialNumber = $disk.CimInstanceProperties['SerialNumber'].Value
        BusType = if ($null -ne $disk.CimInstanceProperties['BusType'].Value) { [uint16]$disk.CimInstanceProperties['BusType'].Value } else { $null }
        Size = if ($null -ne $disk.CimInstanceProperties['Size'].Value) { [uint64]$disk.CimInstanceProperties['Size'].Value } else { $null }
        CanPool = $disk.CimInstanceProperties['CanPool'].Value
        IsPartial = $disk.CimInstanceProperties['IsPartial'].Value
        Pools = $poolRecords
    }
})
[pscustomobject]@{ schema_version = 1; query_complete = $true; physical_disks = $records } | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 6 -Compress
"#;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StoragePool {
    pub object_id: String,
    pub unique_id: String,
    pub friendly_name: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Membership {
    /// No relationship returned; this is not affirmative evidence of non-use.
    NoAssociationObserved,
    /// Only primordial relationships returned; not a write-safety verdict.
    PrimordialOnly,
    /// At least one concrete pool was observed, even if CanPool reports true.
    NonPrimordial,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PhysicalDiskPools {
    pub object_id: String,
    pub unique_id: String,
    pub unique_id_format: Option<u16>,
    /// Provider identifier, not a Windows physical-disk number or path.
    pub device_id: Option<String>,
    pub serial_number: Option<String>,
    pub bus_type: Option<u16>,
    pub size_bytes: Option<u64>,
    pub can_pool: Option<bool>,
    pub is_partial: Option<bool>,
    pub primordial_pools: Vec<StoragePool>,
    pub nonprimordial_pools: Vec<StoragePool>,
}

impl PhysicalDiskPools {
    /// Absence of a concrete pool association is not proof that a disk is safe
    /// to overwrite. USB transport and CanPool are deliberately not consulted.
    pub fn membership(&self) -> Membership {
        if !self.nonprimordial_pools.is_empty() {
            Membership::NonPrimordial
        } else if !self.primordial_pools.is_empty() {
            Membership::PrimordialOnly
        } else {
            Membership::NoAssociationObserved
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PoolObservation {
    pub source: String,
    pub physical_disks: Vec<PhysicalDiskPools>,
}

/// Read the local provider without opening disks or changing storage state.
/// Provider errors fail the whole observation; callers must preserve unknown.
pub fn collect() -> Result<PoolObservation, InventoryError> {
    #[cfg(target_os = "windows")]
    {
        collect_with(&crate::NativeCommandRunner)
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

/// Run the fixed query through an injectable runner. Only complete, bounded
/// records with unambiguous identities are returned. Repeated consistent pool
/// identities across disks are expected; repeated physical identities are not.
pub fn collect_with(runner: &impl CommandRunner) -> Result<PoolObservation, InventoryError> {
    let output = runner
        .run(crate::windows::POWERSHELL, ARGS)
        .map_err(|_| InventoryError::Command("Windows pool observation could not run".into()))?;
    if output.stdout.len() > MAX_OUTPUT || output.stderr.len() > MAX_OUTPUT {
        return Err(invalid("pool observation output exceeds limit"));
    }
    if !output.success || !output.stderr.is_empty() {
        return Err(InventoryError::Command(
            "Windows pool query failed or reported errors".into(),
        ));
    }
    // Do not embed serde errors: they can contain provider strings or paths.
    let raw: RawObservation = serde_json::from_slice(&output.stdout)
        .map_err(|_| invalid("pool observation JSON does not match the required schema"))?;
    if raw.schema_version != 1 || !raw.query_complete {
        return Err(invalid(
            "pool query is incomplete or has an unsupported schema",
        ));
    }
    if raw.physical_disks.len() > MAX_DISKS {
        return Err(invalid("physical disk count exceeds limit"));
    }
    let mut disk_objects = HashSet::new();
    let mut disk_unique_ids = HashSet::new();
    for disk in &raw.physical_disks {
        identity(&disk.object_id)?;
        identity(&disk.unique_id)?;
        if !disk_objects.insert(disk.object_id.clone())
            || !disk_unique_ids.insert(disk.unique_id.clone())
        {
            return Err(invalid("physical disk identity is duplicated"));
        }
    }
    let mut pools_by_object: HashMap<String, RawPool> = HashMap::new();
    let mut pool_unique_ids: HashMap<String, String> = HashMap::new();
    let mut associations = 0;
    let mut physical_disks = Vec::with_capacity(raw.physical_disks.len());
    for disk in raw.physical_disks {
        optional_text(&disk.device_id)?;
        optional_text(&disk.serial_number)?;
        associations += disk.pools.len();
        if disk.pools.len() > MAX_POOLS_PER_DISK || associations > MAX_ASSOCIATIONS {
            return Err(invalid("pool association count exceeds limit"));
        }
        let mut associated_objects = HashSet::new();
        let mut primordial_pools = Vec::new();
        let mut nonprimordial_pools = Vec::new();
        for pool in disk.pools {
            identity(&pool.object_id)?;
            identity(&pool.unique_id)?;
            optional_text(&pool.friendly_name)?;
            if !associated_objects.insert(pool.object_id.clone()) {
                return Err(invalid("pool association is duplicated"));
            }
            if disk_objects.contains(&pool.object_id) || disk_unique_ids.contains(&pool.unique_id) {
                return Err(invalid("pool and physical disk identities conflict"));
            }
            if let Some(previous) = pools_by_object.get(&pool.object_id) {
                if previous != &pool {
                    return Err(invalid("associated pool records conflict"));
                }
            } else {
                if pool_unique_ids
                    .insert(pool.unique_id.clone(), pool.object_id.clone())
                    .is_some()
                {
                    return Err(invalid("pool unique identity is ambiguous"));
                }
                pools_by_object.insert(pool.object_id.clone(), pool.clone());
            }
            let target = if pool.is_primordial {
                &mut primordial_pools
            } else {
                &mut nonprimordial_pools
            };
            target.push(StoragePool {
                object_id: pool.object_id,
                unique_id: pool.unique_id,
                friendly_name: pool.friendly_name,
            });
        }
        physical_disks.push(PhysicalDiskPools {
            object_id: disk.object_id,
            unique_id: disk.unique_id,
            unique_id_format: disk.unique_id_format,
            device_id: disk.device_id,
            serial_number: disk.serial_number,
            bus_type: disk.bus_type,
            size_bytes: disk.size,
            can_pool: disk.can_pool,
            is_partial: disk.is_partial,
            primordial_pools,
            nonprimordial_pools,
        });
    }
    Ok(PoolObservation {
        source: "windows_storage_cim".into(),
        physical_disks,
    })
}

fn invalid(message: &str) -> InventoryError {
    InventoryError::Invalid(message.into())
}

fn identity(value: &str) -> Result<(), InventoryError> {
    if value.trim().is_empty() {
        return Err(invalid("storage identity is empty"));
    }
    text(value)
}

fn text(value: &str) -> Result<(), InventoryError> {
    if value.len() > MAX_TEXT || value.chars().any(char::is_control) {
        return Err(invalid(
            "storage text exceeds limit or contains control characters",
        ));
    }
    Ok(())
}

fn optional_text(value: &Option<String>) -> Result<(), InventoryError> {
    if let Some(value) = value {
        text(value)?;
    }
    Ok(())
}

// Option normally treats an absent field as None. Requiring this deserializer
// keeps explicit provider null distinct from a missing projection/schema field.
fn nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawObservation {
    schema_version: u8,
    query_complete: bool,
    physical_disks: Vec<RawDisk>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct RawDisk {
    object_id: String,
    unique_id: String,
    #[serde(deserialize_with = "nullable")]
    unique_id_format: Option<u16>,
    #[serde(deserialize_with = "nullable")]
    device_id: Option<String>,
    #[serde(deserialize_with = "nullable")]
    serial_number: Option<String>,
    #[serde(deserialize_with = "nullable")]
    bus_type: Option<u16>,
    #[serde(deserialize_with = "nullable")]
    size: Option<u64>,
    #[serde(deserialize_with = "nullable")]
    can_pool: Option<bool>,
    #[serde(deserialize_with = "nullable")]
    is_partial: Option<bool>,
    pools: Vec<RawPool>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase", deny_unknown_fields)]
struct RawPool {
    object_id: String,
    unique_id: String,
    #[serde(deserialize_with = "nullable")]
    friendly_name: Option<String>,
    is_primordial: bool,
}
