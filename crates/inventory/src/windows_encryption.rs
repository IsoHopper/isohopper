// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only BitLocker provider evidence. No result authorizes device writes.
//! Conversion, protection, lock, and encryption method are separate observations:
//! protection off can mean suspended keys, and hardware encryption can report
//! fully decrypted conversion when it is perpetually unlocked.
//! The separate method calls are not an atomic snapshot; later preparation
//! must obtain fresh evidence and independently establish complete safety.
//! Provider contracts: https://learn.microsoft.com/windows/win32/secprov/win32-encryptablevolume
//! and its GetConversionStatus, GetProtectionStatus, GetLockStatus, and
//! GetEncryptionMethod method references. No cached ProtectionStatus property
//! substitutes for these method calls.
use crate::{CommandRunner, InventoryError, NativeCommandRunner, Platform, windows};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

const MAX_OUTPUT: usize = 256 * 1024;
const MAX_VOLUMES: usize = 256;
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
$PSModuleAutoLoadingPreference = 'None'
$env:PSModulePath = $PSHOME + '\Modules'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Microsoft.PowerShell.Core\Import-Module ($PSHOME + '\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
Microsoft.PowerShell.Core\Import-Module ($PSHOME + '\Modules\CimCmdlets\CimCmdlets.psd1') -ErrorAction Stop
$provider = 'available'
$instances = @()
try {
    $instances = @(CimCmdlets\Get-CimInstance -Namespace 'Root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName 'Win32_EncryptableVolume' -OperationTimeoutSec 5 -ErrorAction Stop | Microsoft.PowerShell.Utility\Select-Object -First 257)
} catch {
    if ($_.Exception -isnot [Microsoft.Management.Infrastructure.CimException]) { throw }
    if ($_.Exception.NativeErrorCode -eq [Microsoft.Management.Infrastructure.NativeErrorCode]::InvalidNamespace) {
        $provider = 'missing_namespace'
    } elseif ($_.Exception.NativeErrorCode -eq [Microsoft.Management.Infrastructure.NativeErrorCode]::InvalidClass) {
        $provider = 'missing_class'
    } else { throw }
}
if ($instances.Count -gt 256) { throw 'Too many BitLocker volume records' }
$volumes = @($instances | Microsoft.PowerShell.Core\ForEach-Object {
    $volume = $_
    $conversion = $null
    $protection = $null
    $lock = $null
    $method = $null
    try { $conversion = CimCmdlets\Invoke-CimMethod -InputObject $volume -MethodName 'GetConversionStatus' -Arguments @{PrecisionFactor=[uint32]0} -OperationTimeoutSec 5 -ErrorAction Stop } catch {}
    try { $protection = CimCmdlets\Invoke-CimMethod -InputObject $volume -MethodName 'GetProtectionStatus' -OperationTimeoutSec 5 -ErrorAction Stop } catch {}
    try { $lock = CimCmdlets\Invoke-CimMethod -InputObject $volume -MethodName 'GetLockStatus' -OperationTimeoutSec 5 -ErrorAction Stop } catch {}
    try { $method = CimCmdlets\Invoke-CimMethod -InputObject $volume -MethodName 'GetEncryptionMethod' -OperationTimeoutSec 5 -ErrorAction Stop } catch {}
    # Preserve absent/null results. Casting a missing numeric value would
    # invent zero, incorrectly turning a failed query into successful evidence.
    [pscustomobject]@{
        device_id = $volume.DeviceID
        conversion = [pscustomobject]@{return_code=$conversion.ReturnValue; status=$conversion.ConversionStatus; percentage=$conversion.EncryptionPercentage}
        protection = [pscustomobject]@{return_code=$protection.ReturnValue; status=$protection.ProtectionStatus}
        lock = [pscustomobject]@{return_code=$lock.ReturnValue; status=$lock.LockStatus}
        encryption_method = [pscustomobject]@{return_code=$method.ReturnValue; status=$method.EncryptionMethod}
    }
})
[pscustomobject]@{provider=$provider; volumes=$volumes} | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 5 -Compress
"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Available,
    MissingNamespace,
    MissingClass,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EncryptionInventory {
    pub provider: ProviderStatus,
    pub volumes: Vec<VolumeEncryption>,
}

/// Failed method outputs are undefined and discarded; absent return codes
/// never mean zero. Values are present only after a successful method return.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MethodObservation<T> {
    pub return_code: Option<u32>,
    pub value: Option<T>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VolumeEncryption {
    pub device_id: String,
    pub conversion: MethodObservation<ConversionStatus>,
    pub encryption_percentage: Option<u8>,
    pub protection: MethodObservation<ProtectionStatus>,
    pub lock: MethodObservation<LockStatus>,
    pub encryption_method: MethodObservation<EncryptionMethod>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum ConversionStatus {
    /// Hardware encryption may mean perpetually unlocked. Inspect the method
    /// too; this state alone does not prove no encryption.
    FullyDecrypted = 0,
    FullyEncrypted = 1,
    EncryptionInProgress = 2,
    DecryptionInProgress = 3,
    EncryptionPaused = 4,
    DecryptionPaused = 5,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum ProtectionStatus {
    /// May mean unencrypted, partially encrypted, or suspended key protection.
    Off = 0,
    On = 1,
    Unknown = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum LockStatus {
    Unlocked = 0,
    /// On a hardware-encrypted drive, the provider can report this value for
    /// a locked or unlocked band. It is not absolute accessibility evidence.
    Locked = 1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[repr(u32)]
pub enum EncryptionMethod {
    None = 0,
    Aes128WithDiffuser = 1,
    Aes256WithDiffuser = 2,
    Aes128 = 3,
    Aes256 = 4,
    Hardware = 5,
    XtsAes128 = 6,
    XtsAes256 = 7,
    Unknown = 0xffff_ffff,
}

/// Query the local Windows provider. Missing provider/volume/method evidence
/// never establishes that a target is unencrypted or writable.
pub fn collect() -> Result<EncryptionInventory, InventoryError> {
    if !cfg!(target_os = "windows") {
        return Err(InventoryError::Unsupported(if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else {
            Platform::Other
        }));
    }
    collect_with(&NativeCommandRunner)
}

pub fn collect_with(runner: &impl CommandRunner) -> Result<EncryptionInventory, InventoryError> {
    let output = runner
        .run(windows::POWERSHELL, ARGS)
        .map_err(|_| InventoryError::Command("BitLocker provider query failed".into()))?;
    if output.stdout.len() > MAX_OUTPUT || output.stderr.len() > MAX_OUTPUT {
        return Err(invalid("response exceeds 256 KiB"));
    }
    if !output.success || !output.stderr.is_empty() {
        return Err(InventoryError::Command(
            "BitLocker provider query failed".into(),
        ));
    }
    let raw: RawListing = serde_json::from_slice(&output.stdout)
        .map_err(|_| invalid("response does not match the expected JSON schema"))?;
    if raw.volumes.len() > MAX_VOLUMES {
        return Err(invalid("more than 256 volume records"));
    }
    if raw.provider != ProviderStatus::Available && !raw.volumes.is_empty() {
        return Err(invalid("unavailable provider returned volume records"));
    }
    let mut seen = BTreeSet::new();
    let mut volumes = Vec::with_capacity(raw.volumes.len());
    for raw in raw.volumes {
        let device_id = canonical_guid(&raw.device_id)?;
        if !seen.insert(device_id.clone()) {
            return Err(invalid("duplicate volume GUID"));
        }
        let conversion = raw.conversion.unwrap_or_default();
        let percentage = if conversion.return_code == Some(0) {
            match conversion.percentage {
                Some(value) if value > 100 => {
                    return Err(invalid("encryption percentage exceeds 100"));
                }
                value => value.map(|value| value as u8),
            }
        } else {
            None
        };
        volumes.push(VolumeEncryption {
            device_id,
            conversion: observe(
                RawMethod {
                    return_code: conversion.return_code,
                    status: conversion.status,
                },
                |value| {
                    Some(match value {
                        0 => ConversionStatus::FullyDecrypted,
                        1 => ConversionStatus::FullyEncrypted,
                        2 => ConversionStatus::EncryptionInProgress,
                        3 => ConversionStatus::DecryptionInProgress,
                        4 => ConversionStatus::EncryptionPaused,
                        5 => ConversionStatus::DecryptionPaused,
                        _ => return None,
                    })
                },
            )?,
            encryption_percentage: percentage,
            protection: observe(raw.protection.unwrap_or_default(), |value| {
                Some(match value {
                    0 => ProtectionStatus::Off,
                    1 => ProtectionStatus::On,
                    2 => ProtectionStatus::Unknown,
                    _ => return None,
                })
            })?,
            lock: observe(raw.lock.unwrap_or_default(), |value| {
                Some(match value {
                    0 => LockStatus::Unlocked,
                    1 => LockStatus::Locked,
                    _ => return None,
                })
            })?,
            encryption_method: observe(raw.encryption_method.unwrap_or_default(), |value| {
                Some(match value {
                    0 => EncryptionMethod::None,
                    1 => EncryptionMethod::Aes128WithDiffuser,
                    2 => EncryptionMethod::Aes256WithDiffuser,
                    3 => EncryptionMethod::Aes128,
                    4 => EncryptionMethod::Aes256,
                    5 => EncryptionMethod::Hardware,
                    6 => EncryptionMethod::XtsAes128,
                    7 => EncryptionMethod::XtsAes256,
                    u32::MAX => EncryptionMethod::Unknown,
                    _ => return None,
                })
            })?,
        });
    }
    volumes.sort_by(|a, b| a.device_id.cmp(&b.device_id));
    Ok(EncryptionInventory {
        provider: raw.provider,
        volumes,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawListing {
    provider: ProviderStatus,
    volumes: Vec<RawVolume>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVolume {
    device_id: String,
    conversion: Option<RawConversion>,
    protection: Option<RawMethod>,
    lock: Option<RawMethod>,
    encryption_method: Option<RawMethod>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConversion {
    return_code: Option<u32>,
    status: Option<u32>,
    percentage: Option<u32>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMethod {
    return_code: Option<u32>,
    status: Option<u32>,
}

fn observe<T>(
    raw: RawMethod,
    parse: impl FnOnce(u32) -> Option<T>,
) -> Result<MethodObservation<T>, InventoryError> {
    let value = if raw.return_code == Some(0) {
        raw.status
            .map(|status| parse(status).ok_or_else(|| invalid("unknown method status value")))
            .transpose()?
    } else {
        None
    };
    Ok(MethodObservation {
        return_code: raw.return_code,
        value,
    })
}

fn canonical_guid(value: &str) -> Result<String, InventoryError> {
    let guid = value
        .strip_prefix(r"\\?\Volume{")
        .and_then(|value| value.strip_suffix("}\\"))
        .ok_or_else(|| invalid("noncanonical volume GUID path"))?;
    if guid.len() != 36
        || !guid.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
    {
        return Err(invalid("invalid volume GUID"));
    }
    Ok(format!(r"\\?\Volume{{{}}}\", guid.to_ascii_lowercase()))
}

fn invalid(message: &str) -> InventoryError {
    InventoryError::Invalid(format!("BitLocker evidence: {message}"))
}
