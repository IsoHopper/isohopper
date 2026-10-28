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

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use crate::CommandOutput;
    use std::io;

    // Replace only external CIM operations. The production script still imports
    // its trusted modules, invokes methods, projects nulls and serializes JSON.
    // Each method returns only its own documented output fields, so an incorrect
    // field name in the production projection cannot pass using another method.
    const CIM_FIXTURES: &str = r#"
function Get-TestEncryptionVolume {
    [CmdletBinding()]
    param([string]$Namespace, [string]$ClassName, [uint32]$OperationTimeoutSec)
    if ($Namespace -ne 'Root\CIMV2\Security\MicrosoftVolumeEncryption' -or $ClassName -ne 'Win32_EncryptableVolume') { throw 'Unexpected test query' }
    if ($script:EmptyEncryptionQuery) { return }
    $states = @(
        @{conversion=0; percentage=0; protection=0; lock=0; method=0},
        @{conversion=1; percentage=100; protection=1; lock=0; method=7},
        @{conversion=0; percentage=0; protection=0; lock=1; method=5},
        @{conversion=1; percentage=100; protection=2; lock=1; method=[uint32]::MaxValue}
    )
    foreach ($case in 0..6) {
        [pscustomobject]@{
            DeviceID = '\\?\Volume{00000000-0000-0000-0000-' + $case.ToString('D12') + '}\'
            TestCase = $case
            State = $states[[Math]::Min($case, 3)]
        }
    }
}
function Invoke-TestEncryptionMethod {
    [CmdletBinding()]
    param($InputObject, [string]$MethodName, [hashtable]$Arguments, [uint32]$OperationTimeoutSec)
    if ($InputObject.TestCase -eq 5) { throw 'Synthetic method failure' }
    $state = $InputObject.State
    $result = switch ($MethodName) {
        'GetConversionStatus' {
            if ($Arguments.Count -ne 1 -or $Arguments.PrecisionFactor -ne 0) { throw 'Unexpected conversion arguments' }
            @{ConversionStatus=[uint32]$state.conversion; EncryptionPercentage=[uint32]$state.percentage; EncryptionFlags=[uint32]0; WipingStatus=[uint32]0; WipingPercentage=[uint32]0}
        }
        'GetProtectionStatus' { @{ProtectionStatus=[uint32]$state.protection} }
        'GetLockStatus' { @{LockStatus=[uint32]$state.lock} }
        'GetEncryptionMethod' { @{EncryptionMethod=[uint32]$state.method; SelfEncryptionDriveEncryptionMethod=$null} }
        default { throw 'Unexpected test method' }
    }
    if ($InputObject.TestCase -ne 6) {
        $result.ReturnValue = if ($InputObject.TestCase -eq 4) { [uint32]2150694912 } else { [uint32]0 }
    }
    [pscustomobject]$result
}
"#;

    struct ProjectionRunner;
    impl CommandRunner for ProjectionRunner {
        fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
            assert_eq!(program, windows::POWERSHELL);
            assert_eq!(args, ARGS);
            let script = projected_script(false);
            let output = crate::native::test_powershell_script(&script)?;
            assert!(
                output.success,
                "synthetic PowerShell projection failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            Ok(output)
        }
    }

    fn projected_script(empty: bool) -> String {
        // These checks guard the test boundary: never accidentally enumerate a
        // real volume if the production query spelling changes.
        assert_eq!(SCRIPT.matches("CimCmdlets\\Get-CimInstance").count(), 1);
        assert_eq!(SCRIPT.matches("CimCmdlets\\Invoke-CimMethod").count(), 4);
        assert_eq!(SCRIPT.matches("$provider = 'available'").count(), 1);
        let script = SCRIPT
            .replace("CimCmdlets\\Get-CimInstance", "Get-TestEncryptionVolume")
            .replace("CimCmdlets\\Invoke-CimMethod", "Invoke-TestEncryptionMethod")
            .replacen(
                "$provider = 'available'",
                &format!(
                    "{CIM_FIXTURES}\n$script:EmptyEncryptionQuery = ${empty}\n$provider = 'available'"
                ),
                1,
            );
        assert!(!script.contains("CimCmdlets\\Get-"));
        assert!(!script.contains("CimCmdlets\\Invoke-"));
        script
    }

    #[test]
    fn windows_projects_bitlocker_methods_without_inventing_success() {
        let observation = collect_with(&ProjectionRunner)
            .expect("production PowerShell projection must preserve synthetic CIM method outputs");
        assert_eq!(observation.provider, ProviderStatus::Available);
        assert_eq!(observation.volumes.len(), 7);
        let values = &observation.volumes;
        let expected = [
            (
                ConversionStatus::FullyDecrypted,
                0,
                ProtectionStatus::Off,
                LockStatus::Unlocked,
                EncryptionMethod::None,
            ),
            (
                ConversionStatus::FullyEncrypted,
                100,
                ProtectionStatus::On,
                LockStatus::Unlocked,
                EncryptionMethod::XtsAes256,
            ),
            (
                ConversionStatus::FullyDecrypted,
                0,
                ProtectionStatus::Off,
                LockStatus::Locked,
                EncryptionMethod::Hardware,
            ),
            (
                ConversionStatus::FullyEncrypted,
                100,
                ProtectionStatus::Unknown,
                LockStatus::Locked,
                EncryptionMethod::Unknown,
            ),
        ];
        for (volume, (conversion, percentage, protection, lock, method)) in
            values.iter().zip(expected)
        {
            assert_eq!(volume.conversion.return_code, Some(0));
            assert_eq!(volume.conversion.value, Some(conversion));
            assert_eq!(volume.encryption_percentage, Some(percentage));
            assert_eq!(volume.protection.return_code, Some(0));
            assert_eq!(volume.protection.value, Some(protection));
            assert_eq!(volume.lock.return_code, Some(0));
            assert_eq!(volume.lock.value, Some(lock));
            assert_eq!(volume.encryption_method.return_code, Some(0));
            assert_eq!(volume.encryption_method.value, Some(method));
        }
        for (volume, code) in values[4..].iter().zip([Some(2_150_694_912), None, None]) {
            assert_eq!(volume.conversion.return_code, code);
            assert_eq!(volume.protection.return_code, code);
            assert_eq!(volume.lock.return_code, code);
            assert_eq!(volume.encryption_method.return_code, code);
            assert_eq!(volume.conversion.value, None);
            assert_eq!(volume.encryption_percentage, None);
            assert_eq!(volume.protection.value, None);
            assert_eq!(volume.lock.value, None);
            assert_eq!(volume.encryption_method.value, None);
        }

        let empty = crate::native::test_powershell_script(&projected_script(true))
            .expect("empty synthetic query must finish");
        assert!(
            empty.success,
            "empty synthetic query failed: {}",
            String::from_utf8_lossy(&empty.stderr)
        );
        assert!(empty.stderr.is_empty());
        let empty: serde_json::Value = serde_json::from_slice(&empty.stdout).unwrap();
        assert_eq!(empty["provider"], "available");
        assert_eq!(empty["volumes"], serde_json::json!([]));
    }
}
