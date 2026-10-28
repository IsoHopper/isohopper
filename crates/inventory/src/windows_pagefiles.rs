// SPDX-License-Identifier: GPL-3.0-or-later
//! Active pagefile names reported by local WMI. These are observations, not
//! retained volume mappings or permission to write any disk. The caller must
//! resolve and revalidate their storage separately before target authorization.
#[cfg(not(target_os = "windows"))]
use crate::Platform;
use crate::{CommandRunner, InventoryError, MAX_OUTPUT, windows::POWERSHELL};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const MAX_PAGEFILES: usize = 64;
const MAX_PATH_BYTES: usize = 4096;

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
Import-Module ($PSHOME + '\Modules\CimCmdlets\CimCmdlets.psd1') -ErrorAction Stop
$pagefiles = @(CimCmdlets\Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PageFileUsage -Property Name -OperationTimeoutSec 15 -ErrorAction Stop | Microsoft.PowerShell.Utility\Select-Object -First 65 | Microsoft.PowerShell.Core\ForEach-Object {
    [pscustomobject]@{ Name = $_.Name }
})
[pscustomobject]@{ pagefiles = $pagefiles; query_complete = $true } | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 3 -Compress
"#;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Pagefile {
    pub path: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PagefileObservation {
    pub source: String,
    pub pagefiles: Vec<Pagefile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    pagefiles: Vec<ObservedPagefile>,
    query_complete: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservedPagefile {
    #[serde(rename = "Name")]
    name: String,
}

/// Observe currently active pagefiles without creating, resizing or opening
/// them. Non-Windows hosts are unsupported; an empty successful list is valid.
pub fn collect() -> Result<PagefileObservation, InventoryError> {
    #[cfg(target_os = "windows")]
    {
        collect_with(&crate::NativeCommandRunner)
    }
    #[cfg(not(target_os = "windows"))]
    {
        Err(InventoryError::Unsupported(if cfg!(target_os = "macos") {
            Platform::MacOs
        } else if cfg!(target_os = "linux") {
            Platform::Linux
        } else {
            Platform::Other
        }))
    }
}

/// Use the fixed Windows query with an injectable runner for fixture tests.
/// A result is accepted only after a successful complete query and strict
/// bounded parsing. No pagefile path is passed back to a command or opened.
pub fn collect_with(runner: &impl CommandRunner) -> Result<PagefileObservation, InventoryError> {
    let output = runner.run(POWERSHELL, ARGS).map_err(|error| {
        InventoryError::Command(format!(
            "active pagefile query could not run ({:?})",
            error.kind()
        ))
    })?;
    if output.stdout.len() > MAX_OUTPUT || output.stderr.len() > MAX_OUTPUT {
        return Err(InventoryError::Invalid(
            "active pagefile output exceeds the size limit".into(),
        ));
    }
    if !output.success || !output.stderr.is_empty() {
        return Err(InventoryError::Command(
            "active pagefile query did not complete cleanly".into(),
        ));
    }
    let listing: Listing = serde_json::from_slice(&output.stdout).map_err(|error| {
        // Do not include serde's error text: it can contain private paths or
        // attacker-controlled field names. Position still assists diagnosis.
        InventoryError::Invalid(format!(
            "malformed or incorrectly typed active pagefile JSON at line {} column {}",
            error.line(),
            error.column()
        ))
    })?;
    if !listing.query_complete || listing.pagefiles.len() > MAX_PAGEFILES {
        return Err(InventoryError::Invalid(
            "active pagefile query is incomplete or exceeds the record limit".into(),
        ));
    }
    let mut paths = BTreeMap::new();
    for record in listing.pagefiles {
        if !valid_path(&record.name) {
            return Err(InventoryError::Invalid(
                "unsupported or ambiguous active pagefile path".into(),
            ));
        }
        // Preserve the observed path, but reject case variants of an already
        // reported name rather than silently dropping a duplicate record.
        if paths
            .insert(record.name.to_uppercase(), record.name)
            .is_some()
        {
            return Err(InventoryError::Invalid(
                "duplicate active pagefile path".into(),
            ));
        }
    }
    Ok(PagefileObservation {
        source: "windows_cim_pagefile_usage".into(),
        pagefiles: paths.into_values().map(|path| Pagefile { path }).collect(),
    })
}

fn valid_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    // This slice accepts only local drive-absolute paths. Native-device paths,
    // UNC names, alternate streams and unresolved relative paths need separate
    // retained-volume handling and are not guessed here.
    if !(4..=MAX_PATH_BYTES).contains(&bytes.len())
        || !bytes[0].is_ascii_alphabetic()
        || bytes[1] != b':'
        || bytes[2] != b'\\'
    {
        return false;
    }
    let relative = &path[3..];
    if relative.contains(['/', ':', '<', '>', '"', '|', '?', '*'])
        || relative.chars().any(char::is_control)
    {
        return false;
    }
    relative.split('\\').all(|component| {
        if component.is_empty() || component.ends_with(['.', ' ']) {
            return false;
        }
        // DOS device aliases remain reserved even when followed by an
        // extension. Do not accept a reported alias as a regular-file path.
        let base = component
            .split('.')
            .next()
            .unwrap()
            .trim_end_matches(' ')
            .to_uppercase();
        !matches!(
            base.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        ) && !["COM", "LPT"].iter().any(|prefix| {
            base.strip_prefix(prefix).is_some_and(|suffix| {
                matches!(
                    suffix,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        })
    })
}
