// SPDX-License-Identifier: GPL-3.0-or-later
//! Optional display labels for candidate selection. Never device identity or
//! safety evidence: the helper revalidates the selected device independently.
use crate::{CommandRunner, InventoryError, MAX_OUTPUT};
use serde::Deserialize;
use std::collections::BTreeMap;

pub(crate) const ARGS: &[&str] = &[
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
$labels = @(Storage\Get-Partition -ErrorAction Stop | Microsoft.PowerShell.Utility\Select-Object -First 4097 | Microsoft.PowerShell.Core\ForEach-Object {
    $partition = $_
    $volumes = @($partition | Storage\Get-Volume -ErrorAction SilentlyContinue)
    foreach ($volume in $volumes) {
        if ($null -ne $volume.FileSystemLabel -and $volume.FileSystemLabel.Length -gt 0) {
            [pscustomobject]@{disk_number=[uint32]$partition.DiskNumber; label=[string]$volume.FileSystemLabel}
        }
    }
})
[pscustomobject]@{labels=$labels} | Microsoft.PowerShell.Utility\ConvertTo-Json -Depth 3 -Compress
"#;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Listing {
    labels: Vec<Label>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Label {
    disk_number: u32,
    label: String,
}

pub fn collect_with(
    runner: &impl CommandRunner,
) -> Result<BTreeMap<u32, Vec<String>>, InventoryError> {
    let output = runner
        .run(crate::windows::POWERSHELL, ARGS)
        .map_err(|_| InventoryError::Command("Windows volume labels unavailable".into()))?;
    if !output.success || !output.stderr.is_empty() || output.stdout.len() > MAX_OUTPUT {
        return Err(InventoryError::Command(
            "Windows volume labels unavailable".into(),
        ));
    }
    let listing: Listing = serde_json::from_slice(&output.stdout)
        .map_err(|_| InventoryError::Invalid("Windows volume label response".into()))?;
    if listing.labels.len() > 4096 {
        return Err(InventoryError::Invalid(
            "Too many Windows volume labels".into(),
        ));
    }
    let mut result: BTreeMap<u32, Vec<String>> = BTreeMap::new();
    for item in listing.labels {
        if item.label.is_empty()
            || item.label.len() > 512
            || item.label.chars().any(char::is_control)
        {
            return Err(InventoryError::Invalid(
                "Invalid Windows volume label".into(),
            ));
        }
        let labels = result.entry(item.disk_number).or_default();
        if !labels.contains(&item.label) {
            labels.push(item.label);
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixture(&'static str);
    impl CommandRunner for Fixture {
        fn run(&self, program: &str, args: &[&str]) -> std::io::Result<crate::CommandOutput> {
            assert_eq!(program, "powershell.exe");
            assert_eq!(args, ARGS);
            Ok(crate::CommandOutput {
                success: true,
                stdout: self.0.as_bytes().to_vec(),
                stderr: Vec::new(),
            })
        }
    }
    #[test]
    fn labels_remain_display_hints_associated_with_the_reported_disk_number() {
        let labels = collect_with(&Fixture(r#"{"labels":[{"disk_number":2,"label":"IsoHopper"},{"disk_number":1,"label":"System"},{"disk_number":2,"label":"Other"},{"disk_number":2,"label":"IsoHopper"}]}"#)).unwrap();
        assert_eq!(labels[&2], ["IsoHopper", "Other"]);
        assert_eq!(labels[&1], ["System"]);
        assert!(!labels.contains_key(&0));
        assert!(
            collect_with(&Fixture(r#"{"labels":[]}"#))
                .unwrap()
                .is_empty()
        );
    }
    #[test]
    fn malformed_labels_fail_without_a_selection_hint() {
        for value in [
            r#"{"labels":[{"disk_number":-1,"label":"IsoHopper"}]}"#,
            r#"{"labels":[{"disk_number":2,"label":"bad\nlabel"}]}"#,
            r#"{"labels":[{"disk_number":2,"label":""}]}"#,
            r#"{"labels":[],"unexpected":true}"#,
        ] {
            assert!(collect_with(&Fixture(value)).is_err());
        }
    }

    fn projected_script() -> String {
        const FIXTURE: &str = r#"
function Get-TestPartition {
    [CmdletBinding()] param()
    [pscustomobject]@{DiskNumber=2}
    [pscustomobject]@{DiskNumber=3}
}
function Get-TestVolume {
    [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject)
    process {
        if ($InputObject.DiskNumber -eq 2) { [pscustomobject]@{FileSystemLabel='IsoHopper'} }
        else { [pscustomobject]@{FileSystemLabel='$(literal);data'} }
    }
}
"#;
        assert_eq!(SCRIPT.matches("Storage\\Get-Partition").count(), 1);
        assert_eq!(SCRIPT.matches("Storage\\Get-Volume").count(), 1);
        let script = SCRIPT
            .replace("Storage\\Get-Partition", "Get-TestPartition")
            .replace("Storage\\Get-Volume", "Get-TestVolume")
            .replacen("$labels = @(", &format!("{FIXTURE}\n$labels = @("), 1);
        assert!(!script.contains("Storage\\Get-"));
        script
    }

    #[test]
    fn controlled_label_projection_cannot_query_real_disks() {
        assert!(!projected_script().contains("Storage\\Get-"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_projects_volume_labels_from_controlled_records() {
        struct ProjectionRunner;
        impl CommandRunner for ProjectionRunner {
            fn run(&self, program: &str, args: &[&str]) -> std::io::Result<crate::CommandOutput> {
                assert_eq!(program, crate::windows::POWERSHELL);
                assert_eq!(args, ARGS);
                crate::native::test_powershell_script(&projected_script())
            }
        }
        let labels = collect_with(&ProjectionRunner).unwrap();
        assert_eq!(labels[&2], ["IsoHopper"]);
        assert_eq!(labels[&3], ["$(literal);data"]);
    }
}
