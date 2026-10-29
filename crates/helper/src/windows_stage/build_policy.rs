// SPDX-License-Identifier: GPL-3.0-or-later
use super::StageError;
use crate::{windows_lock::TargetCoverage, writer::Geometry};
use isohopper_core::engine::{Identifiers, Plan};
use isohopper_media::copy::{CopyEntry, validate_manifest};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SelectedVolume {
    pub(super) guid: String,
    pub(super) disk_number: u32,
    pub(super) start: u64,
    pub(super) length: u64,
    pub(super) partition_guid: String,
    pub(super) allocation_unit: u32,
}

const BASIC_DATA: [u8; 16] = [
    0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
];
pub(super) fn allocation_unit(plan: &Plan) -> u32 {
    if plan.layout().size_bytes <= 32 << 30 {
        32 * 1024
    } else {
        128 * 1024
    }
}
pub(super) fn admit(
    plan: &Plan,
    geometry: &Geometry,
    entries: &[CopyEntry],
) -> Result<(), StageError> {
    super::policy::validate_geometry(geometry)?;
    if plan.layout().size_bytes != geometry.size_bytes
        || plan.layout().logical_sector_size != u64::from(geometry.logical_sector_size)
        || geometry.size_bytes > 64u64 << 40
        || entries.len() > 132
    {
        return Err(StageError::Invalid("stage plan or input count"));
    }
    let data = &plan.layout().partitions[0];
    let capacity = (data.end_lba - data.start_lba + 1) * 512;
    let available = capacity
        .checked_sub(1024 * 1024)
        .ok_or(StageError::Invalid(
            "data partition has no metadata reserve",
        ))?;
    let mut all_entries = super::theme::entries();
    all_entries.extend_from_slice(entries);
    validate_manifest(&all_entries, available, u64::from(allocation_unit(plan)))
        .map_err(|_| StageError::Invalid("stage manifest or data capacity"))?;
    Ok(())
}
fn guid(value: &[u8; 16]) -> String {
    format!(
        "{:08x}-{:04x}-{:04x}-{}-{}",
        u32::from_le_bytes(value[..4].try_into().unwrap()),
        u16::from_le_bytes(value[4..6].try_into().unwrap()),
        u16::from_le_bytes(value[6..8].try_into().unwrap()),
        hex::encode(&value[8..10]),
        hex::encode(&value[10..])
    )
}
pub(super) fn canonical_volume(value: &str) -> bool {
    let Some(g) = value
        .strip_prefix(r"\\?\Volume{")
        .and_then(|s| s.strip_suffix("}\\"))
    else {
        return false;
    };
    g.len() == 36
        && g.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
            }
        })
}
pub(super) fn select_data(
    plan: &Plan,
    ids: &Identifiers,
    coverage: &TargetCoverage,
) -> Result<SelectedVolume, StageError> {
    let bad = || StageError::Invalid("owned VHD engine topology differs");
    if coverage.partition_style != 1
        || coverage.layout_identity != ids.disk_guid
        || coverage.partitions.len() != 2
        || coverage.device.geometry.size_bytes != plan.layout().size_bytes
        || u64::from(coverage.device.geometry.logical_sector_size)
            != plan.layout().logical_sector_size
    {
        return Err(bad());
    }
    let mut names = std::collections::BTreeSet::new();
    for (i, expected) in plan.layout().partitions.iter().enumerate() {
        let part = &coverage.partitions[i];
        if part.partition_number != expected.number
            || part.start_offset != expected.start_lba * 512
            || part.length_bytes != (expected.end_lba - expected.start_lba + 1) * 512
            || part.partition_type != BASIC_DATA
            || part.partition_identity != ids.partition_guids[i]
            || !part.volume_required
        {
            return Err(bad());
        }
        let name = part.volume_guid.as_deref().ok_or_else(bad)?;
        if !canonical_volume(name) || !names.insert(name) {
            return Err(bad());
        }
    }
    let data = &coverage.partitions[0];
    Ok(SelectedVolume {
        guid: data.volume_guid.clone().ok_or_else(bad)?,
        disk_number: coverage.device.device_number,
        start: data.start_offset,
        length: data.length_bytes,
        partition_guid: guid(&ids.partition_guids[0]),
        allocation_unit: allocation_unit(plan),
    })
}
pub(super) fn format_completed(output: &[u8]) -> Result<(), StageError> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        return_code: u32,
    }
    if output.len() > 4096 {
        return Err(StageError::Invalid("format reply exceeds bound"));
    }
    let reply: Reply =
        serde_json::from_slice(output).map_err(|_| StageError::Invalid("invalid format reply"))?;
    if reply.return_code != 0 {
        return Err(StageError::FormatProvider(reply.return_code));
    }
    Ok(())
}
pub(super) fn format_outcome(
    exit_code: Option<i32>,
    overdue: bool,
    output: &[u8],
    errors: &[u8],
) -> Result<(), StageError> {
    if exit_code != Some(0) || overdue || !errors.is_empty() || output.len() > 4096 {
        // PowerShell/provider errors may contain host paths. Keep only our
        // fixed script's two bounded numeric fields; never echo arbitrary text.
        let fields = (|| {
            if errors.len() > 128 {
                return None;
            }
            let text = std::str::from_utf8(errors)
                .ok()?
                .trim_end_matches(['\r', '\n']);
            let (stage, hresult) = text
                .strip_prefix("owned VHD format failed: stage=")?
                .split_once("; hresult=")?;
            let stage = stage.parse::<u8>().ok().filter(|n| (1..=4).contains(n))?;
            let hresult = hresult.parse::<i32>().ok()?;
            Some((stage, hresult))
        })();
        return Err(StageError::FormatProcess {
            exit_code,
            overdue,
            stdout_bytes: output.len(),
            stderr_bytes: errors.len(),
            script_stage: fields.map(|v| v.0),
            hresult: fields.map(|v| v.1),
        });
    }
    format_completed(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{windows_lock::PartitionCoverage, writer::DeviceSnapshot};
    fn fixture() -> (Plan, Identifiers, TargetCoverage) {
        let plan = Plan::new(256 << 20, 512).unwrap();
        let ids = Identifiers {
            disk_guid: [1; 16],
            partition_guids: [[2; 16], [3; 16]],
            private_identity: [4; 16],
            mbr_signature: [5; 4],
        };
        let coverage = TargetCoverage {
            device: DeviceSnapshot {
                device_number: 7,
                serial: "fixture".into(),
                device_id: None,
                bus_type: 15,
                geometry: Geometry {
                    size_bytes: 256 << 20,
                    logical_sector_size: 512,
                    physical_sector_size: 4096,
                },
            },
            partition_style: 1,
            layout_identity: ids.disk_guid,
            partitions: plan
                .layout()
                .partitions
                .iter()
                .enumerate()
                .map(|(i, p)| PartitionCoverage {
                    partition_number: p.number,
                    start_offset: p.start_lba * 512,
                    length_bytes: (p.end_lba - p.start_lba + 1) * 512,
                    partition_type: BASIC_DATA,
                    partition_identity: ids.partition_guids[i],
                    volume_guid: Some(format!(
                        "\\\\?\\Volume{{00000000-0000-0000-0000-00000000000{i}}}\\"
                    )),
                    volume_required: true,
                })
                .collect(),
        };
        (plan, ids, coverage)
    }
    #[test]
    fn engine_volume_requires_exact_complete_plan_and_identity() {
        let (plan, ids, coverage) = fixture();
        assert_eq!(select_data(&plan, &ids, &coverage).unwrap().disk_number, 7);
        let mut bad = coverage.clone();
        bad.partitions.pop();
        assert!(select_data(&plan, &ids, &bad).is_err());
        let mut bad = coverage.clone();
        bad.partitions[0].start_offset += 512;
        assert!(select_data(&plan, &ids, &bad).is_err());
        let mut bad = coverage.clone();
        bad.partitions[0].partition_identity = [9; 16];
        assert!(select_data(&plan, &ids, &bad).is_err());
        let mut bad = coverage.clone();
        bad.partitions[0].volume_guid = bad.partitions[1].volume_guid.clone();
        assert!(select_data(&plan, &ids, &bad).is_err());
        let mut bad = coverage.clone();
        bad.layout_identity = [9; 16];
        assert!(select_data(&plan, &ids, &bad).is_err());
        let mut bad = coverage.clone();
        bad.device.geometry.size_bytes += 512;
        assert!(select_data(&plan, &ids, &bad).is_err());
    }
    #[test]
    fn build_admission_rejects_mismatch_and_bad_manifest_before_storage() {
        let (plan, _, coverage) = fixture();
        let geometry = coverage.device.geometry;
        let entry = CopyEntry {
            relative_path: "Windows/test.iso".into(),
            bytes: 1024,
            sha256: [1; 32],
        };
        admit(&plan, &geometry, std::slice::from_ref(&entry)).unwrap();
        assert!(admit(&plan, &geometry, &[entry.clone(), entry.clone()]).is_err());
        let mut bad = entry.clone();
        bad.relative_path = "../escape".into();
        assert!(admit(&plan, &geometry, &[bad]).is_err());
        let mut bad = geometry.clone();
        bad.size_bytes += 512;
        assert!(admit(&plan, &bad, std::slice::from_ref(&entry)).is_err());
        let mut bad = entry;
        bad.bytes = u64::MAX;
        assert!(admit(&plan, &geometry, &[bad]).is_err());
    }

    #[test]
    fn empty_media_still_requires_valid_stage_geometry() {
        let (plan, _, coverage) = fixture();
        let mut geometry = coverage.device.geometry;
        admit(&plan, &geometry, &[]).unwrap();
        geometry.size_bytes += 512;
        assert!(admit(&plan, &geometry, &[]).is_err());
    }
    #[test]
    fn application_theme_paths_are_reserved_before_storage_mutation() {
        let (plan, _, coverage) = fixture();
        for path in [
            "ventoy/ventoy.json",
            "VENTOY/VENTOY.JSON",
            "ventoy",
            "ventoy/isohopper/theme.txt",
            "ventoy/isohopper/theme.txt/child.iso",
        ] {
            let entry = CopyEntry {
                relative_path: path.into(),
                bytes: 1024,
                sha256: [1; 32],
            };
            assert!(
                admit(&plan, &coverage.device.geometry, &[entry]).is_err(),
                "{path}"
            );
        }
    }
    #[test]
    fn admission_includes_theme_allocation_in_capacity() {
        let (plan, _, coverage) = fixture();
        let data = &plan.layout().partitions[0];
        let available = (data.end_lba - data.start_lba + 1) * 512 - 1024 * 1024;
        let unit = u64::from(allocation_unit(&plan));
        let entry = CopyEntry {
            relative_path: "large.iso".into(),
            bytes: available / unit * unit,
            sha256: [1; 32],
        };
        // The user image alone fits; the complete filesystem contents do not.
        validate_manifest(std::slice::from_ref(&entry), available, unit).unwrap();
        assert!(admit(&plan, &coverage.device.geometry, &[entry]).is_err());
    }
    #[test]
    fn formatter_requires_bounded_exact_typed_success() {
        format_completed(br#"{"return_code":0}"#).unwrap();
        for value in [
            r#"{"return_code":1}"#,
            r#"{"return_code":"0"}"#,
            r#"{"return_code":0,"extra":true}"#,
            r#"{"return_code":0,"return_code":0}"#,
            r#"{}"#,
        ] {
            assert!(format_completed(value.as_bytes()).is_err());
        }
        assert!(format_completed(&vec![b' '; 4097]).is_err());
    }
    #[test]
    fn formatter_failure_reports_only_bounded_fixed_script_fields() {
        let error = format_outcome(
            Some(1),
            false,
            b"",
            b"owned VHD format failed: stage=3; hresult=-2146233087\r\n",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("exit=Some(1)"));
        assert!(error.contains("stage=Some(3)"));
        assert!(error.contains("hresult=Some(-2146233087)"));
        let error = format_outcome(Some(1), false, b"", b"private path C:\\sensitive\\name")
            .unwrap_err()
            .to_string();
        assert!(!error.contains("sensitive"));
        assert!(error.contains("stage=None"));
        assert!(format_outcome(Some(0), true, br#"{"return_code":0}"#, b"").is_err());
        assert!(format_outcome(Some(0), false, br#"{"return_code":0}"#, b"unexpected").is_err());
        assert!(format_outcome(Some(0), false, &vec![b' '; 4097], b"").is_err());
        assert!(
            format_outcome(Some(0), false, br#"{"return_code":4097}"#, b"")
                .unwrap_err()
                .to_string()
                .contains("4097")
        );
        format_outcome(Some(0), false, br#"{"return_code":0}"#, b"").unwrap();
    }
}
