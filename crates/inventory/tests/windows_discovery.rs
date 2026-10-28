// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::guard;
use isohopper_inventory::windows::{WindowsEvidenceIssue, WindowsTextField, collect_evidence_with};
use isohopper_inventory::{CommandOutput, CommandRunner, Inventory, Platform, discover_for};
use serde_json::{Value, json};
use std::{cell::RefCell, io};

struct MockRunner(RefCell<Option<CommandOutput>>);
impl MockRunner {
    fn bytes(stdout: Vec<u8>) -> Self {
        Self(RefCell::new(Some(CommandOutput {
            success: true,
            stdout,
            stderr: vec![],
        })))
    }
    fn json(value: Value) -> Self {
        Self::bytes(serde_json::to_vec(&value).unwrap())
    }
}
impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        assert_eq!(program, "powershell.exe");
        assert_eq!(
            &args[..4],
            &["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
        );
        assert_eq!(args.len(), 5);
        Ok(self
            .0
            .borrow_mut()
            .take()
            .expect("only one read-only command"))
    }
}
fn disk(number: u32) -> Value {
    json!({"Number":number,"UniqueId":format!("TEST-UID-{number}"),"SerialNumber":format!("TEST-SERIAL-{number}"),
        "FriendlyName":"Test disk","Size":64_000_000_000u64,"LogicalSectorSize":512,"PhysicalSectorSize":4096,
        "BusType":7,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false,"IsClustered":false,"NumberOfPartitions":1})
}
fn partition(number: u32) -> Value {
    json!({"DiskNumber":number,"PartitionNumber":1,"IsBoot":false,"IsSystem":false,"IsReadOnly":false,"IsOffline":false,
        "GptType":"{ebd0a0a2-b9e5-4433-87c0-68b6b72699c7}","MbrType":0})
}
fn input(disks: Vec<Value>, partitions: Vec<Value>) -> Value {
    json!({"disks":disks,"partitions":partitions,"partitions_complete":true})
}
fn report(value: Value) -> Inventory {
    let result = discover_for(Platform::Windows, &MockRunner::json(value)).unwrap();
    assert_eq!(result.source, "windows_powershell");
    for disk in &result.disks {
        assert!(!disk.safety_checks_complete);
        assert!(!guard::evaluate(disk, &Default::default()).allowed);
    }
    result
}
fn warned(report: &Inventory, id: Option<&str>, code: &str) -> bool {
    report
        .warnings
        .iter()
        .any(|w| w.disk_id.as_deref() == id && w.code == code)
}

#[test]
fn windows_maps_identity_geometry_and_positive_system_evidence_without_authorizing() {
    let mut system = disk(0);
    system["BusType"] = json!(17);
    system["IsBoot"] = json!(true);
    let r = report(input(
        vec![system, disk(3)],
        vec![partition(0), partition(3)],
    ));
    let os = &r.disks[0];
    assert_eq!(os.id, r"\\.\PhysicalDrive0");
    assert_eq!(os.system_disk, Some(true));
    assert!(os.mounted_system && os.nvme);
    assert!(!os.external);
    let usb = &r.disks[1];
    assert_eq!(usb.serial, "TEST-SERIAL-3");
    assert_eq!(usb.model, "Test disk");
    assert_eq!(usb.size_bytes, 64_000_000_000);
    assert_eq!(usb.logical_sector_size, 512);
    assert_eq!(usb.physical_sector_size, 4096);
    assert_eq!(usb.bus, "usb");
    assert!(usb.external && usb.has_data);
    assert_eq!(usb.system_disk, None);
    assert!(warned(&r, Some(&usb.id), "system_unknown"));
    assert!(warned(&r, Some(&usb.id), "safety_incomplete"));
}

#[test]
fn partition_system_boot_readonly_and_offline_flags_propagate() {
    for field in ["IsBoot", "IsSystem"] {
        let mut p = partition(2);
        p[field] = json!(true);
        p["IsReadOnly"] = json!(true);
        p["IsOffline"] = json!(true);
        let r = report(input(vec![disk(2)], vec![p]));
        let d = &r.disks[0];
        assert_eq!(d.system_disk, Some(true));
        assert!(d.mounted_system && d.os_like);
        assert!(warned(&r, Some(&d.id), "read_only"));
        assert!(warned(&r, Some(&d.id), "offline"));
    }
}

#[test]
fn missing_metadata_and_failed_partition_query_stay_visible_and_unknown() {
    let mut d = disk(1);
    for key in [
        "SerialNumber",
        "UniqueId",
        "Size",
        "LogicalSectorSize",
        "PhysicalSectorSize",
        "IsReadOnly",
        "IsBoot",
        "IsSystem",
    ] {
        d.as_object_mut().unwrap().remove(key);
    }
    let mut value = input(vec![d], vec![]);
    value["partitions_complete"] = json!(false);
    let r = report(value);
    let d = &r.disks[0];
    assert!(d.serial.is_empty() && d.identity_ambiguous);
    assert_eq!(d.size_bytes, 0);
    assert_eq!(d.system_disk, None);
    for code in [
        "identity_missing",
        "identity_ambiguous",
        "geometry_unknown",
        "write_protection_unknown",
        "topology_unknown",
        "safety_incomplete",
    ] {
        assert!(warned(&r, Some(&d.id), code), "missing {code}");
    }
}

#[test]
fn bus_types_do_not_turn_embedded_or_virtual_storage_into_external_media() {
    for (bus, want, external, container) in [
        (7, "usb", true, false),
        (12, "sd", true, false),
        (13, "mmc", false, false),
        (17, "nvme", false, false),
        (11, "sata", false, false),
        (8, "raid", false, true),
        (16, "spaces", false, true),
        (14, "virtual", false, true),
        (15, "file_backed_virtual", false, true),
        (65535, "unknown", false, false),
    ] {
        let mut d = disk(1);
        d["BusType"] = json!(bus);
        let r = report(input(vec![d], vec![partition(1)]));
        let d = &r.disks[0];
        assert_eq!(d.bus, want);
        assert_eq!(d.external, external);
        assert_eq!(d.container_member, container);
    }
}

#[test]
fn clustered_disks_and_dynamic_partition_types_are_containers() {
    for gpt in [
        "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3",
        "{AF9B60A0-1431-4F62-BC68-3311714A69AD}",
    ] {
        let mut p = partition(2);
        p["GptType"] = json!(gpt);
        let r = report(input(vec![disk(2)], vec![p]));
        assert!(r.disks[0].container_member);
    }
    let mut p = partition(2);
    p["MbrType"] = json!(0x42);
    let r = report(input(vec![disk(2)], vec![p]));
    assert!(r.disks[0].container_member);
    let mut d = disk(2);
    d["IsClustered"] = json!(true);
    let r = report(input(vec![d], vec![partition(2)]));
    assert!(r.disks[0].container_member);
}

#[test]
fn duplicate_serials_or_unique_ids_mark_all_affected_disks_ambiguous() {
    for key in ["UniqueId", "SerialNumber"] {
        let first = disk(1);
        let mut second = disk(2);
        second[key] = first[key].clone();
        let r = report(input(vec![first, second], vec![partition(1), partition(2)]));
        assert!(r.disks.iter().all(|d| d.identity_ambiguous));
    }
}

#[test]
fn duplicate_numbers_invalid_associations_and_wrong_types_are_rejected() {
    let valid = input(vec![disk(1)], vec![partition(1)]);
    let mut cases = vec![
        input(vec![disk(1), disk(1)], vec![]),
        input(vec![disk(1)], vec![partition(1), partition(1)]),
    ];
    for (field, value) in [
        ("Number", Value::Null),
        ("Number", json!(-1)),
        ("Size", json!("64000")),
        ("IsBoot", json!("false")),
        ("BusType", json!("USB")),
    ] {
        let mut v = valid.clone();
        v["disks"][0][field] = value;
        cases.push(v);
    }
    let mut no_partition_number = valid.clone();
    no_partition_number["partitions"][0]
        .as_object_mut()
        .unwrap()
        .remove("DiskNumber");
    cases.push(no_partition_number);
    let mut unknown = valid;
    unknown["unexpected"] = json!(true);
    cases.push(unknown);
    for value in cases {
        assert!(discover_for(Platform::Windows, &MockRunner::json(value)).is_err());
    }
}

#[test]
fn orphan_partitions_and_mismatched_counts_report_incomplete_topology() {
    for parts in [vec![], vec![partition(2)]] {
        let r = report(input(vec![disk(1)], parts));
        assert!(warned(&r, Some(&r.disks[0].id), "topology_unknown"));
    }
    let r = report(input(vec![disk(1)], vec![partition(1), partition(2)]));
    assert!(warned(&r, None, "orphan_partition"));
}

#[test]
fn untrusted_strings_never_become_commands_or_control_sequences() {
    let mut d = disk(1);
    d["SerialNumber"] = json!("serial\u{1b}[2J");
    d["FriendlyName"] = json!("model\nnext");
    d["UniqueId"] = json!("$(malicious); arbitrary identifier");
    let r = report(input(vec![d], vec![partition(1)]));
    assert!(r.disks[0].serial.is_empty());
    assert!(r.disks[0].model.is_empty());
    assert_eq!(r.disks[0].id, r"\\.\PhysicalDrive1");
}

#[test]
fn output_and_record_counts_are_bounded() {
    for bytes in [
        b"not json".to_vec(),
        b"{}".to_vec(),
        b"{\"disks\":[],\"disks\":[],\"partitions\":[],\"partitions_complete\":true}".to_vec(),
        vec![b' '; 2 * 1024 * 1024 + 1],
    ] {
        assert!(discover_for(Platform::Windows, &MockRunner::bytes(bytes)).is_err());
    }
    assert!(
        discover_for(
            Platform::Windows,
            &MockRunner::json(input((0..257).map(disk).collect(), vec![]))
        )
        .is_err()
    );
    let parts = (0..4097)
        .map(|i| {
            let mut p = partition(1);
            p["PartitionNumber"] = json!(i + 1);
            p
        })
        .collect();
    assert!(
        discover_for(
            Platform::Windows,
            &MockRunner::json(input(vec![disk(1)], parts))
        )
        .is_err()
    );
}

#[test]
fn command_errors_are_redacted_and_empty_inventory_is_explicit() {
    let runner = MockRunner::bytes(b"private output".to_vec());
    runner.0.borrow_mut().as_mut().unwrap().success = false;
    let error = discover_for(Platform::Windows, &runner)
        .unwrap_err()
        .to_string();
    assert!(!error.contains("private output"));
    let runner = MockRunner::json(input(vec![disk(1)], vec![partition(1)]));
    runner.0.borrow_mut().as_mut().unwrap().stderr = b"private diagnostics".to_vec();
    let r = discover_for(Platform::Windows, &runner).unwrap();
    assert!(warned(&r, None, "command_diagnostics"));
    assert!(
        !serde_json::to_string(&r)
            .unwrap()
            .contains("private diagnostics")
    );
    let r = report(input(vec![], vec![]));
    assert!(warned(&r, None, "no_disks"));
}

#[test]
fn schema_errors_identify_known_paths_and_types_without_exposing_values() {
    for (field, value, expected) in [
        (
            "BusType",
            json!("private-bus-value"),
            "unsigned 16-bit integer",
        ),
        (
            "Size",
            json!({"private-key": "private-size"}),
            "unsigned 64-bit integer",
        ),
        ("IsBoot", json!("private-flag"), "boolean"),
        ("SerialNumber", json!(["private-serial"]), "string"),
    ] {
        let mut value_to_parse = input(vec![disk(1)], vec![partition(1)]);
        value_to_parse["disks"][0][field] = value;
        let error = discover_for(Platform::Windows, &MockRunner::json(value_to_parse))
            .unwrap_err()
            .to_string();
        assert!(error.contains(&format!("disks[].{field}")), "{error}");
        assert!(error.contains(expected), "{error}");
        assert!(!error.contains("private"), "{error}");
    }
    let mut value = input(vec![disk(1)], vec![partition(1)]);
    value["partitions"][0]["MbrType"] = json!("private-mbr");
    let error = discover_for(Platform::Windows, &MockRunner::json(value))
        .unwrap_err()
        .to_string();
    assert!(error.contains("partitions[].MbrType"), "{error}");
    assert!(error.contains("received string"), "{error}");
    assert!(!error.contains("private"), "{error}");
}

#[test]
fn malformed_missing_and_unknown_fields_keep_diagnostics_redacted() {
    for bytes in [
        b"private-invalid-json".to_vec(),
        b"{\"private-key\":\"private-value\"}".to_vec(),
        b"{\"disks\":[],\"partitions\":[],\"partitions_complete\":true,\"private-key\":0}".to_vec(),
        b"{\"disks\":[],\"disks\":[],\"partitions\":[],\"partitions_complete\":true}".to_vec(),
    ] {
        let error = discover_for(Platform::Windows, &MockRunner::bytes(bytes))
            .unwrap_err()
            .to_string();
        assert!(error.contains("line "), "{error}");
        assert!(error.contains("column "), "{error}");
        assert!(!error.contains("private"), "{error}");
    }
    let mut value = input(vec![disk(1)], vec![partition(1)]);
    value["disks"][0].as_object_mut().unwrap().remove("Number");
    let error = discover_for(Platform::Windows, &MockRunner::json(value))
        .unwrap_err()
        .to_string();
    assert!(error.contains("disks[].Number"), "{error}");
    assert!(error.contains("received missing field"), "{error}");
}

#[test]
fn command_projects_underlying_enum_numbers_and_null_remains_unknown() {
    struct ProjectionRunner;
    impl CommandRunner for ProjectionRunner {
        fn run(&self, _: &str, args: &[&str]) -> io::Result<CommandOutput> {
            for field in ["BusType", "MbrType", "UniqueIdFormat"] {
                let raw = format!("$_.CimInstanceProperties['{field}'].Value");
                assert!(args[4].contains(&format!("$null -ne {raw}")));
                assert!(args[4].contains(&format!("[uint16]{raw}")));
            }
            for field in ["Offset", "Size"] {
                let raw = format!("$_.CimInstanceProperties['{field}'].Value");
                assert!(args[4].contains(&format!("$null -ne {raw}")));
                assert!(args[4].contains(&format!("[uint64]{raw}")));
            }
            assert!(args[4].contains("Path=$_.CimInstanceProperties['Path'].Value"));
            let mut d = disk(1);
            d["BusType"] = Value::Null;
            let mut p = partition(1);
            p["MbrType"] = Value::Null;
            Ok(CommandOutput {
                success: true,
                stdout: serde_json::to_vec(&input(vec![d], vec![p])).unwrap(),
                stderr: vec![],
            })
        }
    }
    let result = discover_for(Platform::Windows, &ProjectionRunner).unwrap();
    assert_eq!(result.disks[0].bus, "unknown");
    assert!(!result.disks[0].safety_checks_complete);
    assert!(warned(
        &result,
        Some(&result.disks[0].id),
        "transport_unknown"
    ));
}

fn evidence_input() -> Value {
    let mut d = disk(5);
    d["Path"] = json!(r"\\?\scsi#disk&ven_test#5");
    d["UniqueIdFormat"] = json!(3);
    let mut p = partition(5);
    p["Offset"] = json!(1_048_576u64);
    p["Size"] = json!(32_000_000_000u64);
    input(vec![d], vec![p])
}

#[test]
fn evidence_preserves_raw_identity_false_flags_and_full_width_geometry() {
    let mut value = evidence_input();
    let path = r"\\?\scsi#disk&ven_test#$(not-a-command); literal";
    value["disks"][0]["Path"] = json!(path);
    value["disks"][0]["UniqueId"] = json!("  MixedCase-ID  ");
    value["partitions"][0]["Offset"] = json!(u64::MAX - 1);
    value["partitions"][0]["Size"] = json!(u64::MAX);
    let e = collect_evidence_with(&MockRunner::json(value.clone())).unwrap();
    assert_eq!(e.source, "windows_powershell");
    assert_eq!(e.disks[0].path.as_deref(), Some(path));
    assert_eq!(e.disks[0].unique_id.as_deref(), Some("  MixedCase-ID  "));
    assert_eq!(e.disks[0].unique_id_format, Some(3));
    assert_eq!(e.disks[0].is_boot, Some(false));
    assert_eq!(e.partitions[0].is_system, Some(false));
    assert_eq!(e.partitions[0].offset, Some(u64::MAX - 1));
    assert_eq!(e.partitions[0].size, Some(u64::MAX));
    // Presence is deliberately separate from geometry validity or authority.
    assert!(e.completeness.geometry_fields_present);
    assert!(e.completeness.identity_fields_present);
    assert!(e.completeness.status_fields_present);
    assert!(e.completeness.partition_membership_consistent);
    assert!(e.completeness.identity_values_unique);
    assert!(e.completeness.command_clean);
    assert!(e.issues.is_empty());
    let r = report(value);
    assert_eq!(r.disks[0].system_disk, None);
}

#[test]
fn old_fixtures_and_nulls_do_not_invent_new_evidence() {
    for mut value in [input(vec![disk(5)], vec![partition(5)]), evidence_input()] {
        if value["disks"][0].get("Path").is_some() {
            for key in ["Path", "UniqueIdFormat"] {
                value["disks"][0][key] = Value::Null;
            }
            for key in ["Offset", "Size", "IsBoot"] {
                value["partitions"][0][key] = Value::Null;
            }
        }
        let e = collect_evidence_with(&MockRunner::json(value)).unwrap();
        assert_eq!(e.disks[0].path, None);
        assert_eq!(e.disks[0].unique_id_format, None);
        assert_eq!(e.partitions[0].offset, None);
        assert_eq!(e.partitions[0].size, None);
        assert!(!e.completeness.identity_fields_present);
        assert!(!e.completeness.geometry_fields_present);
    }
}

#[test]
fn evidence_retains_orphans_and_every_duplicate_identity_member() {
    let mut value = evidence_input();
    let mut duplicate = value["disks"][0].clone();
    duplicate["Number"] = json!(6);
    duplicate["Path"] = json!(duplicate["Path"].as_str().unwrap().to_ascii_uppercase());
    value["disks"].as_array_mut().unwrap().push(duplicate);
    value["partitions"]
        .as_array_mut()
        .unwrap()
        .push(partition(99));
    let e = collect_evidence_with(&MockRunner::json(value)).unwrap();
    assert_eq!(e.partitions.len(), 2);
    assert!(!e.completeness.partition_membership_consistent);
    assert!(!e.completeness.identity_values_unique);
    assert!(e.issues.contains(&WindowsEvidenceIssue::OrphanPartition {
        disk_number: 99,
        partition_number: 1,
    }));
    for number in [5, 6] {
        for field in [
            WindowsTextField::Path,
            WindowsTextField::UniqueId,
            WindowsTextField::SerialNumber,
        ] {
            assert!(e.issues.contains(&WindowsEvidenceIssue::DuplicateIdentity {
                disk_number: number,
                field,
            }));
        }
    }
    assert!(
        e.issues
            .contains(&WindowsEvidenceIssue::PartitionCountMismatch {
                disk_number: 6,
                reported: Some(1),
                observed: 0,
            })
    );
}

#[test]
fn evidence_bounds_text_without_disguising_invalid_fields_as_observations() {
    let mut value = evidence_input();
    value["disks"][0]["Path"] = json!("x".repeat(4097));
    value["disks"][0]["SerialNumber"] = json!("private\u{0}serial");
    value["partitions"][0]["GptType"] = json!("x".repeat(1025));
    let e = collect_evidence_with(&MockRunner::json(value)).unwrap();
    assert_eq!(e.disks[0].path, None);
    assert_eq!(e.disks[0].serial_number, None);
    assert_eq!(e.partitions[0].gpt_type, None);
    assert!(!e.completeness.identity_fields_present);
    for (partition_number, field) in [
        (None, WindowsTextField::Path),
        (None, WindowsTextField::SerialNumber),
        (Some(1), WindowsTextField::GptType),
    ] {
        assert!(e.issues.contains(&WindowsEvidenceIssue::InvalidText {
            disk_number: 5,
            partition_number,
            field,
        }));
    }
}

#[test]
fn evidence_exposes_failed_enumeration_and_diagnostics_without_their_contents() {
    let mut value = evidence_input();
    value["partitions_complete"] = json!(false);
    let runner = MockRunner::json(value);
    runner.0.borrow_mut().as_mut().unwrap().stderr = b"private diagnostic".to_vec();
    let e = collect_evidence_with(&runner).unwrap();
    assert!(!e.completeness.partition_query_complete);
    assert!(!e.completeness.command_clean);
    assert!(!format!("{e:?}").contains("private diagnostic"));
}

#[test]
fn evidence_new_fields_remain_strictly_typed_and_errors_redacted() {
    for (group, field, bad) in [
        ("disks", "Path", json!(["private"])),
        ("disks", "UniqueIdFormat", json!("private")),
        ("disks", "UniqueIdFormat", json!(65536)),
        ("partitions", "Offset", json!(-1)),
        ("partitions", "Size", json!("private")),
    ] {
        let mut value = evidence_input();
        value[group][0][field] = bad;
        let error = collect_evidence_with(&MockRunner::json(value))
            .unwrap_err()
            .to_string();
        assert!(error.contains(&format!("{group}[].{field}")), "{error}");
        assert!(!error.contains("private"));
    }
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "read-only Windows Storage provider observation; no complete-safety claim"]
fn native_windows_typed_evidence_is_read_only() {
    use isohopper_inventory::windows::collect_evidence;
    use std::collections::BTreeSet;

    let evidence = collect_evidence().expect("Windows typed evidence query must complete");
    assert_eq!(evidence.source, "windows_powershell");
    assert!(evidence.disks.len() <= 256);
    assert!(evidence.partitions.len() <= 4096);
    let numbers: BTreeSet<_> = evidence.disks.iter().map(|d| d.number).collect();
    assert!(numbers.len() == evidence.disks.len(), "duplicate disk key");
    let partition_keys: BTreeSet<_> = evidence
        .partitions
        .iter()
        .map(|p| (p.disk_number, p.partition_number))
        .collect();
    assert!(
        partition_keys.len() == evidence.partitions.len(),
        "duplicate partition key"
    );
    for part in &evidence.partitions {
        assert!(part.partition_number > 0, "invalid partition key");
        let orphan = !numbers.contains(&part.disk_number);
        assert!(
            orphan
                == evidence
                    .issues
                    .contains(&WindowsEvidenceIssue::OrphanPartition {
                        disk_number: part.disk_number,
                        partition_number: part.partition_number,
                    }),
            "orphan partition evidence must remain explicit"
        );
    }
    for disk in &evidence.disks {
        let observed = evidence
            .partitions
            .iter()
            .filter(|p| p.disk_number == disk.number)
            .count() as u32;
        assert!(observed <= 256);
        let mismatch = disk.number_of_partitions != Some(observed);
        assert!(
            mismatch
                == evidence
                    .issues
                    .contains(&WindowsEvidenceIssue::PartitionCountMismatch {
                        disk_number: disk.number,
                        reported: disk.number_of_partitions,
                        observed,
                    }),
            "partition count evidence must remain explicit"
        );
    }
    if evidence.completeness.partition_membership_consistent {
        assert!(
            evidence
                .partitions
                .iter()
                .all(|p| numbers.contains(&p.disk_number))
        );
        assert!(evidence.disks.iter().all(|d| {
            d.number_of_partitions
                == Some(
                    evidence
                        .partitions
                        .iter()
                        .filter(|p| p.disk_number == d.number)
                        .count() as u32,
                )
        }));
    }
    if evidence.completeness.identity_fields_present {
        assert!(evidence.disks.iter().all(|d| {
            d.path.as_ref().is_some_and(|p| !p.trim().is_empty())
                && d.unique_id.as_ref().is_some_and(|id| !id.trim().is_empty())
                && d.serial_number
                    .as_ref()
                    .is_some_and(|id| !id.trim().is_empty())
                && d.unique_id_format.is_some()
        }));
    }
    if evidence.completeness.geometry_fields_present {
        assert!(evidence.disks.iter().all(|d| d.size.is_some()
            && d.logical_sector_size.is_some()
            && d.physical_sector_size.is_some()));
        assert!(
            evidence
                .partitions
                .iter()
                .all(|p| p.offset.is_some() && p.size.is_some())
        );
    }
    if evidence.completeness.status_fields_present {
        assert!(evidence.disks.iter().all(|d| d.is_boot.is_some()
            && d.is_system.is_some()
            && d.is_read_only.is_some()
            && d.is_offline.is_some()
            && d.is_clustered.is_some()));
        assert!(evidence.partitions.iter().all(|p| p.is_boot.is_some()
            && p.is_system.is_some()
            && p.is_read_only.is_some()
            && p.is_offline.is_some()));
    }
    let incomplete = [
        evidence.completeness.partition_query_complete,
        evidence.completeness.partition_membership_consistent,
        evidence.completeness.identity_fields_present,
        evidence.completeness.geometry_fields_present,
        evidence.completeness.status_fields_present,
        evidence.completeness.identity_values_unique,
        evidence.completeness.command_clean,
    ]
    .iter()
    .filter(|&&complete| !complete)
    .count();
    println!(
        "OBSERVED Windows typed evidence: disks={}, partitions={}, issues={}, incomplete_components={}; no target safety conclusion",
        evidence.disks.len(),
        evidence.partitions.len(),
        evidence.issues.len(),
        incomplete
    );
}
