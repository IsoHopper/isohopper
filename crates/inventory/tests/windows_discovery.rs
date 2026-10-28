// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::guard;
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
