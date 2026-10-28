// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::guard;
use isohopper_inventory::{CommandOutput, CommandRunner, Inventory, Platform, discover_for};
use serde_json::{Value, json};
use std::{cell::RefCell, io};

const COLUMNS: &str =
    "NAME,KNAME,PATH,TYPE,SIZE,LOG-SEC,PHY-SEC,RM,RO,TRAN,SERIAL,MODEL,MOUNTPOINTS,FSTYPE";
struct MockRunner {
    output: RefCell<Option<CommandOutput>>,
    calls: RefCell<usize>,
}
impl MockRunner {
    fn json(value: Value) -> Self {
        Self::bytes(serde_json::to_vec(&value).unwrap())
    }
    fn bytes(stdout: Vec<u8>) -> Self {
        Self {
            output: RefCell::new(Some(CommandOutput {
                success: true,
                stdout,
                stderr: vec![],
            })),
            calls: RefCell::new(0),
        }
    }
}
impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        assert_eq!(program, "/usr/bin/lsblk");
        assert_eq!(
            args,
            [
                "--json", "--bytes", "--paths", "--tree", "--output", COLUMNS
            ]
        );
        *self.calls.borrow_mut() += 1;
        Ok(self
            .output
            .borrow_mut()
            .take()
            .expect("only one fixed command is permitted"))
    }
}
fn node(name: &str, kind: &str) -> Value {
    json!({"name":format!("/dev/{name}"),"kname":format!("/dev/{name}"),"path":format!("/dev/{name}"),"type":kind,
        "size":64_000_000_000u64,"log-sec":512,"phy-sec":4096,"rm":false,"ro":false,"tran":"usb",
        "serial":format!("TEST-{name}"),"model":"Test disk","mountpoints":[null],"fstype":null})
}
fn discover(nodes: Vec<Value>) -> Inventory {
    let runner = MockRunner::json(json!({"blockdevices":nodes}));
    let result = discover_for(Platform::Linux, &runner).unwrap();
    assert_eq!(*runner.calls.borrow(), 1);
    result
}
fn has_warning(report: &Inventory, disk: &str, code: &str) -> bool {
    report
        .warnings
        .iter()
        .any(|w| w.disk_id.as_deref() == Some(disk) && w.code == code)
}
fn assert_blocked(report: &Inventory) {
    for disk in &report.disks {
        assert!(!disk.safety_checks_complete);
        assert!(!guard::evaluate(disk, &Default::default()).allowed);
    }
}

#[test]
fn linux_identity_geometry_and_system_descendants_remain_inspection_only() {
    let mut system = node("nvme0n1", "disk");
    system["tran"] = json!("nvme");
    let mut partition = node("nvme0n1p2", "part");
    partition["fstype"] = json!("crypto_LUKS");
    let mut crypt = node("mapper/root-crypt", "crypt");
    crypt["mountpoints"] = json!(["/", "/mnt/root-copy"]);
    partition["children"] = json!([crypt]);
    system["children"] = json!([partition]);
    let report = discover(vec![system, node("sdb", "disk")]);
    assert_eq!(report.source, "linux_lsblk");
    assert_eq!(report.disks.len(), 2);
    let system = &report.disks[0];
    assert_eq!(system.id, "/dev/nvme0n1");
    assert!(system.nvme && !system.external);
    assert_eq!(system.system_disk, Some(true));
    assert!(system.mounted_system && system.encryption_in_use && system.container_member);
    let usb = &report.disks[1];
    assert_eq!(usb.serial, "TEST-sdb");
    assert_eq!(usb.size_bytes, 64_000_000_000);
    assert_eq!(usb.logical_sector_size, 512);
    assert_eq!(usb.physical_sector_size, 4096);
    assert_eq!(usb.bus, "usb");
    assert!(usb.external && usb.has_data);
    assert_eq!(usb.system_disk, None);
    assert!(has_warning(&report, "/dev/sdb", "system_unknown"));
    assert_blocked(&report);
}

#[test]
fn shared_raid_root_is_propagated_to_each_physical_member() {
    let mut raid = node("md0", "raid1");
    raid["mountpoints"] = json!(["/"]);
    let mut first = node("sda", "disk");
    let mut second = node("sdb", "disk");
    first["children"] = json!([raid.clone()]);
    second["children"] = json!([raid]);
    let report = discover(vec![first, second]);
    assert!(
        report
            .disks
            .iter()
            .all(|disk| disk.system_disk == Some(true) && disk.container_member)
    );
    assert_blocked(&report);
}

#[test]
fn missing_identity_geometry_and_read_only_media_have_explicit_warnings() {
    let mut disk = node("sdb", "disk");
    for field in ["serial", "log-sec", "phy-sec", "size", "rm", "mountpoints"] {
        disk.as_object_mut().unwrap().remove(field);
    }
    disk["ro"] = json!(true);
    let report = discover(vec![disk]);
    let disk = &report.disks[0];
    assert!(disk.serial.is_empty());
    assert_eq!(disk.logical_sector_size, 0);
    assert_eq!(disk.physical_sector_size, 0);
    for code in [
        "identity_missing",
        "geometry_unknown",
        "read_only",
        "topology_unknown",
        "safety_incomplete",
    ] {
        assert!(has_warning(&report, "/dev/sdb", code), "missing {code}");
    }
    assert_blocked(&report);
}

#[test]
fn unobserved_root_and_boot_mount_do_not_assert_system_exclusion() {
    let mut disk = node("sdb", "disk");
    let mut boot = node("sdb1", "part");
    boot["mountpoints"] = json!(["/boot/efi"]);
    disk["children"] = json!([boot]);
    let report = discover(vec![disk]);
    assert_eq!(report.disks[0].system_disk, None);
    assert!(report.disks[0].mounted_system);
    assert_blocked(&report);
}

#[test]
fn repeated_physical_identity_and_duplicate_serials_are_ambiguous() {
    let mut first = node("sda", "disk");
    first["serial"] = json!("DUPLICATE");
    let mut second = node("sdb", "disk");
    second["serial"] = json!("DUPLICATE");
    let mut repeated = first.clone();
    repeated["mountpoints"] = json!(["/"]);
    let report = discover(vec![first, second, repeated]);
    assert_eq!(report.disks.len(), 2);
    assert!(report.disks.iter().all(|disk| disk.identity_ambiguous));
    assert_eq!(report.disks[0].system_disk, Some(true));
    assert!(has_warning(&report, "/dev/sda", "identity_ambiguous"));
    assert!(has_warning(&report, "/dev/sdb", "identity_ambiguous"));
    assert_blocked(&report);
}

#[test]
fn removable_mmc_is_sd_but_embedded_mmc_is_not_confirmed_external() {
    let mut removable = node("mmcblk0", "disk");
    removable["tran"] = json!("mmc");
    removable["rm"] = json!(true);
    let mut embedded = node("mmcblk1", "disk");
    embedded["tran"] = json!("mmc");
    let report = discover(vec![removable, embedded]);
    assert_eq!(report.disks[0].bus, "sd");
    assert!(report.disks[0].external);
    assert!(!report.disks[1].external);
    assert_blocked(&report);
}

#[test]
fn malformed_types_duplicate_fields_and_excessive_bytes_fail_closed() {
    for bytes in [
        b"not JSON".to_vec(),
        b"{}".to_vec(),
        b"{\"blockdevices\":[],\"blockdevices\":[]}".to_vec(),
        b"{\"blockdevices\":[{\"name\":\"/dev/sda\",\"type\":\"disk\",\"size\":-1}]}".to_vec(),
        b"{\"blockdevices\":[{\"name\":\"/dev/sda\",\"type\":\"disk\",\"ro\":\"false\"}]}".to_vec(),
        b"{\"blockdevices\":[{\"name\":\"/dev/sda\",\"type\":\"disk\",\"mountpoints\":\"/\"}]}"
            .to_vec(),
        vec![b' '; 2 * 1024 * 1024 + 1],
    ] {
        let runner = MockRunner::bytes(bytes);
        assert!(discover_for(Platform::Linux, &runner).is_err());
        assert_eq!(*runner.calls.borrow(), 1);
    }
}

#[test]
fn device_paths_cannot_inject_commands_or_escape_dev() {
    for name in [
        "/dev/sda;touch /tmp/untrusted",
        "--help",
        "/tmp/sda",
        "/dev/../etc/passwd",
        "/dev/sda\n",
        "/dev//sda",
    ] {
        let mut disk = node("sda", "disk");
        disk["path"] = json!(name);
        let runner = MockRunner::json(json!({"blockdevices":[disk]}));
        assert!(
            discover_for(Platform::Linux, &runner).is_err(),
            "accepted {name:?}"
        );
        assert_eq!(*runner.calls.borrow(), 1);
    }
}

#[test]
fn tree_depth_node_count_and_physical_disk_count_are_bounded() {
    let mut deep = node("sda1", "part");
    for index in 0..18 {
        let mut parent = node(&format!("dm-{index}"), "lvm");
        parent["children"] = json!([deep]);
        deep = parent;
    }
    for nodes in [
        vec![deep],
        (0..4097)
            .map(|i| node(&format!("loop{i}"), "loop"))
            .collect(),
        (0..257)
            .map(|i| node(&format!("disk{i}"), "disk"))
            .collect(),
    ] {
        let runner = MockRunner::json(json!({"blockdevices":nodes}));
        assert!(discover_for(Platform::Linux, &runner).is_err());
    }
}

#[test]
fn failed_command_diagnostics_are_not_exposed() {
    let runner = MockRunner::bytes(b"sensitive raw device metadata".to_vec());
    {
        let mut output = runner.output.borrow_mut();
        output.as_mut().unwrap().success = false;
        output.as_mut().unwrap().stderr = b"sensitive diagnostic".to_vec();
    }
    let error = discover_for(Platform::Linux, &runner)
        .unwrap_err()
        .to_string();
    assert!(!error.contains("sensitive"));
    assert_eq!(*runner.calls.borrow(), 1);
}

#[test]
fn unsafe_serial_and_missing_device_path_remain_visible_but_ambiguous() {
    let mut disk = node("sdb", "disk");
    disk.as_object_mut().unwrap().remove("path");
    disk["serial"] = json!("SERIAL\n\u{1b}[2J");
    let report = discover(vec![disk]);
    assert_eq!(report.disks[0].id, "/dev/sdb");
    assert!(report.disks[0].serial.is_empty());
    assert!(report.disks[0].identity_ambiguous);
    assert!(has_warning(&report, "/dev/sdb", "identity_missing"));
    assert!(has_warning(&report, "/dev/sdb", "identity_ambiguous"));
    assert_blocked(&report);
}

#[test]
fn successful_command_diagnostics_warn_without_leaking_raw_output() {
    let runner = MockRunner::json(json!({"blockdevices":[node("sdb", "disk")]}));
    runner.output.borrow_mut().as_mut().unwrap().stderr = b"private device diagnostic".to_vec();
    let report = discover_for(Platform::Linux, &runner).unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.code == "command_diagnostics")
    );
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("private device")
    );
    assert_blocked(&report);
}

#[test]
fn non_disk_devices_and_empty_lists_never_become_preparation_targets() {
    for nodes in [vec![], vec![node("loop0", "loop"), node("sr0", "rom")]] {
        let report = discover(nodes);
        assert!(report.disks.is_empty());
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.code == "no_physical_disks")
        );
    }
}
