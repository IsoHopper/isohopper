// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::guard::{self, Options};
use isohopper_inventory::{CommandOutput, CommandRunner, Platform, discover_for};
use serde::Serialize;
use std::{cell::RefCell, collections::VecDeque, io};

struct MockRunner {
    responses: RefCell<VecDeque<CommandOutput>>,
    calls: RefCell<Vec<Vec<String>>>,
}
impl MockRunner {
    fn new(outputs: Vec<CommandOutput>) -> Self {
        Self {
            responses: RefCell::new(outputs.into()),
            calls: RefCell::new(Vec::new()),
        }
    }
}
impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        assert_eq!(program, "/usr/sbin/diskutil");
        self.calls
            .borrow_mut()
            .push(args.iter().map(|v| (*v).to_owned()).collect());
        Ok(self
            .responses
            .borrow_mut()
            .pop_front()
            .expect("unexpected command"))
    }
}
fn plist(value: impl Serialize) -> CommandOutput {
    let mut stdout = Vec::new();
    plist::to_writer_xml(&mut stdout, &value).unwrap();
    CommandOutput {
        success: true,
        stdout,
        stderr: vec![],
    }
}
fn listing() -> CommandOutput {
    plist(
        serde_json::json!({"WholeDisks":["disk0","disk4"],"AllDisksAndPartitions":[
            {"DeviceIdentifier":"disk0","Size":1000000000000u64,"Content":"GUID_partition_scheme","Partitions":[{"DeviceIdentifier":"disk0s2","Content":"Apple_APFS"}]},
            {"DeviceIdentifier":"disk4","Size":64000000000u64,"Content":"GUID_partition_scheme","Partitions":[{"DeviceIdentifier":"disk4s1","Content":"Microsoft Basic Data"}]}
        ]}),
    )
}
fn system() -> CommandOutput {
    plist(
        serde_json::json!({"MountPoint":"/","ParentWholeDisk":"disk3","APFSPhysicalStores":[{"APFSPhysicalStore":"disk0s2"}],"FileVault":true}),
    )
}
fn info(id: &str, internal: bool, size: u64) -> CommandOutput {
    plist(
        serde_json::json!({"DeviceIdentifier":id,"DeviceNode":format!("/dev/{id}"),"WholeDisk":true,"VirtualOrPhysical":"Physical","Internal":internal,"MediaName":"Test Flash Disk","BusProtocol":if internal {"PCI-Express"} else {"USB"},"DeviceBlockSize":512,"TotalSize":size,"AESHardware":true}),
    )
}

#[test]
fn real_source_records_stay_blocked_without_missing_evidence() {
    let runner = MockRunner::new(vec![
        listing(),
        system(),
        info("disk0", true, 1000000000000),
        info("disk4", false, 64000000000),
    ]);
    let inventory = discover_for(Platform::MacOs, &runner).unwrap();
    assert_eq!(inventory.source, "macos_diskutil");
    assert_eq!(inventory.disks.len(), 2);
    let internal = &inventory.disks[0];
    assert_eq!(internal.system_disk, Some(true));
    assert!(internal.container_member);
    assert!(internal.mounted_system);
    assert!(internal.encryption_in_use);
    let usb = &inventory.disks[1];
    assert_eq!(usb.id, "/dev/disk4");
    assert_eq!(usb.bus, "usb");
    assert!(usb.external);
    assert_eq!(usb.size_bytes, 64000000000);
    assert_eq!(usb.logical_sector_size, 512);
    assert_eq!(usb.physical_sector_size, 0);
    assert!(usb.serial.is_empty());
    assert_eq!(usb.system_disk, Some(false));
    assert!(
        !usb.encryption_in_use,
        "AES support must not be treated as active encryption"
    );
    for disk in &inventory.disks {
        assert!(!disk.safety_checks_complete);
        assert!(!guard::evaluate(disk, &Options::default()).allowed);
    }
    assert!(
        inventory
            .warnings
            .iter()
            .any(|w| w.code == "physical_sector_unknown")
    );
    assert!(
        inventory
            .warnings
            .iter()
            .any(|w| w.code == "identity_missing")
    );
    assert_eq!(
        runner.calls.borrow().as_slice(),
        &[
            vec!["list", "-plist", "physical"],
            vec!["info", "-plist", "/"],
            vec!["info", "-plist", "disk0"],
            vec!["info", "-plist", "disk4"]
        ]
    );
    let json = serde_json::to_value(inventory).unwrap();
    assert!(json["disks"][1].get("safety_checks_complete").is_some());
}

#[test]
fn unsafe_or_inconsistent_identifiers_never_become_command_arguments() {
    for id in [
        "disk4;touch /tmp/anything",
        "/dev/disk4",
        "--help",
        "disk4s1",
        "disk4\n",
        "disk999999999999999999999",
        "",
    ] {
        let runner = MockRunner::new(vec![plist(
            serde_json::json!({"WholeDisks":[id],"AllDisksAndPartitions":[{"DeviceIdentifier":id,"Size":64000000000u64}]}),
        )]);
        assert!(discover_for(Platform::MacOs, &runner).is_err(), "{id:?}");
        assert_eq!(runner.calls.borrow().len(), 1);
    }
    for value in [
        serde_json::json!({"WholeDisks":["disk1"],"AllDisksAndPartitions":[{"DeviceIdentifier":"disk2","Size":1}]}),
        serde_json::json!({"WholeDisks":["disk1","disk1"],"AllDisksAndPartitions":[{"DeviceIdentifier":"disk1","Size":1}]}),
        serde_json::json!({"WholeDisks":["disk1"],"AllDisksAndPartitions":[{"DeviceIdentifier":"disk1","Size":1,"Partitions":[{"DeviceIdentifier":"disk2s1"}]}]}),
    ] {
        let runner = MockRunner::new(vec![plist(value)]);
        assert!(discover_for(Platform::MacOs, &runner).is_err());
        assert_eq!(runner.calls.borrow().len(), 1);
    }
}

#[test]
fn failed_info_keeps_visible_blocked_record_and_warning() {
    let failed = CommandOutput {
        success: false,
        stdout: vec![],
        stderr: b"sensitive diagnostic must stay private".to_vec(),
    };
    let runner = MockRunner::new(vec![
        listing(),
        failed.clone(),
        failed,
        info("disk4", false, 64000000000),
    ]);
    let inventory = discover_for(Platform::MacOs, &runner).unwrap();
    assert_eq!(inventory.disks.len(), 2);
    assert!(
        inventory
            .disks
            .iter()
            .all(|d| d.system_disk.is_none() && !d.safety_checks_complete)
    );
    assert!(
        inventory
            .warnings
            .iter()
            .any(|w| w.code == "system_unknown")
    );
    assert!(
        inventory
            .warnings
            .iter()
            .any(|w| w.code == "info_unavailable")
    );
    assert!(
        !serde_json::to_string(&inventory)
            .unwrap()
            .contains("sensitive diagnostic")
    );
}

#[test]
fn wrong_device_or_geometry_is_not_accepted_as_scanned_disk() {
    for altered in [
        info("disk8", false, 64000000000),
        info("disk4", false, 65000000000),
        plist(
            serde_json::json!({"DeviceIdentifier":"disk4","DeviceNode":"/tmp/untrusted","WholeDisk":true,"VirtualOrPhysical":"Physical"}),
        ),
    ] {
        let runner = MockRunner::new(vec![
            listing(),
            system(),
            info("disk0", true, 1000000000000),
            altered,
        ]);
        let inventory = discover_for(Platform::MacOs, &runner).unwrap();
        let disk = &inventory.disks[1];
        assert!(disk.identity_ambiguous);
        assert!(!disk.safety_checks_complete);
        assert!(!guard::evaluate(disk, &Options::default()).allowed);
    }
}

#[test]
fn malformed_empty_and_excessive_output_fail_closed() {
    for output in [
        CommandOutput {
            success: true,
            stdout: b"not plist".to_vec(),
            stderr: vec![],
        },
        CommandOutput {
            success: true,
            stdout: vec![b'x'; 2 * 1024 * 1024 + 1],
            stderr: vec![],
        },
        plist(serde_json::json!({})),
        plist(serde_json::json!({"WholeDisks":"disk0","AllDisksAndPartitions":[]})),
        plist(
            serde_json::json!({"WholeDisks":["disk0"],"AllDisksAndPartitions":[{"DeviceIdentifier":"disk0","Size":-1}]}),
        ),
    ] {
        let runner = MockRunner::new(vec![output]);
        assert!(discover_for(Platform::MacOs, &runner).is_err());
    }
}

#[test]
fn unsupported_platforms_execute_nothing() {
    for platform in [Platform::Windows, Platform::Other] {
        let runner = MockRunner::new(vec![]);
        assert!(discover_for(platform, &runner).is_err());
        assert!(runner.calls.borrow().is_empty());
    }
}

#[test]
fn duplicate_keys_and_incorrect_safety_types_are_rejected() {
    let xml = b"<?xml version=\"1.0\"?><plist version=\"1.0\"><dict><key>WholeDisks</key><array/><key>WholeDisks</key><array/><key>AllDisksAndPartitions</key><array/></dict></plist>";
    let runner = MockRunner::new(vec![CommandOutput {
        success: true,
        stdout: xml.to_vec(),
        stderr: vec![],
    }]);
    assert!(discover_for(Platform::MacOs, &runner).is_err());
    assert_eq!(runner.calls.borrow().len(), 1);

    let malformed = plist(
        serde_json::json!({"DeviceIdentifier":"disk4","DeviceNode":"/dev/disk4","WholeDisk":true,"VirtualOrPhysical":"Physical","Internal":"false","TotalSize":64000000000u64}),
    );
    let runner = MockRunner::new(vec![
        listing(),
        system(),
        info("disk0", true, 1000000000000),
        malformed,
    ]);
    let inventory = discover_for(Platform::MacOs, &runner).unwrap();
    let usb = &inventory.disks[1];
    assert!(!usb.external);
    assert!(usb.identity_ambiguous);
    assert!(
        inventory
            .warnings
            .iter()
            .any(|w| w.code == "info_unavailable")
    );
}

#[test]
fn unresolved_system_topology_cannot_exclude_any_disk_from_system_membership() {
    for root in [
        serde_json::json!({"MountPoint":"/","APFSPhysicalStores":[]}),
        serde_json::json!({"MountPoint":"/","APFSPhysicalStores":[{"APFSPhysicalStore":"disk88s1"}]}),
        serde_json::json!({"MountPoint":"/","APFSPhysicalStores":[{"APFSPhysicalStore":"disk0s2;echo"}]}),
        serde_json::json!({"MountPoint":"/other","ParentWholeDisk":"disk0"}),
    ] {
        let runner = MockRunner::new(vec![
            listing(),
            plist(root),
            info("disk0", true, 1000000000000),
            info("disk4", false, 64000000000),
        ]);
        let inventory = discover_for(Platform::MacOs, &runner).unwrap();
        assert!(inventory.disks.iter().all(|d| d.system_disk.is_none()));
        assert!(
            inventory
                .warnings
                .iter()
                .any(|w| w.code == "system_unknown")
        );
    }
}

#[test]
fn unknown_physical_kind_retains_observed_metadata_but_stays_blocked() {
    let unknown = plist(
        serde_json::json!({"DeviceIdentifier":"disk4","DeviceNode":"/dev/disk4","WholeDisk":true,"VirtualOrPhysical":"Unknown","Internal":false,"BusProtocol":"USB","MediaName":"Test Flash Disk","DeviceBlockSize":512,"TotalSize":64000000000u64}),
    );
    let runner = MockRunner::new(vec![
        listing(),
        system(),
        info("disk0", true, 1000000000000),
        unknown,
    ]);
    let inventory = discover_for(Platform::MacOs, &runner).unwrap();
    let disk = &inventory.disks[1];
    assert_eq!(disk.bus, "usb");
    assert_eq!(disk.logical_sector_size, 512);
    assert!(disk.external);
    assert!(!disk.safety_checks_complete);
    assert!(!guard::evaluate(disk, &Options::default()).allowed);
    assert!(
        inventory
            .warnings
            .iter()
            .any(|w| w.code == "physical_kind_unknown")
    );
}
