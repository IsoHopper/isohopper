// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::guard::Disk;
use isohopper_inventory::{Inventory, Warning};

#[test]
fn human_inventory_preserves_identity_sizes_and_all_safety_flags() {
    let report = Inventory {
        source: "macos_diskutil".into(),
        disks: vec![Disk {
            id: "/dev/disk123456".into(),
            serial: "SERIAL-full-123456789".into(),
            model: "External test disk".into(),
            bus: "USB".into(),
            size_bytes: 64_000_000_000,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            external: true,
            safety_checks_complete: false,
            system_disk: None,
            mounted_system: true,
            encryption_in_use: true,
            container_member: true,
            identity_ambiguous: true,
            nvme: true,
            has_data: true,
            os_like: true,
            freshly_plugged: true,
            previously_selected: true,
        }],
        warnings: vec![Warning {
            disk_id: Some("/dev/disk123456".into()),
            code: "safety_incomplete".into(),
            message: "Safety status remains unknown".into(),
        }],
    };
    let output = isohopper_cli::format_inventory(&report);
    for expected in [
        "macos_diskutil",
        "/dev/disk123456",
        "SERIAL-full-123456789",
        "External test disk",
        "USB",
        "64000000000 bytes",
        "logical_sector_size=512",
        "physical_sector_size=4096",
        "external=true",
        "safety_checks_complete=false",
        "system_disk=unknown",
        "mounted_system=true",
        "encryption_in_use=true",
        "container_member=true",
        "identity_ambiguous=true",
        "nvme=true",
        "has_data=true",
        "os_like=true",
        "freshly_plugged=true",
        "previously_selected=true",
        "blocked",
        "safety_incomplete",
        "Safety status remains unknown",
    ] {
        assert!(output.contains(expected), "missing {expected}: {output}");
    }
}

#[test]
fn human_inventory_escapes_device_and_warning_text_and_labels_unknowns() {
    let report = Inventory {
        source: "macos_diskutil".into(),
        disks: vec![Disk {
            id: "disk123".into(),
            model: "test\n\x1b[31mtext".into(),
            ..Disk::default()
        }],
        warnings: vec![Warning {
            disk_id: None,
            code: "test\rwarning".into(),
            message: "untrusted\n\x1b[2Jmessage".into(),
        }],
    };
    let output = isohopper_cli::format_inventory(&report);
    assert!(output.contains("serial=<unknown>"));
    assert!(output.contains("physical_sector_size=unknown"));
    assert!(output.contains("logical_sector_size=unknown"));
    assert!(output.contains("\\n"));
    assert!(!output.contains('\x1b'));
    assert!(!output.contains('\r'));
    assert!(!output.contains("test\n"));
    assert!(!output.contains("untrusted\n"));
}

#[test]
fn empty_inventory_keeps_source_and_global_warning() {
    let output = isohopper_cli::format_inventory(&Inventory {
        source: "macos_diskutil".into(),
        disks: vec![],
        warnings: vec![Warning {
            disk_id: None,
            code: "empty".into(),
            message: "No disks reported".into(),
        }],
    });
    assert!(output.contains("0 device(s)"));
    assert!(output.contains("macos_diskutil"));
    assert!(output.contains("No disks reported"));
}
