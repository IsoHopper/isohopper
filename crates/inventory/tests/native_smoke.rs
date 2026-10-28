// SPDX-License-Identifier: GPL-3.0-or-later
/// Opt-in only: observes host disk metadata without opening device contents.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "requires a macOS user session with DiskManagement service access"]
fn native_macos_inventory_is_read_only_and_fail_closed() {
    let inventory = isohopper_inventory::discover().unwrap();
    assert_eq!(inventory.source, "macos_diskutil");
    for disk in &inventory.disks {
        assert!(!disk.safety_checks_complete);
        assert!(!isohopper_core::guard::evaluate(disk, &Default::default()).allowed);
    }
    println!(
        "source={}, disks={}, warnings={}, all_blocked=true",
        inventory.source,
        inventory.disks.len(),
        inventory.warnings.len()
    );
    println!(
        "warning_codes={:?}",
        inventory
            .warnings
            .iter()
            .map(|w| w.code.as_str())
            .collect::<Vec<_>>()
    );
}

/// Opt-in only: the provider runs fixed read-only lsblk arguments.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires a Linux user session with lsblk and sysfs access"]
fn native_linux_inventory_is_read_only_and_fail_closed() {
    let inventory = isohopper_inventory::discover().unwrap();
    assert_eq!(inventory.source, "linux_lsblk");
    for disk in &inventory.disks {
        assert!(!disk.safety_checks_complete);
        assert!(!isohopper_core::guard::evaluate(disk, &Default::default()).allowed);
    }
    println!(
        "devices={}, warnings={}, blocked={}",
        inventory.disks.len(),
        inventory.warnings.len(),
        inventory.disks.len()
    );
}

/// Opt-in only: the provider reads Windows storage metadata, never device bytes.
#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires Windows with the Storage PowerShell module"]
fn native_windows_inventory_is_read_only_and_fail_closed() {
    let inventory = isohopper_inventory::discover().unwrap();
    assert_eq!(inventory.source, "windows_powershell");
    for disk in &inventory.disks {
        assert!(!disk.safety_checks_complete);
        assert!(!isohopper_core::guard::evaluate(disk, &Default::default()).allowed);
    }
    println!(
        "devices={}, warnings={}, blocked={}",
        inventory.disks.len(),
        inventory.warnings.len(),
        inventory.disks.len()
    );
}
