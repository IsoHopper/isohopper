// SPDX-License-Identifier: GPL-3.0-or-later
#![cfg(target_os = "macos")]

/// Opt-in only: observes host disk metadata without opening device contents.
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
