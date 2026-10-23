// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_launcher::{Entry, Menu, Policy, Trust, can_boot, valid_path};

#[test]
fn trust_failures_remain_blocked_even_in_permissive_policy() {
    assert!(!can_boot(Policy::Enforce, Trust::Unknown));
    assert!(!can_boot(Policy::Enforce, Trust::Unsigned));
    assert!(!can_boot(Policy::Off, Trust::Revoked));
    assert!(!can_boot(Policy::Off, Trust::Tampered));
    assert!(can_boot(Policy::Enforce, Trust::Verified));
    assert!(can_boot(Policy::Off, Trust::Unsigned));
}
#[test]
fn selection_wraps_and_empty_menu_is_safe() {
    let mut empty = Menu::new(&[]);
    empty.next();
    empty.previous();
    assert!(empty.selected().is_none());
    let entries = [
        Entry {
            label: "Recovery",
            path: "EFI/recovery.efi",
            trust: Trust::Verified,
        },
        Entry {
            label: "Installer",
            path: "ISOs/setup.iso",
            trust: Trust::Unknown,
        },
    ];
    let mut menu = Menu::new(&entries);
    menu.previous();
    assert_eq!(menu.selected().unwrap().label, "Installer");
    menu.next();
    assert_eq!(menu.selected().unwrap().label, "Recovery");
}
#[test]
fn unsafe_paths_cannot_become_boot_targets() {
    for path in [
        "../boot.efi",
        "/boot.efi",
        "EFI/../boot.efi",
        "C:\\boot.efi",
        "EFI\\..\\x",
        "EFI//x",
        "",
        "EFI/x\0",
    ] {
        assert!(!valid_path(path), "{path}");
    }
    assert!(valid_path("EFI/BOOT/BOOTX64.EFI"));
    assert!(valid_path("ISOs/Some Linux.iso"));
}
