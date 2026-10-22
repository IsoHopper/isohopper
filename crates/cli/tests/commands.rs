// SPDX-License-Identifier: GPL-3.0-or-later
use std::process::Command;
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_isohopper"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn no_physical_write_override_exists() {
    let out = cli(&[
        "write",
        "--disk",
        "internal-system",
        "--yes",
        "--allow-risky-target",
        "INTERNAL-3456",
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("physical"));
}
#[test]
fn demo_is_explicit_and_reports_guard() {
    let out = cli(&["list", "--demo", "--json"]);
    assert!(out.status.success());
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value[0]["source"], "mock");
    assert_eq!(value[2]["verdict"]["state"], "blocked");
}
#[test]
fn creates_and_verifies_only_new_virtual_image() {
    let temp = tempfile::tempdir().unwrap();
    let p = temp.path().join("test.img");
    let path = p.to_str().unwrap();
    let out = cli(&["image", "create", path, "--size-mib", "160"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(cli(&["image", "verify", path]).status.success());
    assert_eq!(
        cli(&["image", "create", path, "--size-mib", "160"])
            .status
            .code(),
        Some(5)
    );
}
#[test]
fn bad_input_is_usage_failure() {
    assert_eq!(cli(&["--invalid"]).status.code(), Some(2));
}

#[test]
fn real_inventory_is_distinct_from_explicit_demo_listing() {
    let help = cli(&["devices", "--help"]);
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("--json"));
    assert_eq!(cli(&["devices", "--demo"]).status.code(), Some(2));
    let list = cli(&["list"]);
    assert_eq!(list.status.code(), Some(3));
    let message = String::from_utf8_lossy(&list.stderr);
    assert!(message.contains("devices"));
    assert!(message.contains("list --demo"));
}
