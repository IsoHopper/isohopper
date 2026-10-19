// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_config::{Config, convert, load, parse, schema, validate};
use std::{fs, path::Path};

fn write(path: &Path, data: &str) {
    fs::write(path, data).unwrap();
}

#[test]
fn formats_share_defaults_and_keep_explicit_false() {
    let yaml = b"boot:\n  timeout: 5\n  netboot_xyz: false\nlauncher:\n  theme: NO\nimages:\n  verify_hash: false\n";
    let toml = b"[boot]\ntimeout=5\nnetboot_xyz=false\n[launcher]\ntheme='NO'\n[images]\nverify_hash=false\n";
    let a = parse(yaml, "yml").unwrap();
    assert_eq!(a, parse(toml, "toml").unwrap());
    assert_eq!(a.boot.timeout, 5);
    assert!(!a.boot.netboot_xyz && !a.images.verify_hash);
    assert_eq!(a.launcher.theme, "NO");
    assert_eq!(a.boot.secure_boot_policy, "enforce");
    assert!(a.launcher.warn_multi_disk && a.safety.flag_nvme);
}

#[test]
fn yaml_core_scalars_do_not_apply_legacy_coercions() {
    let a = parse(
        b"boot: {timeout: 010}\nlauncher: {theme: 2026-10-28}",
        "yaml",
    )
    .unwrap();
    assert_eq!(a.boot.timeout, 10);
    assert_eq!(a.launcher.theme, "2026-10-28");
    for value in ["yes", "on", "NO", "1", "'true'"] {
        assert!(
            parse(format!("boot: {{netboot_xyz: {value}}}").as_bytes(), "yml").is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn yaml_rejects_unsafe_ambiguous_and_unknown_values() {
    for data in [
        "boot: &boot {timeout: 5}",
        "boot: *missing",
        "a: &a ['x','x']\nb: &b [*a,*a]\nboot: *b",
        "launcher: !custom {theme: midnight}",
        "launcher: !!python/object {theme: midnight}",
        "boot: {<<: {timeout: 5}}",
        "boot: {timeout: 5, timeout: 6}",
        "boot: {}\nboot: {}",
        "boot: {timeuot: 5}",
        "delete_disk: true",
        "boot: {}\n---\nboot: {}",
        "1: value",
        "[boot]",
        "boot: null",
        "boot: {timeout: -1}",
        "boot: {secure_boot_policy: disable}",
        "overrides: {'../evil.iso': {strategy: native}}",
        "overrides: {'safe.iso': {drivers: ['/etc/shadow']}}",
    ] {
        assert!(parse(data.as_bytes(), "yml").is_err(), "accepted {data:?}");
    }
}

#[test]
fn toml_rejects_duplicates_unknown_fields_and_wrong_types() {
    for data in [
        "[boot]\ntimeout=5\ntimeout=6",
        "[boot]\ntimeuot=5",
        "[boot]\ntimeout='5'",
        "[images]\nverify_signature='sometimes'",
        "[boot]\ntimeout=nan",
        "[launcher]\ntheme=2026-10-28",
        "[safety]\nrisky_size_gb=0",
    ] {
        assert!(parse(data.as_bytes(), "toml").is_err(), "accepted {data:?}");
    }
}

#[test]
fn limits_apply_to_both_formats() {
    let cases = [
        ("yml", "#".repeat(1024 * 1024 + 1), "byte"),
        (
            "yml",
            format!("launcher: {{theme: '{}'}}", "x".repeat(65537)),
            "scalar",
        ),
        (
            "toml",
            format!("[launcher]\ntheme='{}'", "x".repeat(65537)),
            "scalar",
        ),
        (
            "yml",
            format!("x: {}0{}", "[".repeat(34), "]".repeat(34)),
            "depth",
        ),
        (
            "toml",
            format!("x={}0{}", "[".repeat(34), "]".repeat(34)),
            "depth",
        ),
        ("yml", format!("x: [{}]", "0,".repeat(100001)), "node"),
        ("toml", format!("x=[{}]", "0,".repeat(100001)), "node"),
    ];
    for (format, data, kind) in cases {
        let err = parse(data.as_bytes(), format).unwrap_err().to_string();
        assert!(
            err.contains(kind),
            "expected {kind} limit for {format}, got {err}"
        );
    }
}

#[test]
fn schema_and_typed_validation_agree() {
    assert!(serde_json::from_str::<serde_json::Value>(schema()).is_ok());
    validate(&Config::default()).unwrap();
    let mut cfg = Config::default();
    cfg.boot.secure_boot_policy = "invalid".into();
    assert!(validate(&cfg).is_err());
    assert!(parse(b"{}", "json").is_err());
    assert_eq!(parse(b"{}", "yml").unwrap(), Config::default());
    assert_eq!(parse(b"", "toml").unwrap(), Config::default());
}

#[test]
fn directory_precedence_warns_and_yaml_alias_conflicts_fail() {
    let dir = tempfile::tempdir().unwrap();
    write(&dir.path().join("isohopper.toml"), "[boot]\ntimeout=9\n");
    write(&dir.path().join("isohopper.yml"), "boot: {timeout: 5}");
    let cfg = load(dir.path()).unwrap();
    assert_eq!(cfg.boot.timeout, 5);
    assert_eq!(cfg.warnings.len(), 1);
    assert!(cfg.warnings[0].contains("isohopper.toml"));
    write(&dir.path().join("isohopper.yaml"), "boot: {}");
    assert!(load(dir.path()).is_err());
    assert!(load(dir.path().join("isohopper.yml")).is_err());
}

#[test]
fn conversion_roundtrips_and_keeps_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("isohopper.yml");
    let data = "boot: {timeout: 7, netboot_xyz: false}\noverrides:\n  'ISOs/win.iso':\n    strategy: windows\n    drivers: [drivers/storage/]\n    bypass_tpm_check: false\n";
    write(&source, data);
    let expected = parse(data.as_bytes(), "yml").unwrap();
    let dest = convert(&source, "toml", false).unwrap();
    assert!(!source.exists());
    assert_eq!(
        fs::read_to_string(dir.path().join("isohopper.yml.bak")).unwrap(),
        data
    );
    let mut got = load(&dest).unwrap();
    got.source = None;
    got.warnings.clear();
    assert_eq!(got, expected);
    let back = convert(&dest, "yaml", false).unwrap();
    let mut got = load(back).unwrap();
    got.source = None;
    got.warnings.clear();
    assert_eq!(got, expected);
}

#[test]
fn conversion_never_clobbers_without_permission() {
    for backup in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("isohopper.yml");
        write(&source, "boot: {}");
        let collision = dir.path().join(if backup {
            "isohopper.yml.bak"
        } else {
            "isohopper.toml"
        });
        write(&collision, "keep me");
        assert!(convert(&source, "toml", false).is_err());
        assert_eq!(fs::read_to_string(&collision).unwrap(), "keep me");
        assert!(source.exists());
        if backup {
            assert!(convert(&source, "toml", true).is_err());
        }
    }
}

#[test]
fn conversion_force_preserves_source_and_refuses_alias_collisions() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("isohopper.yml");
    write(&source, "boot: {timeout: 4}");
    write(&dir.path().join("isohopper.toml"), "old");
    let dest = convert(&source, "toml", true).unwrap();
    assert_eq!(load(dest).unwrap().boot.timeout, 4);
    write(&dir.path().join("isohopper.yaml"), "boot: {}");
    assert!(convert(dir.path().join("isohopper.toml"), "yml", true).is_err());
}

#[cfg(unix)]
#[test]
fn conversion_refuses_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("original.yml");
    write(&source, "boot: {}");
    let link = dir.path().join("link.yml");
    std::os::unix::fs::symlink(&source, &link).unwrap();
    assert!(convert(&link, "toml", false).is_err());
    let target = dir.path().join("original.toml");
    std::os::unix::fs::symlink(&source, &target).unwrap();
    assert!(convert(&source, "toml", true).is_err());
}

#[cfg(unix)]
#[test]
fn loading_refuses_final_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("real.yml");
    let alias = directory.path().join("alias.yml");
    write(&source, "boot: {timeout: 7}");
    std::os::unix::fs::symlink(&source, &alias).unwrap();
    assert!(load(alias).is_err());
}

#[test]
fn examples_remain_equivalent() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut a = load(root.join("examples/isohopper.yml")).unwrap();
    let mut b = load(root.join("examples/isohopper.toml")).unwrap();
    a.source = None;
    a.warnings.clear();
    b.source = None;
    b.warnings.clear();
    assert_eq!(a, b);
}

#[test]
fn conversion_preserves_quoted_unicode_and_multiline_strings() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("isohopper.toml");
    let data = "[boot]\ndefault = '2026-10-28'\n[launcher]\ntheme = \"quote \\\" café \\n \\\\ true: [yes]\"\n[overrides.'ISOs/café disk.iso']\nstrategy = 'auto'\n";
    write(&source, data);
    let expected = parse(data.as_bytes(), "toml").unwrap();
    let dest = convert(&source, "yml", false).unwrap();
    let mut result = load(dest).unwrap();
    result.source = None;
    assert_eq!(result, expected);
}

#[test]
fn hostile_byte_mutations_never_panic_or_bypass_validation() {
    let seeds: &[&[u8]] = &[
        b"boot: {timeout: 5}\nlauncher: {theme: midnight}",
        b"[boot]\ntimeout=5\n[launcher]\ntheme='midnight'",
        b"overrides: {'ISOs/a.iso': {drivers: ['drivers/x/']}}",
        b"a: &a [*a]\n---\n!!python/object {}",
    ];
    let mut state = 0x382e_0d42_1323_2731u64;
    for turn in 0..10_000 {
        let mut data = seeds[turn % seeds.len()].to_vec();
        for _ in 0..1 + turn % 8 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let position = state as usize % data.len();
            data[position] = (state >> 32) as u8;
        }
        for format in ["yml", "toml"] {
            if let Ok(config) = parse(&data, format) {
                validate(&config).unwrap();
            }
        }
    }
}

#[test]
fn firmware_power_actions_default_enabled_and_roundtrip_in_both_formats() {
    let defaults = serde_json::to_value(Config::default()).unwrap();
    assert_eq!(
        defaults["launcher"]["power"],
        serde_json::json!({"reboot":true,"shutdown":true,"firmware_setup":true})
    );
    let yaml =
        b"launcher:\n  power:\n    reboot: false\n    shutdown: true\n    firmware_setup: false\n";
    let toml = b"[launcher.power]\nreboot=false\nshutdown=true\nfirmware_setup=false\n";
    let expected = parse(yaml, "yaml").unwrap();
    assert_eq!(expected, parse(toml, "toml").unwrap());
    assert_eq!(
        serde_json::to_value(&expected).unwrap()["launcher"]["power"]["reboot"],
        false
    );
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("isohopper.yml");
    fs::write(&source, yaml).unwrap();
    let destination = convert(&source, "toml", false).unwrap();
    let mut loaded = load(&destination).unwrap();
    loaded.source = None;
    assert_eq!(loaded, expected);
    let back = convert(&destination, "yaml", false).unwrap();
    let mut loaded = load(back).unwrap();
    loaded.source = None;
    assert_eq!(loaded, expected);
}

#[test]
fn firmware_power_actions_require_boolean_values_and_known_names() {
    for value in ["1", "'true'", "null", "[true]"] {
        assert!(
            parse(
                format!("launcher: {{power: {{reboot: {value}}}}}").as_bytes(),
                "yaml"
            )
            .is_err()
        );
    }
    for value in ["1", "'true'", "[true]"] {
        assert!(
            parse(
                format!("[launcher.power]\nshutdown={value}").as_bytes(),
                "toml"
            )
            .is_err()
        );
    }
    assert!(parse(b"launcher: {power: {reset: true}}", "yaml").is_err());
}
