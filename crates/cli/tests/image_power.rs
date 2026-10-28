// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::{layout, virtualdisk};
use serde_json::Value;
use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::Path,
    process::{Command, Output},
};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_isohopper"))
        .args(args)
        .output()
        .unwrap()
}

fn efi() -> Vec<u8> {
    let mut bytes = vec![0; 512];
    bytes[..2].copy_from_slice(b"MZ");
    bytes[60..64].copy_from_slice(&128u32.to_le_bytes());
    bytes[128..132].copy_from_slice(b"PE\0\0");
    bytes[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    bytes[134..136].copy_from_slice(&1u16.to_le_bytes());
    bytes[148..150].copy_from_slice(&240u16.to_le_bytes());
    bytes[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
    bytes[220..222].copy_from_slice(&10u16.to_le_bytes());
    bytes[150..152].copy_from_slice(&0x22u16.to_le_bytes());
    bytes[168..172].copy_from_slice(&448u32.to_le_bytes());
    bytes[184..188].copy_from_slice(&32u32.to_le_bytes());
    bytes[188..192].copy_from_slice(&32u32.to_le_bytes());
    bytes[208..212].copy_from_slice(&512u32.to_le_bytes());
    bytes[212..216].copy_from_slice(&448u32.to_le_bytes());
    bytes[260..264].copy_from_slice(&16u32.to_le_bytes());
    bytes[400..404].copy_from_slice(&64u32.to_le_bytes());
    bytes[404..408].copy_from_slice(&448u32.to_le_bytes());
    bytes[408..412].copy_from_slice(&64u32.to_le_bytes());
    bytes[412..416].copy_from_slice(&448u32.to_le_bytes());
    bytes[428..432].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    bytes
}

fn read_at(file: &mut File, offset: u64, bytes: &mut [u8]) {
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(bytes).unwrap();
}

// Follow each FAT32 root entry independently of the writer's cluster choices.
fn assert_stored_power(path: &Path, size_mib: u64, sector: u64, mask: u8) {
    let plan = layout::plan(size_mib << 20, sector, false).unwrap();
    let mut file = File::open(path).unwrap();
    for partition in &plan.partitions[1..3] {
        let base = partition.start_lba * sector;
        let mut boot = vec![0; sector as usize];
        read_at(&mut file, base, &mut boot);
        let word = |offset| u16::from_le_bytes(boot[offset..offset + 2].try_into().unwrap());
        let dword = |offset| u32::from_le_bytes(boot[offset..offset + 4].try_into().unwrap());
        assert_eq!(u64::from(word(11)), sector);
        let cluster_size = sector * u64::from(boot[13]);
        let data =
            base + (u64::from(word(14)) + u64::from(boot[16]) * u64::from(dword(36))) * sector;
        let mut root = vec![0; cluster_size as usize];
        read_at(
            &mut file,
            data + (u64::from(dword(44)) - 2) * cluster_size,
            &mut root,
        );
        let entry = root
            .as_chunks::<32>()
            .0
            .iter()
            .find(|entry| &entry[..11] == b"IHPOWER CFG")
            .unwrap();
        let cluster = u32::from(u16::from_le_bytes(entry[20..22].try_into().unwrap())) << 16
            | u32::from(u16::from_le_bytes(entry[26..28].try_into().unwrap()));
        assert_eq!(u32::from_le_bytes(entry[28..32].try_into().unwrap()), 8);
        let mut stored = [0; 8];
        read_at(
            &mut file,
            data + (u64::from(cluster) - 2) * cluster_size,
            &mut stored,
        );
        assert_eq!(stored, [b'I', b'H', b'P', b'W', 1, mask, 0, 0]);
    }
}

#[test]
fn config_controls_both_fat_volumes_and_reports_exact_preferences() {
    let cases = [
        (
            "yaml",
            "launcher:\n  power:\n    reboot: false\n    shutdown: false\n    firmware_setup: true\n",
            4u8,
            512u64,
            160u64,
        ),
        (
            "toml",
            "[launcher.power]\nreboot = true\nshutdown = true\nfirmware_setup = false\n",
            3,
            4096,
            1100,
        ),
        (
            "yaml",
            "launcher:\n  power:\n    reboot: false\n    shutdown: false\n    firmware_setup: false\n",
            0,
            512,
            160,
        ),
    ];
    for (extension, config_text, mask, sector, size_mib) in cases {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join(format!("isohopper.{extension}"));
        let image = directory.path().join("boot.img");
        let payload = directory.path().join("boot.efi");
        let bytes = efi();
        fs::write(&config, config_text).unwrap();
        fs::write(&payload, &bytes).unwrap();
        let output = cli(&[
            "image",
            "create",
            image.to_str().unwrap(),
            "--size-mib",
            &size_mib.to_string(),
            "--sector-size",
            &sector.to_string(),
            "--efi",
            payload.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(value["power_mask"], mask);
        assert_eq!(value["power"]["reboot"], mask & 1 != 0);
        assert_eq!(value["power"]["shutdown"], mask & 2 != 0);
        assert_eq!(value["power"]["firmware_setup"], mask & 4 != 0);
        assert_stored_power(&image, size_mib, sector, mask);
        virtualdisk::verify_bootable(&image, &bytes).unwrap();
        assert!(
            cli(&[
                "image",
                "verify",
                image.to_str().unwrap(),
                "--efi",
                payload.to_str().unwrap()
            ])
            .status
            .success()
        );
    }
}

#[test]
fn absent_config_preserves_all_three_power_actions() {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("boot.img");
    let payload = directory.path().join("boot.efi");
    fs::write(&payload, efi()).unwrap();
    let output = cli(&[
        "image",
        "create",
        image.to_str().unwrap(),
        "--size-mib",
        "160",
        "--efi",
        payload.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["power_mask"], 7);
    assert_eq!(
        value["power"],
        serde_json::json!({"reboot":true,"shutdown":true,"firmware_setup":true})
    );
    assert_stored_power(&image, 160, 512, 7);
}

#[test]
fn malformed_or_missing_config_creates_no_output() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("boot.efi");
    let config = directory.path().join("isohopper.yaml");
    let image = directory.path().join("boot.img");
    fs::write(&payload, efi()).unwrap();
    for contents in [
        None,
        Some("launcher:\n  power:\n    reboot: 'false'\n"),
        Some("launcher:\n  power:\n    firmware_setpu: false\n"),
    ] {
        if let Some(contents) = contents {
            fs::write(&config, contents).unwrap();
        }
        let output = cli(&[
            "image",
            "create",
            image.to_str().unwrap(),
            "--size-mib",
            "160",
            "--efi",
            payload.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
        ]);
        assert_eq!(
            output.status.code(),
            Some(5),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!image.exists());
    }
}

#[test]
fn config_requires_efi_before_creating_anything() {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("boot.img");
    let config = directory.path().join("isohopper.yaml");
    fs::write(&config, "{}").unwrap();
    let output = cli(&[
        "image",
        "create",
        image.to_str().unwrap(),
        "--size-mib",
        "160",
        "--config",
        config.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--efi"));
    assert!(!image.exists());
}

#[cfg(unix)]
#[test]
fn config_symlink_is_refused_before_creating_image() {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("boot.img");
    let payload = directory.path().join("boot.efi");
    let original = directory.path().join("original.yaml");
    let config = directory.path().join("isohopper.yaml");
    fs::write(&original, "{}").unwrap();
    fs::write(&payload, efi()).unwrap();
    std::os::unix::fs::symlink(&original, &config).unwrap();
    let output = cli(&[
        "image",
        "create",
        image.to_str().unwrap(),
        "--size-mib",
        "160",
        "--efi",
        payload.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert!(!image.exists());
    assert_eq!(fs::read_to_string(original).unwrap(), "{}");
}
