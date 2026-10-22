// SPDX-License-Identifier: GPL-3.0-or-later
use ed25519_dalek::{Signer, SigningKey};
use serde_json::Value;
use std::{
    fs,
    process::{Command, Output},
};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_isohopper"))
        .args(args)
        .output()
        .unwrap()
}
fn json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn iso() -> Vec<u8> {
    let mut data = vec![0; 24 * 2048];
    let pvd = &mut data[16 * 2048..17 * 2048];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[40..72].fill(b' ');
    pvd[40..52].copy_from_slice(b"Ubuntu 24.04");
    pvd[80..84].copy_from_slice(&24u32.to_le_bytes());
    pvd[84..88].copy_from_slice(&24u32.to_be_bytes());
    pvd[128..130].copy_from_slice(&2048u16.to_le_bytes());
    pvd[130..132].copy_from_slice(&2048u16.to_be_bytes());
    pvd[156] = 34;
    pvd[181] = 2;
    pvd[881] = 1;
    data
}

fn efi() -> Vec<u8> {
    let mut data = vec![0; 512];
    data[..2].copy_from_slice(b"MZ");
    data[60..64].copy_from_slice(&128u32.to_le_bytes());
    data[128..132].copy_from_slice(b"PE\0\0");
    data[132..134].copy_from_slice(&0x8664u16.to_le_bytes());
    data[134..136].copy_from_slice(&1u16.to_le_bytes());
    data[148..150].copy_from_slice(&240u16.to_le_bytes());
    data[152..154].copy_from_slice(&0x20bu16.to_le_bytes());
    data[220..222].copy_from_slice(&10u16.to_le_bytes());
    data
}

#[test]
fn scan_json_exposes_labels_and_only_untested_recipe_candidates() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("ubuntu-24.04-desktop-amd64.iso"),
        iso(),
    )
    .unwrap();
    fs::write(directory.path().join("unknown.img"), b"unknown").unwrap();
    let result = json(&cli(&[
        "scan",
        directory.path().to_str().unwrap(),
        "--json",
    ]));
    assert_eq!(result["images"].as_array().unwrap().len(), 2);
    let ubuntu = result["images"]
        .as_array()
        .unwrap()
        .iter()
        .find(|image| image["extension"] == "iso")
        .unwrap();
    assert_eq!(ubuntu["iso_volume_label"], "Ubuntu 24.04");
    assert_eq!(ubuntu["boot_status"], "not-boot-tested");
    assert_eq!(ubuntu["recipe"]["status"], "untested");
    assert_eq!(ubuntu["recipe"]["family"], "ubuntu-live");
}

#[test]
fn scan_terminal_output_explains_unknown_images_and_recipe_path_restrictions() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory
            .path()
            .join("ubuntu-24.04-desktop-with spaces.iso"),
        iso(),
    )
    .unwrap();
    let output = cli(&["scan", directory.path().to_str().unwrap()]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "ubuntu-24.04-desktop-with spaces.iso",
        "iso",
        "49152 bytes",
        "Ubuntu 24.04",
        "not-boot-tested",
        "rename",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
}

#[test]
fn scan_reports_catalog_platforms_as_metadata_and_not_boot_support() {
    let directory = tempfile::tempdir().unwrap();
    let mut data = iso();
    for (offset, value) in [(158, 19u32), (166, 2048)] {
        data[16 * 2048 + offset..16 * 2048 + offset + 4].copy_from_slice(&value.to_le_bytes());
        data[16 * 2048 + offset + 4..16 * 2048 + offset + 8].copy_from_slice(&value.to_be_bytes());
    }
    for (sector, kind) in [(17, 0), (18, 255)] {
        let descriptor = &mut data[sector * 2048..][..2048];
        descriptor[0] = kind;
        descriptor[1..6].copy_from_slice(b"CD001");
        descriptor[6] = 1;
    }
    data[17 * 2048 + 7..17 * 2048 + 30].copy_from_slice(b"EL TORITO SPECIFICATION");
    data[17 * 2048 + 71..17 * 2048 + 75].copy_from_slice(&20u32.to_le_bytes());
    let catalog = &mut data[20 * 2048..][..2048];
    catalog[0] = 1;
    catalog[30] = 0x55;
    catalog[31] = 0xaa;
    catalog[28..30].copy_from_slice(&0x55aau16.to_le_bytes());
    for (offset, lba) in [(32, 21u32), (96, 22)] {
        catalog[offset] = 0x88;
        catalog[offset + 6] = 4;
        catalog[offset + 8..offset + 12].copy_from_slice(&lba.to_le_bytes());
    }
    catalog[64] = 0x91;
    catalog[65] = 0xef;
    catalog[66] = 1;
    fs::write(directory.path().join("mixed.iso"), data).unwrap();
    let value = json(&cli(&[
        "scan",
        directory.path().to_str().unwrap(),
        "--json",
    ]));
    let evidence = &value["images"][0]["boot_inspection"];
    assert_eq!(evidence["status"], "metadata-only");
    assert_eq!(evidence["boot_tested"], false);
    assert_eq!(evidence["catalogs"][0]["entries"][1]["platform"], "efi");
    let output = cli(&["scan", directory.path().to_str().unwrap()]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("El Torito: bios-x86, efi"), "{text}");
    assert!(text.contains("not boot-tested"), "{text}");
}

#[test]
fn scan_cli_keeps_nested_paths_and_same_basename_images_distinct() {
    let directory = tempfile::tempdir().unwrap();
    for folder in ["Mac", "Windows"] {
        fs::create_dir(directory.path().join(folder)).unwrap();
    }
    for path in [
        "Mac/MacOS.img",
        "Windows/Win11.iso",
        "Mac/shared.img",
        "Windows/shared.img",
    ] {
        fs::write(directory.path().join(path), b"image").unwrap();
    }
    let value = json(&cli(&[
        "scan",
        directory.path().to_str().unwrap(),
        "--json",
    ]));
    let paths: Vec<_> = value["images"]
        .as_array()
        .unwrap()
        .iter()
        .map(|image| image["relative_path"].as_str().unwrap())
        .collect();
    assert_eq!(
        paths,
        [
            "Mac/MacOS.img",
            "Mac/shared.img",
            "Windows/Win11.iso",
            "Windows/shared.img"
        ]
    );
}

#[test]
fn manifest_cli_verifies_exact_detached_signature_and_reports_supplied_key_scope() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("manifest.json");
    let signature = directory.path().join("manifest.sig");
    let data = serde_json::to_vec(&serde_json::json!({"schema_version":1,"artifacts":[{"id":"netboot-xyz","version":"1.0","architecture":"x86_64","url":"https://boot.netboot.xyz/netboot.xyz.efi","sha256":"ab".repeat(32)}]})).unwrap();
    let key = SigningKey::from_bytes(&[9; 32]);
    let public = hex::encode(key.verifying_key().as_bytes());
    fs::write(&payload, &data).unwrap();
    fs::write(&signature, key.sign(&data).to_bytes()).unwrap();
    let args = [
        "manifest",
        "verify",
        payload.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        &public,
    ];
    let value = json(&cli(&args));
    assert_eq!(value["status"], "signature-matches-supplied-key");
    assert_eq!(value["manifest"]["artifacts"][0]["id"], "netboot-xyz");
    fs::write(&payload, b"not JSON and not signed").unwrap();
    let failed = cli(&args);
    assert_eq!(failed.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&failed.stderr).contains("signature verification failed"));
}

#[test]
fn manifest_cli_rejects_wrong_key_and_signature_lengths() {
    let directory = tempfile::tempdir().unwrap();
    let payload = directory.path().join("m.json");
    let signature = directory.path().join("m.sig");
    fs::write(&payload, b"{}").unwrap();
    fs::write(&signature, [0u8; 65]).unwrap();
    for key in ["ab".repeat(31), "zz".repeat(32), "ab".repeat(33)] {
        let output = cli(&[
            "manifest",
            "verify",
            payload.to_str().unwrap(),
            "--signature",
            signature.to_str().unwrap(),
            "--public-key",
            &key,
        ]);
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("public key"));
    }
    let output = cli(&[
        "manifest",
        "verify",
        payload.to_str().unwrap(),
        "--signature",
        signature.to_str().unwrap(),
        "--public-key",
        &"ab".repeat(32),
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&output.stderr).contains("64"));
}

#[test]
fn efi_image_cli_creates_and_checks_both_slots_without_claiming_firmware_validation() {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("boot.img");
    let payload = directory.path().join("BOOTX64.EFI");
    fs::write(&payload, efi()).unwrap();
    let value = json(&cli(&[
        "image",
        "create",
        image.to_str().unwrap(),
        "--size-mib",
        "160",
        "--efi",
        payload.to_str().unwrap(),
    ]));
    assert_eq!(value["status"], "firmware-test-only");
    assert_eq!(value["boot_slots"]["A"], "fat32");
    assert_eq!(value["boot_slots"]["B"], "fat32");
    assert_eq!(value["data_partition"], "unformatted");
    assert_eq!(value["firmware_boot_tested"], false);
    let checked = json(&cli(&[
        "image",
        "verify",
        image.to_str().unwrap(),
        "--efi",
        payload.to_str().unwrap(),
    ]));
    assert_eq!(checked["verification"], "gpt-and-fat32-payload");
    assert_eq!(checked["firmware_boot_tested"], false);
    assert_eq!(checked["data_partition"], "not-checked");
    let gpt_only = json(&cli(&["image", "verify", image.to_str().unwrap()]));
    assert_eq!(gpt_only["filesystem_verification"], "not-requested");
    let mut different = efi();
    different[511] = 42;
    fs::write(&payload, different).unwrap();
    assert_eq!(
        cli(&[
            "image",
            "verify",
            image.to_str().unwrap(),
            "--efi",
            payload.to_str().unwrap()
        ])
        .status
        .code(),
        Some(5)
    );
}

#[test]
fn invalid_efi_never_creates_destination() {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("boot.img");
    let payload = directory.path().join("bad.efi");
    fs::write(&payload, b"not a PE image").unwrap();
    let output = cli(&[
        "image",
        "create",
        image.to_str().unwrap(),
        "--size-mib",
        "160",
        "--efi",
        payload.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert!(!image.exists());
}

#[cfg(unix)]
#[test]
fn binary_inputs_reject_symlinks_and_special_files_without_creating_images() {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("boot.img");
    let payload = directory.path().join("source.efi");
    let link = directory.path().join("link.efi");
    fs::write(&payload, efi()).unwrap();
    std::os::unix::fs::symlink(&payload, &link).unwrap();
    assert_eq!(
        cli(&[
            "image",
            "create",
            image.to_str().unwrap(),
            "--size-mib",
            "160",
            "--efi",
            link.to_str().unwrap()
        ])
        .status
        .code(),
        Some(5)
    );
    assert!(!image.exists());
    let pipe = directory.path().join("pipe.efi");
    assert!(
        Command::new("mkfifo")
            .arg(&pipe)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        cli(&[
            "image",
            "create",
            image.to_str().unwrap(),
            "--size-mib",
            "160",
            "--efi",
            pipe.to_str().unwrap()
        ])
        .status
        .code(),
        Some(5)
    );
    assert!(!image.exists());
}

#[test]
fn oversized_efi_is_rejected_before_reading_or_creating_image() {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("boot.img");
    let payload = directory.path().join("large.efi");
    fs::File::create(&payload)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    let output = cli(&[
        "image",
        "create",
        image.to_str().unwrap(),
        "--size-mib",
        "160",
        "--efi",
        payload.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(5));
    assert!(String::from_utf8_lossy(&output.stderr).contains("byte limit"));
    assert!(!image.exists());
}
