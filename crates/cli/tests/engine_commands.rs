// SPDX-License-Identifier: GPL-3.0-or-later
use std::{fs, process::Command};

fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_isohopper"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn engine_help_explains_unformatted_data_and_requires_an_archive() {
    let help = cli(&["image", "engine", "--help"]);
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("unformatted"));
    assert!(text.contains("--archive"));
    assert_eq!(
        cli(&["image", "engine", "unused.img", "--size-mib", "256"])
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn invalid_engine_inputs_never_create_or_truncate_output() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("invalid.tar.gz");
    let output = root.path().join("output.img");
    fs::write(&archive, b"not the pinned archive").unwrap();
    for size in ["0", "256", "18446744073709551615"] {
        let result = cli(&[
            "image",
            "engine",
            output.to_str().unwrap(),
            "--size-mib",
            size,
            "--archive",
            archive.to_str().unwrap(),
        ]);
        assert_eq!(result.status.code(), Some(5));
        assert!(!output.exists());
    }
    fs::write(&output, b"retain existing data").unwrap();
    let result = cli(&[
        "image",
        "engine",
        output.to_str().unwrap(),
        "--size-mib",
        "256",
        "--archive",
        archive.to_str().unwrap(),
    ]);
    assert_eq!(result.status.code(), Some(5));
    assert_eq!(fs::read(output).unwrap(), b"retain existing data");
}

#[test]
#[ignore = "requires the pinned external engine archive; never downloads"]
fn pinned_archive_produces_a_verified_but_unformatted_regular_file() {
    let archive = std::env::var("ISOHOPPER_ENGINE_ARCHIVE").expect("external archive path");
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("engine.img");
    let args = [
        "image",
        "engine",
        output.to_str().unwrap(),
        "--size-mib",
        "256",
        "--archive",
        &archive,
    ];
    let result = cli(&args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(value["status"], "verified-engine-image");
    assert_eq!(value["engine"], "Ventoy");
    assert_eq!(value["data_partition"], "unformatted");
    assert_eq!(value["os_boot_tested"], false);
    assert_eq!(value["secure_boot_verified"], false);
    assert_eq!(value["capacity_bytes"], 256u64 << 20);
    assert_eq!(value["partition_guids"].as_array().unwrap().len(), 2);
    assert_eq!(fs::metadata(&output).unwrap().len(), 256 << 20);
    let mut file = fs::File::open(&output).unwrap();
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(1 << 20)).unwrap();
    let mut data = [255; 512];
    file.read_exact(&mut data).unwrap();
    assert_eq!(data, [0; 512]);
    assert_eq!(cli(&args).status.code(), Some(5), "must not overwrite");
    assert_eq!(fs::metadata(&output).unwrap().len(), 256 << 20);
}
