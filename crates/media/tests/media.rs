// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_media::{ImageEntry, ScanLimits, open_image, recipes, scan, scan_with_limits};
use std::fs;

fn iso(label: &str) -> Vec<u8> {
    let mut data = vec![0; 24 * 2048];
    let pvd = &mut data[16 * 2048..17 * 2048];
    pvd[0] = 1;
    pvd[1..6].copy_from_slice(b"CD001");
    pvd[6] = 1;
    pvd[40..72].fill(b' ');
    pvd[40..40 + label.len()].copy_from_slice(label.as_bytes());
    pvd[80..84].copy_from_slice(&24u32.to_le_bytes());
    pvd[84..88].copy_from_slice(&24u32.to_be_bytes());
    pvd[128..130].copy_from_slice(&2048u16.to_le_bytes());
    pvd[130..132].copy_from_slice(&2048u16.to_be_bytes());
    pvd[156] = 34;
    pvd[181] = 2;
    pvd[881] = 1;
    data
}

#[test]
fn scan_returns_only_image_files_and_distinguishes_header_from_boot_evidence() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("ISOs")).unwrap();
    fs::write(
        dir.path().join("ISOs/ubuntu-24.04-desktop-amd64.ISO"),
        iso("Ubuntu 24.04 LTS amd64"),
    )
    .unwrap();
    for extension in ["img", "wim", "vhd", "vhdx", "efi"] {
        fs::write(dir.path().join(format!("disk.{extension}")), b"x").unwrap();
    }
    fs::write(dir.path().join("notes.txt"), b"skip").unwrap();
    let report = scan(dir.path()).unwrap();
    assert_eq!(report.images.len(), 6);
    let image = report
        .images
        .iter()
        .find(|image| image.extension == "iso")
        .unwrap();
    assert_eq!(
        image.iso_volume_label.as_deref(),
        Some("Ubuntu 24.04 LTS amd64")
    );
    assert_eq!(image.inspection_status, "iso9660-header");
    assert_eq!(image.size, 24 * 2048);
    assert!(
        report
            .images
            .iter()
            .all(|image| image.boot_status == "not-boot-tested")
    );
    assert!(
        report
            .images
            .iter()
            .filter(|image| image.extension != "iso")
            .all(|image| image.inspection_status == "unknown")
    );
}

#[test]
fn malformed_iso_headers_do_not_supply_a_label() {
    let dir = tempfile::tempdir().unwrap();
    let valid = iso("Ubuntu 24.04 LTS amd64");
    let mut cases = vec![vec![], valid[..33000].to_vec()];
    for offset in [
        16 * 2048 + 1,
        16 * 2048 + 6,
        16 * 2048 + 84,
        16 * 2048 + 130,
        16 * 2048 + 881,
    ] {
        let mut bad = valid.clone();
        bad[offset] ^= 0xff;
        cases.push(bad);
    }
    for (index, data) in cases.iter().enumerate() {
        fs::write(dir.path().join(format!("bad-{index}.iso")), data).unwrap();
    }
    let report = scan(dir.path()).unwrap();
    assert!(
        report
            .images
            .iter()
            .all(|image| image.iso_volume_label.is_none()
                && image.inspection_status == "invalid-iso9660-header")
    );
}

#[test]
fn descriptor_search_is_bounded_and_accepts_boot_record_before_primary() {
    let dir = tempfile::tempdir().unwrap();
    let mut data = iso("Debian Live 12");
    data.copy_within(16 * 2048..17 * 2048, 17 * 2048);
    data[16 * 2048] = 0;
    fs::write(dir.path().join("debian-live.iso"), data).unwrap();
    assert_eq!(
        scan(dir.path()).unwrap().images[0]
            .iso_volume_label
            .as_deref(),
        Some("Debian Live 12")
    );
    let mut flood = vec![0; 64 * 2048];
    for chunk in flood[16 * 2048..].chunks_mut(2048) {
        chunk[1..6].copy_from_slice(b"CD001");
        chunk[6] = 1;
    }
    fs::write(dir.path().join("flood.iso"), flood).unwrap();
    assert!(
        scan(dir.path())
            .unwrap()
            .images
            .iter()
            .find(|image| image.relative_path == "flood.iso")
            .unwrap()
            .iso_volume_label
            .is_none()
    );
}

#[test]
fn scan_limits_fail_explicitly_instead_of_returning_a_complete_looking_subset() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("one/two")).unwrap();
    fs::write(dir.path().join("one/two/deep.iso"), b"").unwrap();
    assert!(
        scan_with_limits(
            dir.path(),
            ScanLimits {
                max_depth: 1,
                max_entries: 100
            }
        )
        .is_err()
    );
    assert!(
        scan_with_limits(
            dir.path(),
            ScanLimits {
                max_depth: 8,
                max_entries: 1
            }
        )
        .is_err()
    );
}

#[cfg(unix)]
#[test]
fn scan_never_follows_symlinks_or_opens_special_files() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::write(
        outside.path().join("outside.iso"),
        iso("Ubuntu 24.04 LTS amd64"),
    )
    .unwrap();
    symlink(outside.path(), dir.path().join("escape")).unwrap();
    symlink(
        outside.path().join("outside.iso"),
        dir.path().join("link.iso"),
    )
    .unwrap();
    assert!(
        std::process::Command::new("mkfifo")
            .arg(dir.path().join("pipe.iso"))
            .status()
            .unwrap()
            .success()
    );
    let report = scan(dir.path()).unwrap();
    assert!(report.images.is_empty());
    assert!(!report.warnings.is_empty());
    assert!(scan(dir.path().join("escape")).is_err());
}

fn image(name: &str, label: Option<&str>) -> ImageEntry {
    ImageEntry {
        relative_path: name.into(),
        size: 123,
        extension: "iso".into(),
        iso_volume_label: label.map(str::to_owned),
        inspection_status: "iso9660-header".into(),
        boot_status: "not-boot-tested".into(),
        boot_inspection: None,
    }
}

#[test]
fn recipes_require_matching_family_evidence_and_remain_untested() {
    let ubuntu = recipes::select(&image(
        "ISOs/ubuntu-24.04-desktop-amd64.iso",
        Some("Ubuntu 24.04 LTS amd64"),
    ))
    .unwrap()
    .unwrap();
    assert_eq!(ubuntu.family, "ubuntu-live");
    assert_eq!(ubuntu.status, "untested");
    assert!(
        ubuntu
            .kernel_arguments
            .contains(&"iso-scan/filename=/ISOs/ubuntu-24.04-desktop-amd64.iso".into())
    );
    let debian = recipes::select(&image("debian-live-12-amd64.iso", Some("Debian Live 12")))
        .unwrap()
        .unwrap();
    assert!(
        debian
            .kernel_arguments
            .contains(&"findiso=/debian-live-12-amd64.iso".into())
    );
    for candidate in [
        image("ubuntu-24.04-desktop-amd64.iso", None),
        image("windows.iso", Some("Ubuntu 24.04")),
        image("debian-12-netinst.iso", Some("Debian 12")),
        image("ubuntu-24.04-desktop-amd64.iso", Some("Fedora")),
    ] {
        assert!(recipes::select(&candidate).unwrap().is_none());
    }
}

#[test]
fn recipe_paths_cannot_inject_arguments_or_escape_library() {
    for path in [
        "../ubuntu-desktop.iso",
        "/ubuntu-desktop.iso",
        "a/../ubuntu-desktop.iso",
        "ubuntu desktop.iso",
        "ubuntu-desktop.iso init=/bin/sh",
        "ubuntu-$(reboot)-desktop.iso",
        "ubuntu-'x'-desktop.iso",
        "a\\ubuntu-desktop.iso",
        "ubuntu-desktop.iso\ninit=evil",
    ] {
        assert!(
            recipes::select(&image(path, Some("Ubuntu 24.04"))).is_err(),
            "accepted {path:?}"
        );
    }
}

#[test]
fn nested_libraries_preserve_hierarchy_duplicate_names_and_spaces() {
    let root = tempfile::tempdir().unwrap();
    for folder in ["Mac", "Windows", "Linux with spaces"] {
        fs::create_dir(root.path().join(folder)).unwrap();
    }
    for (path, bytes) in [
        ("Mac/MacOS.img", b"mac".as_slice()),
        ("Windows/Win11.iso", b"windows".as_slice()),
        ("Mac/shared.img", b"first".as_slice()),
        ("Windows/shared.img", b"second".as_slice()),
        ("Linux with spaces/my disk.img", b"spaces".as_slice()),
    ] {
        fs::write(root.path().join(path), bytes).unwrap();
    }
    let report = scan(root.path()).unwrap();
    let paths: Vec<_> = report
        .images
        .iter()
        .map(|image| image.relative_path.as_str())
        .collect();
    assert_eq!(
        paths,
        [
            "Linux with spaces/my disk.img",
            "Mac/MacOS.img",
            "Mac/shared.img",
            "Windows/Win11.iso",
            "Windows/shared.img"
        ]
    );
    use std::io::Read;
    let mut file = open_image(root.path(), "Linux with spaces/my disk.img").unwrap();
    let mut data = String::new();
    file.read_to_string(&mut data).unwrap();
    assert_eq!(data, "spaces");
}

#[test]
fn retained_image_open_rejects_escaping_paths() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("image.img"), b"image").unwrap();
    for path in [
        "../image.img",
        "/image.img",
        "folder/../image.img",
        "folder\\image.img",
        "C:/image.img",
        "folder//image.img",
        "image.img/",
        "image.txt",
    ] {
        assert!(open_image(root.path(), path).is_err(), "opened {path:?}");
    }
}

#[cfg(unix)]
#[test]
fn retained_image_handle_cannot_follow_swapped_links() {
    use std::{io::Read, os::unix::fs::symlink};
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("Mac")).unwrap();
    fs::write(root.path().join("Mac/MacOS.img"), b"original").unwrap();
    fs::write(outside.path().join("MacOS.img"), b"outside").unwrap();
    let mut retained = open_image(root.path(), "Mac/MacOS.img").unwrap();
    fs::rename(root.path().join("Mac"), root.path().join("old-Mac")).unwrap();
    symlink(outside.path(), root.path().join("Mac")).unwrap();
    assert!(open_image(root.path(), "Mac/MacOS.img").is_err());
    symlink(
        outside.path().join("MacOS.img"),
        root.path().join("leaf.img"),
    )
    .unwrap();
    assert!(open_image(root.path(), "leaf.img").is_err());
    let mut data = String::new();
    retained.read_to_string(&mut data).unwrap();
    assert_eq!(data, "original");
}
