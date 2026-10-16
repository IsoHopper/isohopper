// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::{guard::*, layout};

type DiskMutation = Box<dyn Fn(&mut Disk)>;

fn ordinary() -> Disk {
    Disk {
        id: "usb:port-1".into(),
        serial: "USB-AbCd".into(),
        model: "USB flash drive".into(),
        bus: "usb".into(),
        size_bytes: 64_000_000_000,
        logical_sector_size: 512,
        physical_sector_size: 4096,
        external: true,
        safety_checks_complete: true,
        system_disk: Some(false),
        freshly_plugged: true,
        previously_selected: true,
        ..Disk::default()
    }
}

#[test]
fn fixtures_classify_and_missing_evidence_blocks() {
    let disks: Vec<Disk> =
        serde_json::from_str(include_str!("../../../tests/fixtures/disks.json")).unwrap();
    let expected = [
        ("usb-64gb", "ok"),
        ("usb-nvme-1tb", "confirm"),
        ("internal-system", "blocked"),
        ("sd-32gb", "ok"),
        ("missing-serial", "blocked"),
    ];
    assert_eq!(disks.len(), expected.len());
    for (id, state) in expected {
        let d = disks.iter().find(|d| d.id == id).unwrap();
        assert_eq!(evaluate(d, &Options::default()).state, state, "{id}");
    }
    let d: Disk =
        serde_json::from_str(r#"{"id":"a","serial":"b","bus":"usb","external":true}"#).unwrap();
    assert!(!evaluate(&d, &Options::default()).allowed);
}

#[test]
fn hard_blocks_survive_all_overrides() {
    let options = Options {
        large_disk_threshold_bytes: u64::MAX,
        disable_nvme_risk: true,
        disable_fresh_plug_risk: true,
        disable_new_selection_risk: true,
    };
    let changes: Vec<DiskMutation> = vec![
        Box::new(|d| d.id.clear()),
        Box::new(|d| d.serial = "  ".into()),
        Box::new(|d| d.identity_ambiguous = true),
        Box::new(|d| d.safety_checks_complete = false),
        Box::new(|d| d.system_disk = None),
        Box::new(|d| d.system_disk = Some(true)),
        Box::new(|d| d.external = false),
        Box::new(|d| d.bus = "unknown".into()),
        Box::new(|d| d.mounted_system = true),
        Box::new(|d| d.encryption_in_use = true),
        Box::new(|d| d.container_member = true),
        Box::new(|d| d.size_bytes = 0),
        Box::new(|d| d.size_bytes += 1),
        Box::new(|d| d.logical_sector_size = 0),
        Box::new(|d| d.logical_sector_size = 1024),
        Box::new(|d| d.physical_sector_size = 0),
        Box::new(|d| d.physical_sector_size = 256),
        Box::new(|d| d.physical_sector_size = 768),
    ];
    for change in changes {
        let mut d = ordinary();
        change(&mut d);
        let v = evaluate(&d, &options);
        assert_eq!(v.state, "blocked");
        assert!(!v.allowed);
        assert!(!v.hard_blocks.is_empty());
        let consent = Confirmation {
            yes: true,
            interactive: true,
            serial_override: d.serial.clone(),
            challenge: challenge(&d),
            ..Confirmation::default()
        };
        assert_eq!(
            authorize(&d, &options, &consent).unwrap_err().code,
            EXIT_GUARD
        );
    }
}

#[test]
fn risk_threshold_and_confirmation_are_exact() {
    let options = Options::default();
    let mut d = ordinary();
    assert!(authorize(&d, &options, &Confirmation::default()).is_err());
    assert!(
        authorize(
            &d,
            &options,
            &Confirmation {
                yes: true,
                ..Confirmation::default()
            }
        )
        .is_ok()
    );
    d.size_bytes = 256_000_000_000;
    assert!(!evaluate(&d, &options).risky);
    d.size_bytes += 512;
    assert!(evaluate(&d, &options).risky);
    d = ordinary();
    d.has_data = true;
    assert_eq!(challenge(&d), "WIPE 64GB-USB-FLASH-DRIVE-ABCD");
    assert_eq!(evaluate(&d, &options).challenge, challenge(&d));
    for c in [
        Confirmation {
            yes: true,
            ..Default::default()
        },
        Confirmation {
            interactive: true,
            challenge: "AbCd".into(),
            ..Default::default()
        },
        Confirmation {
            interactive: true,
            challenge: format!("{} ", challenge(&d)),
            ..Default::default()
        },
        Confirmation {
            serial_override: "usb-abcd".into(),
            ..Default::default()
        },
        Confirmation {
            yes: true,
            serial_override_set: true,
            ..Default::default()
        },
    ] {
        assert_eq!(authorize(&d, &options, &c).unwrap_err().code, 3);
    }
    assert!(
        authorize(
            &d,
            &options,
            &Confirmation {
                serial_override: d.serial.clone(),
                ..Default::default()
            }
        )
        .is_ok()
    );
    assert!(
        authorize(
            &d,
            &options,
            &Confirmation {
                interactive: true,
                challenge: challenge(&d).to_lowercase(),
                ..Default::default()
            }
        )
        .is_ok()
    );
    let old = challenge(&d);
    d.model = "Other model".into();
    assert!(
        authorize(
            &d,
            &options,
            &Confirmation {
                interactive: true,
                challenge: old,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn identity_change_or_new_hard_block_aborts() {
    let expected = ordinary();
    assert!(revalidate(&expected, &expected).is_ok());
    for change in [0, 1, 2, 3, 4, 5, 6, 7] {
        let mut actual = expected.clone();
        match change {
            0 => actual.serial.push('x'),
            1 => actual.id.push('x'),
            2 => actual.size_bytes += 512,
            3 => actual.logical_sector_size = 4096,
            4 => actual.physical_sector_size = 512,
            5 => actual.bus = "sd".into(),
            6 => actual.safety_checks_complete = false,
            _ => actual.mounted_system = true,
        }
        assert_eq!(
            revalidate(&expected, &actual).unwrap_err().code,
            EXIT_IDENTITY_CHANGED
        );
    }
}

#[test]
fn layout_handles_sector_sizes_large_images_and_backups() {
    for (size, sector, legacy, boot) in [
        (8 << 30, 512, false, 64 << 20),
        (8 << 30, 4096, false, 512 << 20),
        (3 << 40, 512, true, 64 << 20),
        ((8 << 30) + 512, 512, false, 64 << 20),
    ] {
        let p = layout::plan(size, sector, legacy).unwrap();
        assert_eq!(p.total_sectors, size / sector);
        assert_eq!(p.first_usable_lba, 2 + 16384 / sector);
        assert_eq!(p.last_usable_lba, p.total_sectors - 16384 / sector - 2);
        assert_eq!(p.partitions.len(), if legacy { 4 } else { 3 });
        let mut last = 0;
        for part in &p.partitions {
            assert!(part.start_lba > last);
            assert!(part.start_lba <= part.end_lba);
            assert_eq!(part.start_lba * sector % (1 << 20), 0);
            assert!(part.end_lba <= p.last_usable_lba);
            last = part.end_lba;
        }
        for part in &p.partitions[1..3] {
            assert_eq!((part.end_lba - part.start_lba + 1) * sector, boot);
        }
        assert!(layout::validate(&p).is_ok());
        let mut changed = p.clone();
        changed.partitions[0].end_lba += 1;
        assert!(layout::validate(&changed).is_err());
    }
}

#[test]
fn layout_rejects_overflow_small_or_impossible_geometry() {
    for (size, sector, legacy) in [
        (0, 512, false),
        (8 << 30, 0, false),
        (8 << 30, 1024, false),
        ((8 << 30) + 1, 512, false),
        (128 << 20, 512, false),
        (1 << 30, 4096, false),
        (8 << 30, 4096, true),
        (u64::MAX, 512, false),
        (1 << 63, 512, false),
    ] {
        assert!(
            layout::plan(size, sector, legacy).is_err(),
            "{size}/{sector}/{legacy}"
        );
    }
}

#[test]
fn generated_geometry_never_overlaps_or_exceeds_image() {
    let mut state = 0x9182_abcd_1234_5678_u64;
    for _ in 0..10_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let sector = if state & 1 == 0 { 512 } else { 4096 };
        let size = (state >> 1) / sector * sector;
        if let Ok(p) = layout::plan(size, sector, false) {
            assert!(layout::validate(&p).is_ok());
            let mut end = 0;
            for part in p.partitions {
                assert!(part.start_lba > end);
                assert!(part.end_lba < p.total_sectors);
                end = part.end_lba;
            }
        }
    }
}

#[test]
fn every_risk_reason_is_reported_and_data_risks_cannot_be_suppressed() {
    let mut d = ordinary();
    d.nvme = true;
    d.has_data = true;
    d.os_like = true;
    d.freshly_plugged = false;
    d.previously_selected = false;
    d.size_bytes = 1_000_000_000_000;
    let v = evaluate(&d, &Options::default());
    assert!(v.allowed);
    assert_eq!(v.state, "confirm");
    assert_eq!(v.risks.len(), 6);
    for code in [
        "nvme",
        "large_capacity",
        "existing_data",
        "os_like",
        "not_freshly_plugged",
        "new_selection",
    ] {
        assert!(v.risks.iter().any(|r| r.code == code));
    }
    let options = Options {
        large_disk_threshold_bytes: u64::MAX,
        disable_nvme_risk: true,
        disable_fresh_plug_risk: true,
        disable_new_selection_risk: true,
    };
    let v = evaluate(&d, &options);
    assert_eq!(
        v.risks.iter().map(|r| r.code.as_str()).collect::<Vec<_>>(),
        vec!["existing_data", "os_like"]
    );
    assert!(
        authorize(
            &d,
            &options,
            &Confirmation {
                yes: true,
                ..Default::default()
            }
        )
        .is_err()
    );
}
