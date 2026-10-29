// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::{
    raw_image_job::{
        BootArtifactFingerprint, ImageFingerprint, PreparedRawImage, RawImageDescription,
        RawImageError,
    },
    writer::{DeviceSnapshot, Geometry, StableDeviceId},
};

fn description() -> RawImageDescription {
    RawImageDescription {
        target: DeviceSnapshot {
            device_number: 7,
            serial: "USB-TEST-0001".into(),
            device_id: None,
            bus_type: 7,
            geometry: Geometry {
                size_bytes: 16_777_216,
                logical_sector_size: 512,
                physical_sector_size: 4096,
            },
        },
        image: ImageFingerprint {
            bytes: 16_777_216,
            sha256: [1; 32],
        },
        boot_artifacts: vec![
            BootArtifactFingerprint {
                role: "uefi_launcher".into(),
                version: Some("0.1.0".into()),
                bytes: 4096,
                sha256: [2; 32],
            },
            BootArtifactFingerprint {
                role: "bios_loader".into(),
                version: None,
                bytes: 8192,
                sha256: [3; 32],
            },
        ],
    }
}

#[test]
fn binds_the_exact_raw_image_and_provenance_in_a_stable_versioned_digest() {
    let input = description();
    let prepared = PreparedRawImage::new(input.clone()).unwrap();
    assert_eq!(prepared.target(), &input.target);
    assert_eq!(prepared.image(), &input.image);
    assert_eq!(prepared.boot_artifacts(), input.boot_artifacts);
    assert_eq!(
        prepared.digest(),
        PreparedRawImage::new(input).unwrap().digest()
    );
    // Independent Python struct.pack/hashlib encoding of the documented v1
    // domain and field order, 257 bytes including all length/presence tags.
    assert_eq!(
        hex::encode(prepared.digest()),
        "14eccc51464f81db14ed907f240e21c13bceafa36bfbbea4587af79eb8ea6009"
    );
}

#[test]
fn every_target_image_and_provenance_change_invalidates_the_digest() {
    let baseline = PreparedRawImage::new(description()).unwrap().digest();
    let changes: [fn(&mut RawImageDescription); 16] = [
        |d| d.target.device_number += 1,
        |d| d.target.serial.push('x'),
        |d| d.target.device_id = Some(StableDeviceId::from_naa128([0x60; 16]).unwrap()),
        |d| d.target.bus_type = 12,
        |d| {
            d.target.geometry.size_bytes *= 2;
            d.image.bytes *= 2;
        },
        |d| d.target.geometry.logical_sector_size = 4096,
        |d| d.target.geometry.physical_sector_size = 8192,
        |d| d.image.sha256[0] ^= 1,
        |d| d.boot_artifacts[0].role.push('2'),
        |d| d.boot_artifacts[0].version = Some("0.1.1".into()),
        |d| d.boot_artifacts[0].version = None,
        |d| d.boot_artifacts[1].version = Some("0.1.0".into()),
        |d| d.boot_artifacts[0].bytes += 1,
        |d| d.boot_artifacts[0].sha256[0] ^= 1,
        |d| d.boot_artifacts.swap(0, 1),
        |d| {
            d.boot_artifacts.pop();
        },
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let mut input = description();
        change(&mut input);
        assert_ne!(
            PreparedRawImage::new(input).unwrap().digest(),
            baseline,
            "changed field {index} reused a digest"
        );
    }
    let mut first = description();
    first.target.device_id = Some(StableDeviceId::from_naa128([0x60; 16]).unwrap());
    let mut second = first.clone();
    second.target.device_id = Some(StableDeviceId::from_naa128([0x61; 16]).unwrap());
    assert_ne!(
        PreparedRawImage::new(first).unwrap().digest(),
        PreparedRawImage::new(second).unwrap().digest()
    );
}

#[test]
fn variable_length_metadata_cannot_alias_by_concatenation() {
    let mut first = description();
    first.boot_artifacts[0].role = "a".into();
    first.boot_artifacts[0].version = Some("bc".into());
    let mut second = first.clone();
    second.boot_artifacts[0].role = "ab".into();
    second.boot_artifacts[0].version = Some("c".into());
    assert_ne!(
        PreparedRawImage::new(first).unwrap().digest(),
        PreparedRawImage::new(second).unwrap().digest()
    );
}

#[test]
fn rejects_invalid_target_geometry_and_images_not_exactly_device_sized() {
    let changes: [fn(&mut RawImageDescription); 13] = [
        |d| d.target.device_number = u32::MAX,
        |d| d.target.serial.clear(),
        |d| d.target.serial = " \t ".into(),
        |d| d.target.serial.push('\0'),
        |d| d.target.serial = "x".repeat(4097),
        |d| d.target.geometry.logical_sector_size = 0,
        |d| d.target.geometry.physical_sector_size = 256,
        |d| d.target.geometry.physical_sector_size = 131_072,
        |d| d.target.geometry.size_bytes += 1,
        |d| d.target.geometry.size_bytes = 0,
        |d| d.image.bytes = 0,
        |d| d.image.bytes -= 512,
        |d| d.image.bytes += 512,
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let mut input = description();
        change(&mut input);
        assert!(
            matches!(
                PreparedRawImage::new(input),
                Err(RawImageError::InvalidDescription(_))
            ),
            "invalid target/image {index} accepted"
        );
    }
}

#[test]
fn rejects_missing_oversized_ambiguous_or_malformed_boot_provenance() {
    for role in ["", "../boot", "BOOT", "boot loader", "boot\0loader"] {
        let mut input = description();
        input.boot_artifacts[0].role = role.into();
        assert!(PreparedRawImage::new(input).is_err(), "role {role:?}");
    }
    for version in ["", " ", " v1", "v1 ", "v1\n"] {
        let mut input = description();
        input.boot_artifacts[0].version = Some(version.into());
        assert!(PreparedRawImage::new(input).is_err(), "version {version:?}");
    }
    let changes: [fn(&mut RawImageDescription); 7] = [
        |d| d.boot_artifacts.clear(),
        |d| d.boot_artifacts[1].role = d.boot_artifacts[0].role.clone(),
        |d| d.boot_artifacts[0].role = "x".repeat(65),
        |d| d.boot_artifacts[0].version = Some("x".repeat(129)),
        |d| d.boot_artifacts[0].bytes = 0,
        |d| d.boot_artifacts[0].bytes = i64::MAX as u64 + 1,
        |d| {
            d.boot_artifacts = (0..33)
                .map(|index| BootArtifactFingerprint {
                    role: format!("part_{index}"),
                    ..d.boot_artifacts[0].clone()
                })
                .collect();
        },
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let mut input = description();
        change(&mut input);
        assert!(PreparedRawImage::new(input).is_err(), "provenance {index}");
    }
    let mut maximum = description();
    maximum.boot_artifacts = (0..32)
        .map(|index| BootArtifactFingerprint {
            role: format!("part_{index}_{}", "x".repeat(56)),
            version: Some("v".repeat(128)),
            ..maximum.boot_artifacts[0].clone()
        })
        .collect();
    PreparedRawImage::new(maximum).unwrap();
}

#[test]
fn failed_confirmation_preserves_pending_and_success_consumes_it_once() {
    let prepared = PreparedRawImage::new(description()).unwrap();
    assert_eq!(prepared.challenge(), "ENABLE_WRITE");
    let digest = prepared.digest();
    let target = prepared.target().clone();
    let mut pending = prepared.into_confirmation();
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 1;
    assert!(matches!(
        pending.confirm(&wrong_digest, &target, "ENABLE_WRITE"),
        Err(RawImageError::DigestMismatch)
    ));
    let mut wrong_target = target.clone();
    wrong_target.geometry.physical_sector_size *= 2;
    assert!(matches!(
        pending.confirm(&digest, &wrong_target, "ENABLE_WRITE"),
        Err(RawImageError::TargetMismatch)
    ));
    for challenge in [
        "",
        "USB-TEST-0001",
        "WIPE USB-TEST-0001",
        "enable_write",
        "ENABLE_WRITE ",
        " ENABLE_WRITE",
    ] {
        assert!(matches!(
            pending.confirm(&digest, &target, challenge),
            Err(RawImageError::ChallengeMismatch)
        ));
    }
    let receipt = pending.confirm(&digest, &target, "ENABLE_WRITE").unwrap();
    assert_eq!(receipt.description().digest(), digest);
    assert_eq!(receipt.description().image(), &description().image);
    assert!(matches!(
        pending.confirm(&digest, &target, "ENABLE_WRITE"),
        Err(RawImageError::AlreadyConfirmed)
    ));
}

#[test]
fn fixed_phrase_keeps_device_binding_and_confirmation_is_only_per_instance() {
    let mut input = description();
    input.target.serial.clear();
    input.target.device_id = Some(StableDeviceId::from_naa128([0x60; 16]).unwrap());
    for _ in 0..2 {
        let prepared = PreparedRawImage::new(input.clone()).unwrap();
        assert_eq!(prepared.challenge(), "ENABLE_WRITE");
        let digest = prepared.digest();
        let target = prepared.target().clone();
        let challenge = prepared.challenge().to_owned();
        prepared
            .into_confirmation()
            .confirm(&digest, &target, &challenge)
            .unwrap();
    }
}
