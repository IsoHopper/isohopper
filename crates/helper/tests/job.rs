// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::layout;
use isohopper_helper::{
    job::{
        Configuration, ConfigurationFormat, JobDescription, JobError, PayloadFingerprint,
        PreparedJob, SourceMetadata,
    },
    writer::{DeviceSnapshot, Geometry, StableDeviceId},
};

fn description() -> JobDescription {
    JobDescription {
        target: DeviceSnapshot {
            device_number: 7,
            serial: "USB-TEST-0001".into(),
            device_id: None,
            bus_type: 7,
            geometry: Geometry {
                size_bytes: 256 * 1024 * 1024,
                logical_sector_size: 512,
                physical_sector_size: 4096,
            },
        },
        layout: layout::plan(256 * 1024 * 1024, 512, false).unwrap(),
        sources: vec![
            SourceMetadata {
                source_id: format!("src_{}", "1".repeat(64)),
                destination: "Windows/Win11.iso".into(),
                bytes: 4096,
                sha256: [1; 32],
            },
            SourceMetadata {
                source_id: format!("src_{}", "2".repeat(64)),
                destination: "Linux/日本語.iso".into(),
                bytes: 8192,
                sha256: [2; 32],
            },
        ],
        configuration: Configuration {
            format: ConfigurationFormat::Yaml,
            bytes: b"version: 1\n".to_vec(),
        },
        payloads: vec![
            PayloadFingerprint {
                role: "launcher_x64".into(),
                bytes: 4096,
                sha256: [3; 32],
            },
            PayloadFingerprint {
                role: "utility_x64".into(),
                bytes: 8192,
                sha256: [4; 32],
            },
        ],
    }
}

#[test]
fn equivalent_descriptions_have_stable_digests_and_retain_exact_metadata() {
    let input = description();
    let job = PreparedJob::new(input.clone()).unwrap();
    let equivalent = PreparedJob::new(input.clone()).unwrap();
    assert_eq!(job.digest(), equivalent.digest());
    // Independently encoded with Python struct.pack and hashlib using the
    // documented v1 field order, including the literal canonical GPT geometry.
    assert_eq!(
        hex::encode(job.digest()),
        "ca64c5e191ec9ba9e16f60ee7cdb5ea7b2d86bb16a365e46dfaebd07f7bb1213"
    );
    assert_eq!(job.target(), &input.target);
    assert_eq!(job.layout(), &input.layout);
    assert_eq!(job.sources(), input.sources);
    assert_eq!(job.payloads(), input.payloads);
    assert_eq!(job.configuration().bytes, 11);
    assert_eq!(job.configuration().format, ConfigurationFormat::Yaml);
    assert_eq!(
        hex::encode(job.configuration().sha256),
        "09bfcc6a14b83e2192b8673677725c84883ee9cd0c70e45c9ec09daa8f2b2847"
    );
}

#[test]
fn changing_any_execution_input_changes_the_digest() {
    let original = PreparedJob::new(description()).unwrap().digest();
    let changes: [fn(&mut JobDescription); 18] = [
        |d| d.target.device_number += 1,
        |d| d.target.serial.push('x'),
        |d| d.target.device_id = Some(StableDeviceId::from_naa128([0x60; 16]).unwrap()),
        |d| d.target.bus_type = 12,
        |d| d.target.geometry.physical_sector_size = 8192,
        |d| {
            d.target.geometry.size_bytes *= 2;
            d.layout = layout::plan(d.target.geometry.size_bytes, 512, false).unwrap();
        },
        |d| d.layout = layout::plan(d.target.geometry.size_bytes, 512, true).unwrap(),
        |d| d.sources[0].source_id = format!("src_{}", "3".repeat(64)),
        |d| d.sources[0].destination = "Windows/Other.iso".into(),
        |d| d.sources[0].bytes += 1,
        |d| d.sources[0].sha256[0] ^= 1,
        |d| d.sources.swap(0, 1),
        |d| d.configuration.bytes.push(b' '),
        |d| d.configuration.format = ConfigurationFormat::Toml,
        |d| d.payloads[0].role.push('2'),
        |d| d.payloads[0].bytes += 1,
        |d| d.payloads[0].sha256[0] ^= 1,
        |d| d.payloads.swap(0, 1),
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let mut changed = description();
        change(&mut changed);
        assert_ne!(
            PreparedJob::new(changed).unwrap().digest(),
            original,
            "mutation {index} must not reuse confirmation"
        );
    }
}

#[test]
fn variable_length_fields_do_not_have_concatenation_aliases() {
    let mut first = description();
    first.payloads[0].role = "a".into();
    first.payloads[1].role = "bc".into();
    let mut second = first.clone();
    second.payloads[0].role = "ab".into();
    second.payloads[1].role = "c".into();
    assert_ne!(
        PreparedJob::new(first).unwrap().digest(),
        PreparedJob::new(second).unwrap().digest()
    );
}

#[test]
fn changed_or_missing_confirmation_is_rejected_without_consuming_the_job() {
    let job = PreparedJob::new(description()).unwrap();
    let digest = job.digest();
    let target = job.target().clone();
    let challenge = job.challenge().to_owned();
    let mut pending = job.into_confirmation();
    let mut changed_digest = digest;
    changed_digest[0] ^= 1;
    assert!(matches!(
        pending.confirm(&changed_digest, &target, &challenge),
        Err(JobError::DigestMismatch)
    ));
    let mut changed_target = target.clone();
    changed_target.geometry.physical_sector_size *= 2;
    assert!(matches!(
        pending.confirm(&digest, &changed_target, &challenge),
        Err(JobError::TargetMismatch)
    ));
    for incorrect in [
        "",
        "USB-TEST-0001",
        "WIPE USB-TEST-0001 ",
        "WIPE usb-test-0001",
    ] {
        assert!(matches!(
            pending.confirm(&digest, &target, incorrect),
            Err(JobError::ChallengeMismatch)
        ));
    }
    let receipt = pending.confirm(&digest, &target, &challenge).unwrap();
    assert_eq!(receipt.description().digest(), digest);
    assert_eq!(receipt.description().target(), &target);
    assert!(matches!(
        pending.confirm(&digest, &target, &challenge),
        Err(JobError::AlreadyConfirmed)
    ));
}

#[test]
fn target_challenge_uses_full_serial_or_exact_supported_naa_identity() {
    let job = PreparedJob::new(description()).unwrap();
    assert_eq!(job.challenge(), "WIPE USB-TEST-0001");
    let mut input = description();
    input.target.serial.clear();
    input.target.device_id = Some(StableDeviceId::from_naa128([0x60; 16]).unwrap());
    let job = PreparedJob::new(input).unwrap();
    assert_eq!(job.challenge(), "WIPE NAA:60606060606060606060606060606060");
    let digest = job.digest();
    let target = job.target().clone();
    let challenge = job.challenge().to_owned();
    job.into_confirmation()
        .confirm(&digest, &target, &challenge)
        .unwrap();
}

#[test]
fn invalid_target_or_noncanonical_layout_cannot_be_described_as_prepared() {
    let changes: [fn(&mut JobDescription); 8] = [
        |d| d.target.serial.clear(),
        |d| d.target.device_number = u32::MAX,
        |d| d.target.geometry.logical_sector_size = 0,
        |d| d.target.geometry.size_bytes += 1,
        |d| d.target.geometry.size_bytes *= 2,
        |d| d.layout.partitions[0].end_lba += 1,
        |d| d.layout.partitions.swap(0, 1),
        |d| d.layout.partitions[0].name = "OTHER".into(),
    ];
    for change in changes {
        let mut input = description();
        change(&mut input);
        assert!(PreparedJob::new(input).is_err());
    }
}

#[test]
fn unsafe_or_ambiguous_destination_paths_are_rejected() {
    for destination in [
        "",
        "/boot.iso",
        "../boot.iso",
        "a/../boot.iso",
        "a/./boot.iso",
        "a//boot.iso",
        "C:/boot.iso",
        "a\\boot.iso",
        "boot.iso:stream",
        "a/boot.iso ",
        "a/boot.iso.",
        "a/CON.iso",
        "LPT1.iso",
        "COM¹.iso",
        "a/*.iso",
        "a/?iso",
        "a/\0.iso",
    ] {
        let mut input = description();
        input.sources[0].destination = destination.into();
        assert!(PreparedJob::new(input).is_err(), "{destination:?}");
    }
    for destination in [
        format!("{}.iso", "x".repeat(256)),
        format!("{}x.iso", "a/".repeat(33)),
    ] {
        let mut input = description();
        input.sources[0].destination = destination;
        assert!(PreparedJob::new(input).is_err());
    }
    for destination in [
        "windows/win11.ISO",
        "Windows/Win11.iso/child.iso",
        "Windows",
    ] {
        let mut input = description();
        input.sources[1].destination = destination.into();
        assert!(PreparedJob::new(input).is_err(), "{destination}");
    }
}

#[test]
fn invalid_ids_sizes_duplicate_roles_and_resource_limits_are_rejected() {
    let changes: [fn(&mut JobDescription); 12] = [
        |d| d.sources[0].source_id = "C:/source.iso".into(),
        |d| d.sources[1].source_id = d.sources[0].source_id.clone(),
        |d| d.sources[0].bytes = 0,
        |d| d.sources[0].bytes = u64::MAX,
        |d| d.sources[0].bytes = d.target.geometry.size_bytes,
        |d| d.payloads[0].bytes = 0,
        |d| d.payloads[0].bytes = u64::MAX,
        |d| d.payloads[0].bytes = d.target.geometry.size_bytes,
        |d| d.payloads[1].role = d.payloads[0].role.clone(),
        |d| d.payloads[0].role = "../launcher".into(),
        |d| d.configuration.bytes = vec![0; 1024 * 1024 + 1],
        |d| {
            d.sources.clear();
            d.payloads.clear();
        },
    ];
    for (index, change) in changes.into_iter().enumerate() {
        let mut input = description();
        change(&mut input);
        assert!(PreparedJob::new(input).is_err(), "mutation {index}");
    }
}

#[test]
fn complete_unique_sets_accept_limits_and_reject_the_next_item() {
    let mut input = description();
    input.sources = (0..128)
        .map(|n| SourceMetadata {
            source_id: format!("src_{n:064x}"),
            destination: format!("Images/{n}.iso"),
            bytes: 1,
            sha256: [1; 32],
        })
        .collect();
    input.payloads = (0..32)
        .map(|n| PayloadFingerprint {
            role: format!("payload_{n}"),
            bytes: 1,
            sha256: [2; 32],
        })
        .collect();
    input.configuration.bytes = vec![b' '; 1024 * 1024];
    PreparedJob::new(input.clone()).unwrap();

    let mut source_overflow = input.clone();
    source_overflow.sources.push(SourceMetadata {
        source_id: format!("src_{:064x}", 128),
        destination: "Images/128.iso".into(),
        bytes: 1,
        sha256: [1; 32],
    });
    assert!(PreparedJob::new(source_overflow).is_err());
    let mut payload_overflow = input.clone();
    payload_overflow.payloads.push(PayloadFingerprint {
        role: "payload_32".into(),
        bytes: 1,
        sha256: [2; 32],
    });
    assert!(PreparedJob::new(payload_overflow).is_err());
    input.configuration.bytes.push(b' ');
    assert!(PreparedJob::new(input).is_err());
}
