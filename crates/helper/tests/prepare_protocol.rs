// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::prepare_protocol::*;

fn client(body: ClientMessage) -> ClientFrame {
    ClientFrame {
        version: VERSION,
        job_id: "ab".repeat(32),
        reply_to: 0,
        body,
    }
}

#[test]
fn prepare_launch_arguments_are_fixed_and_canonical() {
    let args = PrepareArgs::new(&"ab".repeat(32), 31, 987).unwrap();
    let words: Vec<_> = args
        .launch_arguments()
        .split(' ')
        .map(String::from)
        .collect();
    let roundtrip = PrepareArgs::parse(&words).unwrap();
    assert_eq!(roundtrip.studio_pid(), 31);
    assert_eq!(roundtrip.studio_created(), 987);
    assert_eq!(roundtrip.nonce(), "ab".repeat(32));
    let mut noncanonical = words;
    noncanonical[4] = "031".into();
    assert!(PrepareArgs::parse(&noncanonical).is_err());
    assert!(PrepareArgs::new(&"ab".repeat(32), 0, 987).is_err());
}
fn source(index: u16, path: &str) -> ClientMessage {
    ClientMessage::Source {
        index,
        source_id: format!("source-{index}"),
        relative_path: path.into(),
        bytes: 1024,
        sha256: "cd".repeat(32),
        remote_handle: 256,
    }
}

#[test]
fn bounded_strict_roundtrip_and_nested_source_paths() {
    let original = client(source(0, "Windows/Install/Win11.iso"));
    assert_eq!(
        ClientFrame::decode(&original.encode().unwrap()).unwrap(),
        original
    );
    let mut value = serde_json::to_value(&original).unwrap();
    value["body"]["extra"] = true.into();
    assert!(ClientFrame::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut value = serde_json::to_value(&original).unwrap();
    value["extra"] = true.into();
    assert!(ClientFrame::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(ClientFrame::decode(&vec![b' '; 65_537]).is_err());
    assert!(ClientFrame::decode(b"").is_err());
}

#[test]
fn malformed_nonce_handle_source_and_version_are_rejected() {
    for body in [
        source(128, "a.iso"),
        source(0, "../a.iso"),
        source(0, "Windows/CON.iso"),
        ClientMessage::Begin {
            target_selector: "x".into(),
            source_count: 0,
        },
        ClientMessage::Archive {
            remote_handle: u64::MAX,
            bytes: 1,
            sha256: "cd".repeat(32),
        },
    ] {
        assert!(client(body).encode().is_err());
    }
    let mut message = client(ClientMessage::Continue);
    message.version = 2;
    assert!(message.encode().is_err());
    message.version = VERSION;
    message.job_id = "AB".repeat(32);
    assert!(message.encode().is_err());
}

#[test]
fn exchange_checks_nonce_sequence_and_exact_reply_kind() {
    let request = ServerFrame {
        version: VERSION,
        job_id: "ab".repeat(32),
        sequence: 3,
        body: ServerMessage::NeedSource { index: 1 },
    };
    let mut reply = client(source(1, "Linux/boot.iso"));
    reply.reply_to = 3;
    assert!(request.validate_reply(&reply).is_ok());
    reply.reply_to = 2;
    assert!(request.validate_reply(&reply).is_err());
    reply.reply_to = 3;
    reply.job_id = "cd".repeat(32);
    assert!(request.validate_reply(&reply).is_err());
    reply.job_id = request.job_id.clone();
    reply.body = source(0, "Linux/boot.iso");
    assert!(request.validate_reply(&reply).is_err());
    reply.body = ClientMessage::Confirm {
        description_digest: "cd".repeat(32),
        challenge: "WIPE serial".into(),
    };
    assert!(request.validate_reply(&reply).is_err());
    reply.body = ClientMessage::Cancel;
    assert!(request.validate_reply(&reply).is_ok());
}

#[test]
fn source_collection_rejects_duplicate_ids_paths_and_wrong_order() {
    let mut sources = SourceList::new(2).unwrap();
    sources.push(&source(0, "Windows/Win11.iso")).unwrap();
    assert!(sources.push(&source(0, "Mac/MacOS.img")).is_err());
    assert!(sources.push(&source(1, "windows/win11.ISO")).is_err());
    assert!(sources.finish().is_err());
    sources.push(&source(1, "Mac/MacOS.img")).unwrap();
    assert!(sources.finish().is_ok());
    assert!(sources.push(&source(2, "other.iso")).is_err());
}

#[test]
fn prepared_requires_closed_sources_and_complete_target_facts() {
    let target = TargetSummary {
        device_number: 2,
        serial: "USB123".into(),
        device_id: None,
        bus_type: 7,
        size_bytes: 1024 * 1024 * 1024,
        logical_sector_size: 512,
        physical_sector_size: 4096,
    };
    let mut frame = ServerFrame {
        version: VERSION,
        job_id: "ab".repeat(32),
        sequence: 4,
        body: ServerMessage::Prepared {
            target,
            image_bytes: 1024 * 1024 * 1024,
            image_sha256: "cd".repeat(32),
            description_digest: "ef".repeat(32),
            challenge: "WIPE USB123".into(),
            source_count: 2,
            original_handles_closed: true,
        },
    };
    assert!(frame.encode().is_ok());
    if let ServerMessage::Prepared {
        original_handles_closed,
        ..
    } = &mut frame.body
    {
        *original_handles_closed = false;
    }
    assert!(frame.encode().is_err());
}

#[test]
fn terminal_and_progress_counts_cannot_claim_contradictory_success() {
    let mut frame = ServerFrame {
        version: VERSION,
        job_id: "ab".repeat(32),
        sequence: 9,
        body: ServerMessage::Terminal {
            outcome: Outcome::Succeeded,
            phase: Phase::Complete,
            message: "Verified".into(),
            bytes_written: 512,
            bytes_verified: 511,
            target_may_be_incomplete: false,
            sha256: Some("cd".repeat(32)),
        },
    };
    assert!(frame.encode().is_err());
    frame.body = ServerMessage::Progress {
        phase: Phase::WritingTarget,
        completed_bytes: 513,
        total_bytes: 512,
        file_index: None,
    };
    assert!(frame.encode().is_err());
}
