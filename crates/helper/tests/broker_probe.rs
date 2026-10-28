// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::{
    broker_probe::{ProbeArgs, ProbeReply, ProbeRequest, ProbeSession, check_pair, check_studio},
    windows_peer::{ElevationType, IntegrityLevel, PeerEvidence, Sid, TokenEvidence},
};

fn arguments() -> Vec<String> {
    [
        "--probe-broker-v1",
        "--pipe-nonce",
        &"ab".repeat(32),
        "--studio-pid",
        "42",
        "--studio-created",
        "12345",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}
fn peer(elevated: bool) -> PeerEvidence {
    PeerEvidence {
        process_id: if elevated { 43 } else { 42 },
        creation_time: 12345,
        token: TokenEvidence {
            user: Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]).unwrap(),
            logon: Sid::from_bytes(&[1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0])
                .unwrap(),
            session_id: 1,
            integrity: if elevated {
                IntegrityLevel::High
            } else {
                IntegrityLevel::Medium
            },
            elevated,
            elevation_type: if elevated {
                ElevationType::Full
            } else {
                ElevationType::Limited
            },
            is_app_container: false,
            token_id: if elevated { 8 } else { 7 },
            authentication_id: 6,
            modified_id: 5,
        },
    }
}

#[test]
fn probe_arguments_are_exact_bounded_public_identifiers() {
    let parsed = ProbeArgs::parse(&arguments()).unwrap();
    assert_eq!(parsed.studio_pid(), 42);
    assert_eq!(parsed.studio_created(), 12345);
    assert_eq!(parsed.nonce(), "ab".repeat(32));
    assert_eq!(parsed.launch_arguments(), arguments().join(" "));
    for index in 0..arguments().len() {
        let mut short = arguments();
        short.remove(index);
        assert!(ProbeArgs::parse(&short).is_err());
    }
    let mut extra = arguments();
    extra.push("--write".into());
    assert!(ProbeArgs::parse(&extra).is_err());
    for (index, values) in [
        (
            2,
            vec![
                "A".repeat(64),
                "a".repeat(63),
                "a".repeat(65),
                "../helper".into(),
            ],
        ),
        (
            4,
            vec![
                "0".into(),
                "4294967296".into(),
                "-1".into(),
                " 42".into(),
                "01".into(),
            ],
        ),
        (
            6,
            vec!["0".into(), "18446744073709551616".into(), "+1".into()],
        ),
    ] {
        for value in values {
            let mut args = arguments();
            args[index] = value;
            assert!(ProbeArgs::parse(&args).is_err());
        }
    }
}

#[test]
fn probe_round_trip_is_read_only_and_one_shot() {
    let mut session = ProbeSession::new(&"a1".repeat(32)).unwrap();
    let request = ProbeRequest::decode(&session.request().unwrap()).unwrap();
    let reply = ProbeReply::for_request(&request).encode().unwrap();
    let report = session.complete(&reply).unwrap();
    assert_eq!(report.protocol, 1);
    assert_eq!(report.helper_version, env!("CARGO_PKG_VERSION"));
    assert!(!report.physical_preparation);
    assert!(session.complete(&reply).is_err());
    assert!(session.request().is_err());
}

#[test]
fn invalid_reply_never_consumes_or_authorizes_a_probe() {
    let mut session = ProbeSession::new(&"a1".repeat(32)).unwrap();
    let request = ProbeRequest::decode(&session.request().unwrap()).unwrap();
    let reply = ProbeReply::for_request(&request).encode().unwrap();
    for (field, value) in [
        ("protocol", serde_json::json!(2)),
        ("purpose", serde_json::json!("write_plan")),
        ("nonce", serde_json::json!("b2".repeat(32))),
        ("physical_preparation", serde_json::json!(true)),
        ("helper_version", serde_json::json!("x".repeat(129))),
    ] {
        let mut altered: serde_json::Value = serde_json::from_slice(&reply).unwrap();
        altered[field] = value;
        assert!(
            session
                .complete(&serde_json::to_vec(&altered).unwrap())
                .is_err(),
            "{field}"
        );
        assert!(session.request().is_ok());
    }
    assert!(session.complete(&reply).is_ok());
}

#[test]
fn probe_messages_reject_unknown_duplicate_fields_and_disk_operations() {
    let session = ProbeSession::new(&"a1".repeat(32)).unwrap();
    let bytes = session.request().unwrap();
    let mut object: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    object["disk_id"] = serde_json::json!("PhysicalDrive0");
    assert!(ProbeRequest::decode(&serde_json::to_vec(&object).unwrap()).is_err());
    let duplicate = String::from_utf8(bytes)
        .unwrap()
        .replacen('{', "{\"protocol\":1,", 1);
    assert!(ProbeRequest::decode(duplicate.as_bytes()).is_err());
    assert!(
        ProbeRequest::decode(
            br#"{"sequence":0,"plan_hash":"x","disk_id":"x","operation":"write_plan"}"#
        )
        .is_err()
    );
    assert!(ProbeRequest::decode(&vec![b' '; 4097]).is_err());
    assert!(ProbeRequest::decode(&[]).is_err());
}

#[test]
fn role_policy_requires_same_user_logon_session_and_split_elevation() {
    let studio = peer(false);
    let helper = peer(true);
    check_pair(&studio, &helper).unwrap();
    // These per-token identifiers must not be confused with cross-process equality.
    let mut different_stamps = helper.clone();
    different_stamps.token.modified_id += 1;
    check_pair(&studio, &different_stamps).unwrap();
    let mut foreign = helper.clone();
    foreign.token.user = Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 22, 0, 0, 0]).unwrap();
    assert!(check_pair(&studio, &foreign).is_err());
    foreign = helper.clone();
    foreign.token.logon = studio.token.user.clone();
    assert!(check_pair(&studio, &foreign).is_err());
    foreign = helper.clone();
    foreign.token.session_id += 1;
    assert!(check_pair(&studio, &foreign).is_err());
    for integrity in [
        IntegrityLevel::Low,
        IntegrityLevel::Medium,
        IntegrityLevel::System,
    ] {
        foreign = helper.clone();
        foreign.token.integrity = integrity;
        assert!(check_pair(&studio, &foreign).is_err());
    }
    foreign = helper.clone();
    foreign.token.is_app_container = true;
    assert!(check_pair(&studio, &foreign).is_err());
    foreign = helper.clone();
    foreign.token.elevated = false;
    assert!(check_pair(&studio, &foreign).is_err());
    foreign = helper.clone();
    foreign.token.elevation_type = ElevationType::Default;
    assert!(check_pair(&studio, &foreign).is_err());
    assert!(check_pair(&studio, &studio).is_err());
    assert!(check_studio(&helper).is_err());
    let mut standard = studio.clone();
    standard.token.elevation_type = ElevationType::Default;
    assert!(check_studio(&standard).is_err());
    standard = studio.clone();
    standard.token.is_app_container = true;
    assert!(check_studio(&standard).is_err());
}
