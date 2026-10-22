// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::{Operation, Request, Session};
fn request() -> Request {
    Request {
        sequence: 0,
        plan_hash: "a".repeat(64),
        disk_id: "usb-1".into(),
        operation: Operation::WritePlan,
    }
}
#[test]
fn capabilities_are_bound_and_cannot_be_replayed() {
    let key = [7u8; 32];
    let mut session = Session::new(key, "usb-1".into(), "a".repeat(64)).unwrap();
    let r = request();
    let tag = session.sign(&r).unwrap();
    assert!(session.accept(&r, &tag).is_ok());
    assert!(session.accept(&r, &tag).is_err());
}
#[test]
fn changes_and_wrong_client_auth_fail_without_consuming_nonce() {
    let mut s = Session::new([7; 32], "usb-1".into(), "a".repeat(64)).unwrap();
    let good = request();
    let tag = s.sign(&good).unwrap();
    let mut bad = good.clone();
    bad.disk_id = "internal".into();
    assert!(s.accept(&bad, &tag).is_err());
    bad = good.clone();
    bad.plan_hash = "b".repeat(64);
    assert!(s.accept(&bad, &tag).is_err());
    bad = good.clone();
    bad.operation = Operation::Eject;
    assert!(s.accept(&bad, &tag).is_err());
    assert!(s.accept(&good, &[0; 32]).is_err());
    assert!(s.accept(&good, &tag).is_ok());
}
#[test]
fn invalid_job_setup_is_refused() {
    assert!(Session::new([0; 32], "usb-1".into(), "a".repeat(64)).is_err());
    assert!(Session::new([1; 32], "".into(), "a".repeat(64)).is_err());
    assert!(Session::new([1; 32], "usb".into(), "not a hash".into()).is_err());
}

#[test]
fn protocol_frames_reject_oversized_duplicate_and_unknown_fields() {
    let encoded = serde_json::to_vec(&request()).unwrap();
    assert!(isohopper_helper::decode_frame(&encoded).is_ok());
    assert!(isohopper_helper::decode_frame(&vec![b' '; 65_537]).is_err());
    for encoded in [
        r#"{"sequence":0,"sequence":1,"plan_hash":"a","disk_id":"usb","operation":"write_plan"}"#,
        r#"{"sequence":0,"plan_hash":"a","disk_id":"usb","operation":"write_plan","shell":"ignored"}"#,
        r#"{"sequence":0,"plan_hash":"a","disk_id":"usb","operation":"arbitrary_write"}"#,
        r#"{"sequence":-1,"plan_hash":"a","disk_id":"usb","operation":"write_plan"}"#,
    ] {
        assert!(isohopper_helper::decode_frame(encoded.as_bytes()).is_err());
    }
}
