// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_inventory::{
    CommandOutput, CommandRunner, InventoryError,
    windows_pools::{self, Membership, PoolObservation},
};
use serde_json::{Value, json};
use std::{cell::RefCell, io};

struct MockRunner(RefCell<Option<io::Result<CommandOutput>>>);
impl MockRunner {
    fn bytes(stdout: Vec<u8>) -> Self {
        Self(RefCell::new(Some(Ok(CommandOutput {
            success: true,
            stdout,
            stderr: vec![],
        }))))
    }
    fn json(value: Value) -> Self {
        Self::bytes(serde_json::to_vec(&value).unwrap())
    }
}
impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        assert_eq!(program, "powershell.exe");
        assert_eq!(args.len(), 5);
        assert_eq!(
            &args[..4],
            &["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
        );
        self.0
            .borrow_mut()
            .take()
            .expect("exactly one read-only query")
    }
}
fn pool(id: &str, primordial: bool) -> Value {
    json!({"ObjectId":format!("pool-object-{id}"),"UniqueId":format!("pool-unique-{id}"),"FriendlyName":"Pool","IsPrimordial":primordial})
}
fn disk(id: usize, pools: Vec<Value>) -> Value {
    json!({"ObjectId":format!("disk-object-{id}"),"UniqueId":format!("disk-unique-{id}"),"UniqueIdFormat":3,"DeviceId":format!("provider-device-{id}"),"SerialNumber":"SERIAL","BusType":7,"Size":64_000_000_000u64,"CanPool":false,"IsPartial":false,"Pools":pools})
}
fn input(disks: Vec<Value>) -> Value {
    json!({"schema_version":1,"query_complete":true,"physical_disks":disks})
}
fn observe(value: Value) -> Result<PoolObservation, InventoryError> {
    windows_pools::collect_with(&MockRunner::json(value))
}

#[test]
fn usb_and_can_pool_do_not_override_concrete_membership() {
    for can_pool in [json!(false), json!(true), Value::Null] {
        let mut d = disk(1, vec![pool("primordial", true), pool("concrete", false)]);
        d["CanPool"] = can_pool;
        let result = observe(input(vec![d])).unwrap();
        assert_eq!(result.source, "windows_storage_cim");
        let d = &result.physical_disks[0];
        assert_eq!(d.membership(), Membership::NonPrimordial);
        assert_eq!(d.primordial_pools[0].unique_id, "pool-unique-primordial");
        assert_eq!(d.nonprimordial_pools[0].unique_id, "pool-unique-concrete");
        assert_eq!(d.bus_type, Some(7));
        assert_eq!(d.device_id.as_deref(), Some("provider-device-1"));
    }
}

#[test]
fn absent_and_primordial_only_associations_remain_distinct_observations() {
    let result = observe(input(vec![
        disk(1, vec![]),
        disk(2, vec![pool("primordial", true)]),
    ]))
    .unwrap();
    assert_eq!(
        result.physical_disks[0].membership(),
        Membership::NoAssociationObserved
    );
    assert_eq!(
        result.physical_disks[1].membership(),
        Membership::PrimordialOnly
    );
    assert!(observe(input(vec![])).unwrap().physical_disks.is_empty());
}

#[test]
fn nullable_metadata_is_retained_without_filling_in_defaults() {
    let mut d = disk(1, vec![]);
    for field in [
        "UniqueIdFormat",
        "DeviceId",
        "SerialNumber",
        "BusType",
        "Size",
        "CanPool",
        "IsPartial",
    ] {
        d[field] = Value::Null;
    }
    let result = observe(input(vec![d])).unwrap();
    let d = &result.physical_disks[0];
    assert_eq!(d.unique_id_format, None);
    assert_eq!(d.device_id, None);
    assert_eq!(d.serial_number, None);
    assert_eq!(d.bus_type, None);
    assert_eq!(d.size_bytes, None);
    assert_eq!(d.can_pool, None);
    assert_eq!(d.is_partial, None);
}

#[test]
fn missing_fields_and_incomplete_queries_fail_closed() {
    for field in ["schema_version", "query_complete", "physical_disks"] {
        let mut value = input(vec![]);
        value.as_object_mut().unwrap().remove(field);
        assert!(observe(value).is_err(), "missing {field}");
    }
    for field in [
        "ObjectId",
        "UniqueId",
        "UniqueIdFormat",
        "DeviceId",
        "SerialNumber",
        "BusType",
        "Size",
        "CanPool",
        "IsPartial",
        "Pools",
    ] {
        let mut d = disk(1, vec![]);
        d.as_object_mut().unwrap().remove(field);
        assert!(observe(input(vec![d])).is_err(), "missing {field}");
    }
    for field in ["ObjectId", "UniqueId", "FriendlyName", "IsPrimordial"] {
        let mut p = pool("a", false);
        p.as_object_mut().unwrap().remove(field);
        assert!(
            observe(input(vec![disk(1, vec![p])])).is_err(),
            "missing pool {field}"
        );
    }
    let mut value = input(vec![]);
    value["query_complete"] = json!(false);
    assert!(observe(value).is_err());
    let mut value = input(vec![]);
    value["schema_version"] = json!(2);
    assert!(observe(value).is_err());
}

#[test]
fn wrong_types_overflow_and_unknown_fields_are_rejected() {
    for (field, bad) in [
        ("ObjectId", Value::Null),
        ("UniqueId", json!(1)),
        ("UniqueIdFormat", json!(65536)),
        ("DeviceId", json!(3)),
        ("BusType", json!("USB")),
        ("Size", json!(-1)),
        ("Size", json!(1.5)),
        ("CanPool", json!("False")),
        ("IsPartial", json!(0)),
        ("Pools", Value::Null),
    ] {
        let mut d = disk(1, vec![]);
        d[field] = bad;
        assert!(observe(input(vec![d])).is_err(), "bad {field}");
    }
    let mut p = pool("a", false);
    p["IsPrimordial"] = Value::Null;
    assert!(observe(input(vec![disk(1, vec![p])])).is_err());
    let mut value = input(vec![]);
    value["extra"] = json!(true);
    assert!(observe(value).is_err());
    let mut d = disk(1, vec![]);
    d["extra"] = json!(true);
    assert!(observe(input(vec![d])).is_err());
    let mut p = pool("a", false);
    p["extra"] = json!(true);
    assert!(observe(input(vec![disk(1, vec![p])])).is_err());
}

#[test]
fn duplicate_json_keys_are_rejected_before_values_can_hide_each_other() {
    let raw =
        br#"{"schema_version":1,"query_complete":false,"query_complete":true,"physical_disks":[]}"#;
    assert!(windows_pools::collect_with(&MockRunner::bytes(raw.to_vec())).is_err());
    let raw = serde_json::to_string(&input(vec![disk(1, vec![pool("a", false)])])).unwrap();
    for (key, value) in [("ObjectId", "\"shadow\""), ("IsPrimordial", "true")] {
        let raw = raw.replacen(
            &format!("\"{key}\":"),
            &format!("\"{key}\":{value},\"{key}\":"),
            1,
        );
        assert!(windows_pools::collect_with(&MockRunner::bytes(raw.into_bytes())).is_err());
    }
}

#[test]
fn duplicate_physical_identities_are_ambiguous() {
    for field in ["ObjectId", "UniqueId"] {
        let a = disk(1, vec![]);
        let mut b = disk(2, vec![]);
        b[field] = a[field].clone();
        assert!(observe(input(vec![a, b])).is_err(), "duplicate {field}");
    }
    // Shared display metadata is not a physical identity.
    let mut a = disk(1, vec![]);
    let mut b = disk(2, vec![]);
    a["DeviceId"] = json!("0");
    b["DeviceId"] = json!("0");
    assert_eq!(observe(input(vec![a, b])).unwrap().physical_disks.len(), 2);
}

#[test]
fn shared_pool_is_valid_but_duplicate_and_conflicting_pool_records_are_not() {
    let p = pool("shared", false);
    assert_eq!(
        observe(input(vec![
            disk(1, vec![p.clone()]),
            disk(2, vec![p.clone()])
        ]))
        .unwrap()
        .physical_disks
        .len(),
        2
    );
    assert!(observe(input(vec![disk(1, vec![p.clone(), p.clone()])])).is_err());
    for field in ["ObjectId", "UniqueId", "FriendlyName", "IsPrimordial"] {
        let mut conflict = p.clone();
        conflict[field] = if field == "IsPrimordial" {
            json!(true)
        } else {
            json!("conflict")
        };
        assert!(
            observe(input(vec![
                disk(1, vec![p.clone()]),
                disk(2, vec![conflict])
            ]))
            .is_err(),
            "conflicting {field}"
        );
    }
}

#[test]
fn object_identity_cannot_alias_between_pool_and_physical_disk() {
    for field in ["ObjectId", "UniqueId"] {
        let mut p = pool("a", false);
        let d = disk(2, vec![]);
        p[field] = d[field].clone();
        assert!(observe(input(vec![disk(1, vec![p]), d])).is_err());
    }
}

#[test]
fn identity_and_label_strings_are_bounded_and_control_free() {
    for field in ["ObjectId", "UniqueId"] {
        for bad in [
            "".to_string(),
            " ".to_string(),
            "bad\nvalue".to_string(),
            "x".repeat(4097),
        ] {
            let mut d = disk(1, vec![]);
            d[field] = json!(bad);
            assert!(observe(input(vec![d])).is_err(), "bad {field}");
        }
    }
    for field in ["SerialNumber", "DeviceId"] {
        let mut d = disk(1, vec![]);
        d[field] = json!("x".repeat(4097));
        assert!(observe(input(vec![d])).is_err());
    }
    let mut p = pool("a", false);
    p["FriendlyName"] = json!("bad\u{001b}name");
    assert!(observe(input(vec![disk(1, vec![p])])).is_err());
}

#[test]
fn count_and_output_bounds_do_not_silently_truncate() {
    let disks = (0..256).map(|n| disk(n, vec![])).collect::<Vec<_>>();
    assert_eq!(
        observe(input(disks.clone())).unwrap().physical_disks.len(),
        256
    );
    let mut excessive = disks;
    excessive.push(disk(256, vec![]));
    assert!(observe(input(excessive)).is_err());
    let pools = (0..64)
        .map(|n| pool(&n.to_string(), false))
        .collect::<Vec<_>>();
    assert_eq!(
        observe(input(vec![disk(1, pools.clone())]))
            .unwrap()
            .physical_disks[0]
            .nonprimordial_pools
            .len(),
        64
    );
    let mut excessive = pools.clone();
    excessive.push(pool("64", false));
    assert!(observe(input(vec![disk(1, excessive)])).is_err());
    assert!(observe(input((0..65).map(|n| disk(n, pools.clone())).collect())).is_err());
    assert!(
        windows_pools::collect_with(&MockRunner::bytes(vec![b' '; 2 * 1024 * 1024 + 1])).is_err()
    );
}

#[test]
fn failed_or_polluted_commands_never_expose_partial_records_or_stderr() {
    for (success, stderr) in [
        (false, b"private provider details".to_vec()),
        (true, b"private warning".to_vec()),
    ] {
        let runner = MockRunner(RefCell::new(Some(Ok(CommandOutput {
            success,
            stdout: serde_json::to_vec(&input(vec![disk(1, vec![])])).unwrap(),
            stderr,
        }))));
        let error = windows_pools::collect_with(&runner)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("private"));
    }
    let runner = MockRunner(RefCell::new(Some(Err(io::Error::other(
        "private launch detail",
    )))));
    assert!(
        !windows_pools::collect_with(&runner)
            .unwrap_err()
            .to_string()
            .contains("private")
    );
    let mut d = disk(1, vec![]);
    d["CanPool"] = json!("private invalid value");
    assert!(
        !observe(input(vec![d]))
            .unwrap_err()
            .to_string()
            .contains("private")
    );
    assert!(windows_pools::collect_with(&MockRunner::bytes(b"not-json".to_vec())).is_err());
    assert!(windows_pools::collect_with(&MockRunner::bytes(vec![255])).is_err());
}

#[cfg(windows)]
#[test]
#[ignore = "read-only native Storage Management provider smoke test; requires Windows"]
fn windows_storage_pool_observation_smoke() {
    let observation =
        windows_pools::collect().expect("complete read-only Storage Management query");
    println!(
        "Observed {} physical disks; {} have concrete pool associations",
        observation.physical_disks.len(),
        observation
            .physical_disks
            .iter()
            .filter(|d| d.membership() == Membership::NonPrimordial)
            .count()
    );
}
