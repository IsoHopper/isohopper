// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_inventory::{
    CommandOutput, CommandRunner,
    windows_encryption::{
        self, ConversionStatus, EncryptionMethod, LockStatus, ProtectionStatus, ProviderStatus,
    },
};
use serde_json::{Value, json};
use std::{cell::RefCell, io};

const GUID: &str = r"\\?\Volume{01234567-89AB-CDEF-0123-456789ABCDEF}\";

#[cfg(not(target_os = "windows"))]
#[test]
fn native_collection_is_explicitly_unsupported_off_windows() {
    assert!(matches!(
        windows_encryption::collect(),
        Err(isohopper_inventory::InventoryError::Unsupported(_))
    ));
}

struct MockRunner(RefCell<Option<io::Result<CommandOutput>>>);
impl MockRunner {
    fn output(stdout: Vec<u8>) -> Self {
        Self(RefCell::new(Some(Ok(CommandOutput {
            success: true,
            stdout,
            stderr: vec![],
        }))))
    }
    fn json(value: Value) -> Self {
        Self::output(serde_json::to_vec(&value).unwrap())
    }
}
impl CommandRunner for MockRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        assert_eq!(program, "powershell.exe");
        assert_eq!(
            &args[..4],
            &["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
        );
        assert_eq!(args.len(), 5);
        self.0.borrow_mut().take().expect("one bounded query")
    }
}
fn method(status: u32) -> Value {
    json!({"return_code":0,"status":status})
}
fn volume() -> Value {
    json!({"device_id":GUID,
        "conversion":{"return_code":0,"status":0,"percentage":0},
        "protection":method(0),"lock":method(0),"encryption_method":method(0)})
}
fn report(volumes: Vec<Value>) -> Value {
    json!({"provider":"available","volumes":volumes})
}

#[test]
fn conversion_protection_and_encryption_method_remain_independent() {
    let unencrypted =
        windows_encryption::collect_with(&MockRunner::json(report(vec![volume()]))).unwrap();
    let item = &unencrypted.volumes[0];
    assert_eq!(
        item.device_id,
        GUID.replace("89AB-CDEF", "89ab-cdef")
            .replace("ABCDEF", "abcdef")
    );
    assert_eq!(item.conversion.return_code, Some(0));
    assert_eq!(
        item.conversion.value,
        Some(ConversionStatus::FullyDecrypted)
    );
    assert_eq!(item.protection.value, Some(ProtectionStatus::Off));
    assert_eq!(item.lock.value, Some(LockStatus::Unlocked));
    assert_eq!(item.encryption_method.value, Some(EncryptionMethod::None));

    let mut suspended = volume();
    suspended["conversion"]["status"] = json!(1);
    suspended["conversion"]["percentage"] = json!(100);
    suspended["encryption_method"] = method(7);
    let result =
        windows_encryption::collect_with(&MockRunner::json(report(vec![suspended]))).unwrap();
    assert_eq!(
        result.volumes[0].conversion.value,
        Some(ConversionStatus::FullyEncrypted)
    );
    assert_eq!(
        result.volumes[0].protection.value,
        Some(ProtectionStatus::Off)
    );
    assert_eq!(
        result.volumes[0].encryption_method.value,
        Some(EncryptionMethod::XtsAes256)
    );

    let mut hardware = volume();
    hardware["encryption_method"] = method(5);
    let result =
        windows_encryption::collect_with(&MockRunner::json(report(vec![hardware]))).unwrap();
    assert_eq!(
        result.volumes[0].conversion.value,
        Some(ConversionStatus::FullyDecrypted)
    );
    assert_eq!(
        result.volumes[0].encryption_method.value,
        Some(EncryptionMethod::Hardware)
    );
}

#[test]
fn failed_or_missing_methods_cannot_supply_a_known_state() {
    let mut value = volume();
    value["conversion"] = json!({"return_code":2150694912u32,"status":0,"percentage":0});
    value["protection"] = json!({"return_code":null,"status":0});
    value["lock"] = json!({"return_code":0,"status":null});
    value.as_object_mut().unwrap().remove("encryption_method");
    let result = windows_encryption::collect_with(&MockRunner::json(report(vec![value]))).unwrap();
    let item = &result.volumes[0];
    assert_eq!(item.conversion.return_code, Some(2150694912));
    assert_eq!(item.conversion.value, None);
    assert_eq!(item.encryption_percentage, None);
    assert_eq!(item.protection.value, None);
    assert_eq!(item.lock.value, None);
    assert_eq!(item.encryption_method.value, None);
}

#[test]
fn empty_and_unavailable_provider_do_not_create_volume_records() {
    for (name, expected) in [
        ("available", ProviderStatus::Available),
        ("missing_namespace", ProviderStatus::MissingNamespace),
        ("missing_class", ProviderStatus::MissingClass),
    ] {
        let result = windows_encryption::collect_with(&MockRunner::json(
            json!({"provider":name,"volumes":[]}),
        ))
        .unwrap();
        assert_eq!(result.provider, expected);
        assert!(result.volumes.is_empty());
    }
    assert!(
        windows_encryption::collect_with(&MockRunner::json(
            json!({"provider":"missing_class","volumes":[volume()]})
        ))
        .is_err()
    );
    assert!(
        windows_encryption::collect_with(&MockRunner::json(
            json!({"provider":"access_denied","volumes":[]})
        ))
        .is_err()
    );
}

#[test]
fn malformed_guids_duplicates_and_unknown_fields_are_rejected() {
    for id in [
        "",
        r"C:\",
        r"\\server\share",
        r"\\?\volume{01234567-89ab-cdef-0123-456789abcdef}\",
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdeg}\",
        r"\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\file",
    ] {
        let mut bad = volume();
        bad["device_id"] = json!(id);
        assert!(windows_encryption::collect_with(&MockRunner::json(report(vec![bad]))).is_err());
    }
    let mut duplicate = volume();
    duplicate["device_id"] = json!(GUID.to_ascii_lowercase().replacen("volume", "Volume", 1));
    assert!(
        windows_encryption::collect_with(&MockRunner::json(report(vec![volume(), duplicate])))
            .is_err()
    );
    let mut bad = volume();
    bad["unexpected"] = json!(true);
    assert!(windows_encryption::collect_with(&MockRunner::json(report(vec![bad]))).is_err());
    let bytes = br#"{"provider":"available","provider":"missing_class","volumes":[]}"#.to_vec();
    assert!(windows_encryption::collect_with(&MockRunner::output(bytes)).is_err());
}

#[test]
fn successful_methods_validate_documented_enums_and_percentage_bounds() {
    for (field, invalid) in [
        ("conversion", 6),
        ("protection", 3),
        ("lock", 2),
        ("encryption_method", 8),
    ] {
        let mut bad = volume();
        bad[field]["status"] = json!(invalid);
        assert!(windows_encryption::collect_with(&MockRunner::json(report(vec![bad]))).is_err());
    }
    let mut value = volume();
    value["protection"] = method(2);
    value["encryption_method"] = method(u32::MAX);
    let result = windows_encryption::collect_with(&MockRunner::json(report(vec![value]))).unwrap();
    assert_eq!(
        result.volumes[0].protection.value,
        Some(ProtectionStatus::Unknown)
    );
    assert_eq!(
        result.volumes[0].encryption_method.value,
        Some(EncryptionMethod::Unknown)
    );
    for percentage in [101, u32::MAX] {
        let mut bad = volume();
        bad["conversion"]["percentage"] = json!(percentage);
        assert!(windows_encryption::collect_with(&MockRunner::json(report(vec![bad]))).is_err());
    }
}

#[test]
fn partial_and_paused_conversion_is_not_inferred_from_rounded_percentage() {
    for (status, expected) in [
        (2, ConversionStatus::EncryptionInProgress),
        (3, ConversionStatus::DecryptionInProgress),
        (4, ConversionStatus::EncryptionPaused),
        (5, ConversionStatus::DecryptionPaused),
    ] {
        for percentage in [0, 100] {
            let mut value = volume();
            value["conversion"]["status"] = json!(status);
            value["conversion"]["percentage"] = json!(percentage);
            let result =
                windows_encryption::collect_with(&MockRunner::json(report(vec![value]))).unwrap();
            assert_eq!(result.volumes[0].conversion.value, Some(expected));
            assert_eq!(result.volumes[0].encryption_percentage, Some(percentage));
        }
    }
}

#[test]
fn volume_count_limit_accepts_exactly_256_distinct_records_and_rejects_257() {
    let mut records: Vec<_> = (0..256)
        .map(|index| {
            let mut value = volume();
            value["device_id"] = json!(format!(
                r"\\?\Volume{{{index:08x}-89ab-cdef-0123-456789abcdef}}\"
            ));
            value
        })
        .collect();
    records.reverse();
    let result =
        windows_encryption::collect_with(&MockRunner::json(report(records.clone()))).unwrap();
    assert_eq!(result.volumes.len(), 256);
    assert!(
        result
            .volumes
            .windows(2)
            .all(|pair| pair[0].device_id < pair[1].device_id)
    );
    records.push(volume());
    let error = windows_encryption::collect_with(&MockRunner::json(report(records))).unwrap_err();
    assert!(error.to_string().contains("more than 256 volume records"));
}

#[test]
fn duplicate_method_fields_and_invalid_json_never_supply_evidence() {
    let raw = serde_json::to_string(&report(vec![volume()])).unwrap();
    let duplicated = raw.replacen(
        "\"return_code\":0",
        "\"return_code\":0,\"return_code\":1",
        1,
    );
    for bytes in [
        duplicated.into_bytes(),
        b"null".to_vec(),
        vec![0xff],
        b"{}".to_vec(),
    ] {
        assert!(windows_encryption::collect_with(&MockRunner::output(bytes)).is_err());
    }
    let mut failed = volume();
    for field in ["conversion", "protection", "lock", "encryption_method"] {
        failed[field]["return_code"] = json!(u32::MAX);
        failed[field]["status"] = json!(u32::MAX);
    }
    let result = windows_encryption::collect_with(&MockRunner::json(report(vec![failed]))).unwrap();
    let item = &result.volumes[0];
    assert_eq!(item.conversion.value, None);
    assert_eq!(item.protection.value, None);
    assert_eq!(item.lock.value, None);
    assert_eq!(item.encryption_method.value, None);
    assert_eq!(item.encryption_method.return_code, Some(u32::MAX));
}

#[test]
fn wrong_json_types_excessive_output_and_command_errors_are_rejected() {
    for value in [
        json!("0"),
        json!(false),
        json!(-1),
        json!(0.0),
        json!(4294967296u64),
    ] {
        for field in ["return_code", "status"] {
            let mut bad = volume();
            bad["lock"][field] = value.clone();
            assert!(
                windows_encryption::collect_with(&MockRunner::json(report(vec![bad]))).is_err()
            );
        }
    }
    assert!(
        windows_encryption::collect_with(&MockRunner::json(report(vec![volume(); 257]))).is_err()
    );
    assert!(
        windows_encryption::collect_with(&MockRunner::output(vec![b' '; 256 * 1024 + 1])).is_err()
    );
    for (success, stderr) in [
        (false, vec![]),
        (true, b"error".to_vec()),
        (true, vec![b'x'; 256 * 1024 + 1]),
    ] {
        let runner = MockRunner(RefCell::new(Some(Ok(CommandOutput {
            success,
            stderr,
            stdout: serde_json::to_vec(&report(vec![])).unwrap(),
        }))));
        assert!(windows_encryption::collect_with(&runner).is_err());
    }
    let runner = MockRunner(RefCell::new(Some(Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "test timeout",
    )))));
    assert!(windows_encryption::collect_with(&runner).is_err());
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "read-only query of the host BitLocker provider; requires Windows CIM access"]
fn native_windows_encryption_observes_or_reports_missing_provider() {
    let result =
        windows_encryption::collect().expect("query failure is not evidence of no encryption");
    match result.provider {
        ProviderStatus::Available => println!(
            "BitLocker provider observed {} volumes; no write authorization",
            result.volumes.len()
        ),
        ProviderStatus::MissingNamespace | ProviderStatus::MissingClass => {
            assert!(result.volumes.is_empty());
            println!(
                "BitLocker provider unavailable: {:?}; encryption state unknown",
                result.provider
            );
        }
    }
}
