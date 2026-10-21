// SPDX-License-Identifier: GPL-3.0-or-later
use ed25519_dalek::{Signer, SigningKey};
use isohopper_media::{MediaError, manifest};

fn payload(id: &str, url: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"schema_version":1,"artifacts":[{"id":id,"version":"1.0.0","architecture":"x86_64","url":url,"sha256":"ab".repeat(32)}]})).unwrap()
}

fn verify(data: &[u8]) -> Result<manifest::VerifiedManifest, MediaError> {
    let key = SigningKey::from_bytes(&[7; 32]);
    manifest::verify(
        data,
        &key.sign(data).to_bytes(),
        key.verifying_key().as_bytes(),
    )
}

#[test]
fn valid_signature_yields_verified_artifacts_with_no_embedded_release_key() {
    for (id, url) in [
        ("netboot-xyz", "https://boot.netboot.xyz/netboot.xyz.efi"),
        (
            "memtest86plus",
            "https://memtest.org/download/v9.00/memtest.efi",
        ),
    ] {
        let manifest = verify(&payload(id, url)).unwrap();
        assert_eq!(manifest.artifacts()[0].id(), id);
        assert_eq!(manifest.artifacts()[0].url(), url);
        assert_eq!(manifest.artifacts()[0].sha256(), "ab".repeat(32));
    }
}

#[test]
fn authentication_precedes_json_and_url_interpretation() {
    let key = SigningKey::from_bytes(&[7; 32]);
    assert!(matches!(
        manifest::verify(b"not even json", &[0; 64], key.verifying_key().as_bytes()),
        Err(MediaError::Signature)
    ));
    let original = payload("netboot-xyz", "https://boot.netboot.xyz/netboot.xyz.efi");
    let signature = key.sign(&original).to_bytes();
    let mut changed = original.clone();
    changed.push(b' ');
    assert!(matches!(
        manifest::verify(&changed, &signature, key.verifying_key().as_bytes()),
        Err(MediaError::Signature)
    ));
    let other_key = SigningKey::from_bytes(&[8; 32]);
    assert!(matches!(
        manifest::verify(&original, &signature, other_key.verifying_key().as_bytes()),
        Err(MediaError::Signature)
    ));
    assert!(matches!(
        manifest::verify(&original, &[0; 64], &[0; 32]),
        Err(MediaError::Signature)
    ));
}

#[test]
fn signed_malicious_urls_are_rejected_by_per_artifact_allowlist() {
    for url in [
        "http://boot.netboot.xyz/x",
        "https://boot.netboot.xyz.evil.test/x",
        "https://boot.netboot.xyz@evil.test/x",
        "https://evil.test@boot.netboot.xyz/x",
        "https://boot.netboot.xyz:444/x",
        "https://boot.netboot.xyz/x#fragment",
        "https://boot.netboot.xyz/x?redirect=evil",
        "https://boot.netboot.xyz\\@evil.test/x",
        "https://127.0.0.1/x",
        "https://memtest.org/x",
        " https://boot.netboot.xyz/x",
        "https://boot.netboot.xyz./x",
    ] {
        assert!(
            verify(&payload("netboot-xyz", url)).is_err(),
            "accepted {url}"
        );
    }
}

#[test]
fn signed_schema_ambiguity_and_invalid_hashes_are_rejected() {
    let original = String::from_utf8(payload(
        "netboot-xyz",
        "https://boot.netboot.xyz/netboot.xyz.efi",
    ))
    .unwrap();
    for bad in [
        original.replace(&"ab".repeat(32), "bad"),
        original.replace("\"schema_version\":1", "\"schema_version\":2"),
        original.replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        ),
        original.replace("\"id\":\"netboot-xyz\"", "\"id\":\"unknown\""),
        original.replace("\"version\":\"1.0.0\"", "\"version\":\"../evil\""),
    ] {
        assert!(verify(bad.as_bytes()).is_err(), "accepted {bad}");
    }
    assert!(verify(&vec![b'x'; manifest::MAX_MANIFEST_BYTES + 1]).is_err());
}

#[test]
fn signed_duplicate_artifact_identity_and_unknown_fields_are_rejected() {
    let mut document: serde_json::Value = serde_json::from_slice(&payload(
        "netboot-xyz",
        "https://boot.netboot.xyz/netboot.xyz.efi",
    ))
    .unwrap();
    let artifact = document["artifacts"][0].clone();
    document["artifacts"].as_array_mut().unwrap().push(artifact);
    assert!(verify(&serde_json::to_vec(&document).unwrap()).is_err());
    document["artifacts"].as_array_mut().unwrap().pop();
    document["trust_key"] = serde_json::json!("attacker-selected-key");
    assert!(verify(&serde_json::to_vec(&document).unwrap()).is_err());
}
