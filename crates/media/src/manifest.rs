// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{MediaError, invalid};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use url::Url;

pub const MAX_MANIFEST_BYTES: usize = 256 * 1024;

/// This type can only be constructed through signature and policy validation.
/// It authorizes metadata under the caller's key, not downloaded file contents.
#[derive(Debug, Serialize)]
pub struct VerifiedManifest {
    schema_version: u32,
    artifacts: Vec<VerifiedArtifact>,
}
impl VerifiedManifest {
    pub fn artifacts(&self) -> &[VerifiedArtifact] {
        &self.artifacts
    }
}

#[derive(Debug, Serialize)]
pub struct VerifiedArtifact {
    id: String,
    version: String,
    architecture: String,
    url: String,
    sha256: String,
}
impl VerifiedArtifact {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn version(&self) -> &str {
        &self.version
    }
    pub fn architecture(&self) -> &str {
        &self.architecture
    }
    pub fn url(&self) -> &str {
        &self.url
    }
    pub fn sha256(&self) -> &str {
        &self.sha256
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    schema_version: u32,
    artifacts: Vec<Artifact>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    id: String,
    version: String,
    architecture: String,
    url: String,
    sha256: String,
}

/// Verify a detached Ed25519 signature over the exact JSON bytes before parsing.
/// No network access, embedded trust key, download, or replay policy is provided.
pub fn verify(
    payload: &[u8],
    signature: &[u8],
    trust_key: &[u8; 32],
) -> Result<VerifiedManifest, MediaError> {
    if payload.len() > MAX_MANIFEST_BYTES {
        return Err(invalid("manifest exceeds byte limit"));
    }
    let key = VerifyingKey::from_bytes(trust_key).map_err(|_| MediaError::Signature)?;
    let signature = Signature::try_from(signature).map_err(|_| MediaError::Signature)?;
    key.verify_strict(payload, &signature)
        .map_err(|_| MediaError::Signature)?;
    let document: Document = serde_json::from_slice(payload)
        .map_err(|error| invalid(format!("signed manifest JSON: {error}")))?;
    if document.schema_version != 1
        || document.artifacts.is_empty()
        || document.artifacts.len() > 32
    {
        return Err(invalid(
            "manifest requires schema_version 1 and 1..32 artifacts",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut artifacts = Vec::new();
    for artifact in document.artifacts {
        if !matches!(artifact.id.as_str(), "netboot-xyz" | "memtest86plus") {
            return Err(invalid("unknown artifact id"));
        }
        if artifact.version.is_empty()
            || artifact.version.len() > 64
            || artifact.version.contains("..")
            || !artifact
                .version
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b".-_+".contains(&byte))
        {
            return Err(invalid("invalid artifact version"));
        }
        if !matches!(
            artifact.architecture.as_str(),
            "x86_64" | "aarch64" | "i686"
        ) {
            return Err(invalid("unsupported artifact architecture"));
        }
        if !seen.insert((artifact.id.clone(), artifact.architecture.clone())) {
            return Err(invalid("duplicate artifact id and architecture"));
        }
        if artifact.sha256.len() != 64
            || !artifact.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid(
                "artifact SHA256 must contain exactly 64 hexadecimal characters",
            ));
        }
        validate_url(&artifact.id, &artifact.url)?;
        artifacts.push(VerifiedArtifact {
            id: artifact.id,
            version: artifact.version,
            architecture: artifact.architecture,
            url: artifact.url,
            sha256: artifact.sha256.to_ascii_lowercase(),
        });
    }
    Ok(VerifiedManifest {
        schema_version: document.schema_version,
        artifacts,
    })
}

fn validate_url(id: &str, raw: &str) -> Result<(), MediaError> {
    if raw.len() > 2048
        || raw.contains('\\')
        || raw
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(invalid("invalid artifact URL characters"));
    }
    let url = Url::parse(raw).map_err(|_| invalid("invalid artifact URL"))?;
    let allowed = match id {
        "netboot-xyz" => url.host_str() == Some("boot.netboot.xyz"),
        "memtest86plus" => matches!(url.host_str(), Some("memtest.org" | "www.memtest.org")),
        _ => false,
    };
    if !allowed
        || url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port_or_known_default() != Some(443)
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() == "/"
    {
        return Err(invalid(
            "artifact URL must use an allowed official HTTPS host without credentials, custom ports, query, or fragment",
        ));
    }
    Ok(())
}
