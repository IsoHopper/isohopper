// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
//! Read-only elevated-helper diagnostics; never a physical preparation capability.
#[path = "elevation/installation.rs"]
mod installation;
#[cfg(windows)]
#[path = "elevation/windows.rs"]
mod windows;
#[cfg(all(windows, debug_assertions))]
pub(crate) use windows::accept_diagnostic_helper;
#[cfg(windows)]
pub use windows::run;
#[cfg(windows)]
pub(crate) use windows::{Launched, launch_preparation};

#[derive(Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ProbeOutcome {
    Connected {
        protocol: u32,
        helper_version: String,
        helper_pid: u32,
        helper_created: String,
        helper_sha256: String,
        physical_preparation: bool,
    },
    Cancelled {
        physical_preparation: bool,
    },
}

fn check_digest(reader: &mut impl std::io::Read, expected: &str) -> Result<String, String> {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|e| format!("Read packaged helper: {e}"))?;
        if count == 0 {
            break;
        }
        total += count as u64;
        if total > 256 * 1024 * 1024 {
            return Err("Packaged helper exceeds 256 MiB".into());
        }
        hash.update(&buffer[..count]);
    }
    let digest = format!("{:x}", hash.finalize());
    if total == 0 || digest != expected {
        return Err("Packaged helper checksum does not match this Studio build".into());
    }
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packaged_helper_digest_rejects_missing_or_changed_bytes() {
        const ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(check_digest(&mut &b"abc"[..], ABC).unwrap(), ABC);
        assert!(check_digest(&mut &b"abd"[..], ABC).is_err());
        assert!(check_digest(&mut &b""[..], ABC).is_err());
        assert!(check_digest(&mut &b"abc"[..], "").is_err());
    }
    #[test]
    fn probe_serialization_never_looks_like_disk_completion() {
        let value = serde_json::to_value(ProbeOutcome::Cancelled {
            physical_preparation: false,
        })
        .unwrap();
        assert_eq!(
            value,
            serde_json::json!({"status":"cancelled", "physical_preparation":false})
        );
        let value = serde_json::to_value(ProbeOutcome::Connected {
            protocol: 1,
            helper_version: "0.1.0".into(),
            helper_pid: 42,
            helper_created: "123".into(),
            helper_sha256: "a".repeat(64),
            physical_preparation: false,
        })
        .unwrap();
        assert_eq!(value["status"], "connected");
        assert_eq!(value["physical_preparation"], false);
    }
}
