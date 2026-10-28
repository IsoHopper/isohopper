// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use std::{
    io::{self, Read, Write},
    sync::OnceLock,
};

// Generated from our own ASCII fixture with Python's XZ encoder, not vendor data.
const XZ: &[u8] = &[
    253, 55, 122, 88, 90, 0, 0, 1, 105, 34, 222, 54, 2, 0, 33, 1, 22, 0, 0, 0, 116, 47, 229, 163,
    224, 2, 255, 0, 22, 93, 0, 48, 156, 136, 138, 28, 65, 128, 169, 167, 144, 166, 94, 226, 203,
    254, 152, 62, 84, 232, 144, 82, 128, 0, 0, 0, 185, 65, 158, 17, 0, 1, 46, 128, 6, 0, 0, 0, 213,
    95, 126, 106, 62, 48, 13, 139, 2, 0, 0, 0, 0, 1, 89, 90,
];

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn append(builder: &mut tar::Builder<Vec<u8>>, path: &str, kind: u8, size: u64) {
    let mut header = tar::Header::new_gnu();
    let name = &mut header.as_mut_bytes()[..100];
    name.fill(0);
    name[..path.len()].copy_from_slice(path.as_bytes());
    header.set_size(size);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::new(kind));
    header.set_cksum();
    builder.append(&header, io::repeat(0).take(size)).unwrap();
}

fn archive(extra: &[(&str, u8, u64)]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, size) in member::SELECTED {
        append(&mut builder, name, b'0', size);
    }
    for (name, kind, size) in extra {
        append(&mut builder, name, *kind, *size);
    }
    builder.into_inner().unwrap()
}

fn base() -> &'static [u8] {
    static TAR: OnceLock<Vec<u8>> = OnceLock::new();
    TAR.get_or_init(|| archive(&[]))
}

#[test]
fn invalid_outer_size_and_hash_fail_before_decoder() {
    let wrong_size = import(b"not gzip").err().unwrap().to_string();
    assert!(wrong_size.contains("archive size"), "{wrong_size}");
    let wrong_hash = import(&vec![0; ARCHIVE_BYTES]).err().unwrap().to_string();
    assert!(wrong_hash.contains("archive SHA256"), "{wrong_hash}");
}

#[test]
fn gzip_rejects_overrun_truncation_checksum_and_trailing_members() {
    let input = gzip(b"bounded gzip payload");
    assert_eq!(decode_gzip(&input, 20).unwrap(), b"bounded gzip payload");
    assert!(decode_gzip(&input, 19).is_err());
    assert!(decode_gzip(&input[..input.len() - 1], 20).is_err());
    let mut corrupt = input.clone();
    corrupt[input.len() - 8] ^= 1;
    assert!(decode_gzip(&corrupt, 20).is_err());
    for trailing in [&input[..], &[0][..]] {
        let mut combined = input.clone();
        combined.extend_from_slice(trailing);
        assert!(decode_gzip(&combined, 40).is_err());
    }
}

#[test]
fn xz_rejects_memory_output_truncation_and_trailing_streams() {
    let expected = b"archive-test".repeat(64);
    assert_eq!(
        decode_xz(XZ, expected.len(), XZ_MEMORY_KIB).unwrap(),
        expected
    );
    assert!(decode_xz(XZ, expected.len() - 1, XZ_MEMORY_KIB).is_err());
    assert!(decode_xz(XZ, expected.len() + 1, XZ_MEMORY_KIB).is_err());
    assert!(decode_xz(XZ, expected.len(), 1).is_err());
    assert!(decode_xz(&XZ[..XZ.len() - 1], expected.len(), XZ_MEMORY_KIB).is_err());
    let mut corrupt = XZ.to_vec();
    corrupt[56] ^= 1;
    assert!(decode_xz(&corrupt, expected.len(), XZ_MEMORY_KIB).is_err());
    for trailing in [XZ, &[0][..]] {
        let mut combined = XZ.to_vec();
        combined.extend_from_slice(trailing);
        assert!(decode_xz(&combined, expected.len(), XZ_MEMORY_KIB).is_err());
    }
}

#[test]
fn raw_tar_keeps_only_fixed_regular_members() {
    let selected = selected_members(&archive(&[("./ventoy-1.1.18/unused", b'0', 100)])).unwrap();
    for (i, value) in selected.iter().enumerate() {
        assert_eq!(value.len() as u64, member::SELECTED[i].1);
        assert!(value.iter().all(|byte| *byte == 0));
    }
}

#[test]
fn raw_tar_rejects_duplicates_links_extensions_and_traversal() {
    for extra in [
        vec![("./ventoy-1.1.18/boot/boot.img", b'0', 512)],
        vec![
            ("ventoy-1.1.18/unused", b'0', 0),
            ("./ventoy-1.1.18/unused", b'0', 0),
        ],
        vec![("ventoy-1.1.18/link", b'2', 0)],
        vec![("ventoy-1.1.18/extension", b'x', 0)],
        vec![("ventoy-1.1.18/../outside", b'0', 0)],
    ] {
        assert!(selected_members(&archive(&extra)).is_err(), "{extra:?}");
    }
}

#[test]
fn raw_tar_rejects_missing_corrupt_unbounded_and_hidden_tail_records() {
    let mut missing = tar::Builder::new(Vec::new());
    append(&mut missing, member::SELECTED[0].0, b'0', 512);
    assert!(selected_members(&missing.into_inner().unwrap()).is_err());
    let mut corrupt = base().to_vec();
    corrupt[0] ^= 1;
    assert!(selected_members(&corrupt).is_err());
    let mut tail = base().to_vec();
    *tail.last_mut().unwrap() = 1;
    assert!(selected_members(&tail).is_err());
    let mut padding = base().to_vec();
    padding[1536 + member::SELECTED[1].1 as usize] = 1;
    assert!(selected_members(&padding).is_err());
    let mut oversized = base().to_vec();
    let mut header = tar::Header::new_gnu();
    header.as_mut_bytes().copy_from_slice(&oversized[..512]);
    header.set_size(u64::MAX);
    header.set_cksum();
    oversized[..512].copy_from_slice(header.as_bytes());
    assert!(selected_members(&oversized).is_err());
    assert!(selected_members(&base()[..base().len() - 1024]).is_err());
    assert!(selected_members(&vec![0; TAR_BYTES + 1]).is_err());
    let names: Vec<_> = (0..257).map(|i| format!("ventoy-1.1.18/file{i}")).collect();
    let extras: Vec<_> = names.iter().map(|name| (name.as_str(), b'0', 0)).collect();
    assert!(selected_members(&archive(&extras)).is_err());
}

#[test]
#[ignore = "requires explicitly supplied pinned upstream archive; no download"]
fn actual_pinned_archive_imports_exact_builder_payloads() {
    let path = std::env::var_os("ISOHOPPER_ENGINE_ARCHIVE")
        .expect("set ISOHOPPER_ENGINE_ARCHIVE to the pinned upstream Linux tar.gz");
    let file = std::fs::File::open(path).unwrap();
    let mut bytes = Vec::new();
    file.take(ARCHIVE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    let imported = import(&bytes).unwrap();
    let payloads = imported.payloads();
    assert_eq!(payloads.boot.len(), super::super::BOOT_BYTES);
    assert_eq!(payloads.core.len(), CORE_BYTES);
    assert_eq!(payloads.firmware.len(), FIRMWARE_BYTES);
    assert_eq!(
        hex::encode(Sha256::digest(payloads.boot)),
        super::super::BOOT_SHA256
    );
    assert_eq!(
        hex::encode(Sha256::digest(payloads.core)),
        super::super::CORE_SHA256
    );
    assert_eq!(
        hex::encode(Sha256::digest(payloads.firmware)),
        super::super::FIRMWARE_SHA256
    );
}
