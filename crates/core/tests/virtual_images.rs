// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_core::{layout, virtualdisk};
#[cfg(unix)]
use std::path::Path;
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
};

fn read_at(f: &mut File, off: u64, len: usize) -> Vec<u8> {
    let mut b = vec![0; len];
    f.seek(SeekFrom::Start(off)).unwrap();
    f.read_exact(&mut b).unwrap();
    b
}
fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b.try_into().unwrap())
}
fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes(b.try_into().unwrap())
}
fn crc(b: &[u8]) -> u32 {
    let mut c = !0u32;
    for &v in b {
        c ^= u32::from(v);
        for _ in 0..8 {
            c = (c >> 1) ^ if c & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    !c
}

#[test]
fn creates_sparse_images_with_real_primary_and_backup_gpt() {
    for (size, sector, legacy) in [
        (256 << 20, 512, false),
        (256 << 20, 512, true),
        (2 << 30, 4096, false),
        (3 << 40, 512, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image.img");
        let p = layout::plan(size, sector, legacy).unwrap();
        virtualdisk::create(&path, &p).unwrap();
        virtualdisk::verify(&path).unwrap();
        let mut f = File::open(&path).unwrap();
        assert_eq!(f.metadata().unwrap().len(), size);
        #[cfg(windows)]
        {
            use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_ATTRIBUTE_SPARSE_FILE, FILE_STANDARD_INFO, FileStandardInfo,
                GetFileInformationByHandleEx,
            };
            assert_ne!(
                f.metadata().unwrap().file_attributes() & FILE_ATTRIBUTE_SPARSE_FILE,
                0,
                "image must have the Windows sparse-file attribute"
            );
            let mut info = FILE_STANDARD_INFO::default();
            // SAFETY: the live file handle is readable and info is a correctly
            // sized writable FILE_STANDARD_INFO buffer for the selected class.
            let success = unsafe {
                GetFileInformationByHandleEx(
                    f.as_raw_handle(),
                    FileStandardInfo,
                    (&mut info as *mut FILE_STANDARD_INFO).cast(),
                    std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
                )
            };
            assert_ne!(success, 0, "{}", std::io::Error::last_os_error());
            assert_eq!(info.EndOfFile as u64, size);
            assert!(
                (0..=1024 * 1024).contains(&info.AllocationSize),
                "GPT-only sparse image allocated {} bytes",
                info.AllocationSize
            );
        }
        let m = read_at(&mut f, 0, 512);
        assert_eq!(&m[510..512], &[0x55, 0xaa]);
        assert_eq!(m[450], 0xee);
        assert_eq!(le32(&m[454..458]), 1);
        assert_eq!(
            u64::from(le32(&m[458..462])),
            (size / sector - 1).min(u64::from(u32::MAX))
        );
        let primary = read_at(&mut f, sector, sector as usize);
        let backup = read_at(&mut f, size - sector, sector as usize);
        assert_eq!(&primary[56..72], &backup[56..72]);
        assert_ne!(&primary[56..72], &[0; 16]);
        for (h, my, alt) in [
            (&primary, 1, size / sector - 1),
            (&backup, size / sector - 1, 1),
        ] {
            assert_eq!(&h[..8], b"EFI PART");
            assert_eq!(le32(&h[8..12]), 0x10000);
            assert_eq!(le32(&h[12..16]), 92);
            let mut copy = h[..92].to_vec();
            copy[16..20].fill(0);
            assert_eq!(crc(&copy), le32(&h[16..20]));
            assert_eq!(le64(&h[24..32]), my);
            assert_eq!(le64(&h[32..40]), alt);
            assert_eq!(le32(&h[80..84]), 128);
            assert_eq!(le32(&h[84..88]), 128);
            let entries = read_at(&mut f, le64(&h[72..80]) * sector, 16384);
            // In particular, do not set read-only, hidden, or no-drive-letter
            // flags as a substitute for partition-type semantics.
            for entry in entries.as_chunks::<128>().0.iter().take(p.partitions.len()) {
                assert_eq!(
                    le64(&entry[48..56]),
                    0,
                    "partition attributes must remain zero"
                );
            }
            assert_eq!(crc(&entries), le32(&h[88..92]));
            assert_eq!(le64(&entries[32..40]), (1 << 20) / sector);
            assert_eq!(
                &entries[..16],
                &[
                    0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7,
                    0x26, 0x99, 0xc7
                ]
            );
        }
        assert_eq!(
            read_at(&mut f, p.partitions[0].start_lba * sector, 512),
            vec![0; 512]
        );
    }
}

#[test]
fn refuses_existing_paths_and_invalid_plans_without_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("keep");
    fs::write(&path, b"keep me").unwrap();
    let p = layout::plan(256 << 20, 512, false).unwrap();
    assert!(virtualdisk::create(&path, &p).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"keep me");
    let bad_path = dir.path().join("bad");
    let mut bad = p;
    bad.partitions[0].end_lba += 1;
    assert!(virtualdisk::create(&bad_path, &bad).is_err());
    assert!(!bad_path.exists());
    assert!(virtualdisk::verify(dir.path()).is_err());
    assert!(virtualdisk::verify(&path).is_err());
}

#[cfg(unix)]
#[test]
fn refuses_symlinks_and_special_files() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    let link = dir.path().join("link");
    let dangling = dir.path().join("dangling");
    let p = layout::plan(256 << 20, 512, false).unwrap();
    virtualdisk::create(&original, &p).unwrap();
    symlink(&original, &link).unwrap();
    symlink(dir.path().join("absent"), &dangling).unwrap();
    assert!(virtualdisk::create(&link, &p).is_err());
    assert!(virtualdisk::create(&dangling, &p).is_err());
    assert!(!dir.path().join("absent").exists());
    assert!(virtualdisk::verify(&link).is_err());
    assert!(virtualdisk::verify(Path::new("/dev/null")).is_err());
}

#[test]
fn detects_corruption_in_either_copy_and_truncation() {
    for offset in [
        450,
        512 + 56,
        (256 << 20) - 512 + 56,
        1024 + 16,
        (256 << 20) - 512 - 16384 + 16,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image");
        virtualdisk::create(&path, &layout::plan(256 << 20, 512, false).unwrap()).unwrap();
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut b = read_at(&mut f, offset, 1);
        b[0] ^= 1;
        f.seek(SeekFrom::Start(offset)).unwrap();
        f.write_all(&b).unwrap();
        assert!(virtualdisk::verify(&path).is_err(), "offset {offset}");
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image");
    virtualdisk::create(&path, &layout::plan(256 << 20, 512, false).unwrap()).unwrap();
    OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len((256 << 20) - 512)
        .unwrap();
    assert!(virtualdisk::verify(&path).is_err());
}

#[test]
fn rejects_structural_corruption_even_with_valid_checksums() {
    for case in [
        "location",
        "bounds",
        "disk-guid",
        "reserved",
        "overlap",
        "duplicate-guid",
        "attribute",
        "name",
        "hole",
        "huge-count",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image");
        virtualdisk::create(&path, &layout::plan(256 << 20, 512, false).unwrap()).unwrap();
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut h = read_at(&mut f, 512, 512);
        let mut b = read_at(&mut f, (256 << 20) - 512, 512);
        let mut e = read_at(&mut f, 1024, 16384);
        match case {
            "location" => h[32..40].copy_from_slice(&17_u64.to_le_bytes()),
            "bounds" => h[40..48].copy_from_slice(&1_u64.to_le_bytes()),
            "disk-guid" => {
                h[56..72].fill(0);
                b[56..72].fill(0)
            }
            "reserved" => h[20] = 1,
            "overlap" => {
                let start = e[160..168].to_vec();
                e[40..48].copy_from_slice(&start)
            }
            "duplicate-guid" => {
                let id = e[16..32].to_vec();
                e[144..160].copy_from_slice(&id)
            }
            "attribute" => e[48] = 1,
            "name" => e[56] = b'X',
            "hole" => e[128..256].fill(0),
            "huge-count" => h[80..84].copy_from_slice(&u32::MAX.to_le_bytes()),
            _ => unreachable!(),
        }
        for header in [&mut h, &mut b] {
            header[88..92].copy_from_slice(&crc(&e).to_le_bytes());
            header[16..20].fill(0);
            let sum = crc(&header[..92]);
            header[16..20].copy_from_slice(&sum.to_le_bytes());
        }
        for (bytes, off) in [
            (&h, 512),
            (&b, (256 << 20) - 512),
            (&e, 1024),
            (&e, (256 << 20) - 512 - 16384),
        ] {
            f.seek(SeekFrom::Start(off)).unwrap();
            f.write_all(bytes).unwrap();
        }
        assert!(virtualdisk::verify(&path).is_err(), "case {case}");
    }
}
