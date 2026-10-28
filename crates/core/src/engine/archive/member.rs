// SPDX-License-Identifier: GPL-3.0-or-later
//! Strict member policy for the one supported upstream archive.

pub(super) const SELECTED: [(&str, u64); 3] = [
    ("ventoy-1.1.18/boot/boot.img", 512),
    ("ventoy-1.1.18/boot/core.img.xz", 455_176),
    ("ventoy-1.1.18/ventoy/ventoy.disk.img.xz", 13_434_140),
];

pub(super) fn validate(
    path: &[u8],
    kind: u8,
    size: u64,
) -> Result<(String, Option<usize>), &'static str> {
    if !matches!(kind, b'0' | b'5') {
        return Err("archive contains a link, special file or extension record");
    }
    if path.is_empty() || path.len() > 256 || !path.is_ascii() {
        return Err("archive member path is outside the supported bound");
    }
    let path = std::str::from_utf8(path).map_err(|_| "archive path is not ASCII")?;
    let path = path.strip_prefix("./").unwrap_or(path);
    let path = if kind == b'5' {
        if size != 0 {
            return Err("archive directory has data");
        }
        path.strip_suffix('/').unwrap_or(path)
    } else {
        path
    };
    let mut parts = path.split('/');
    if parts.next() != Some("ventoy-1.1.18") {
        return Err("archive path is outside the fixed version root");
    }
    let mut children = 0;
    for part in parts {
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with('.')
            || !part
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            return Err("archive contains a noncanonical member path");
        }
        children += 1;
    }
    if children == 0 && kind != b'5' {
        return Err("archive root is not a directory");
    }
    let selected = SELECTED
        .iter()
        .position(|(candidate, _)| *candidate == path);
    if let Some(index) = selected
        && (kind != b'0' || size != SELECTED[index].1)
    {
        return Err("selected payload is not a regular member of the pinned size");
    }
    Ok((path.to_owned(), selected))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_regular_members_are_selected_with_exact_sizes() {
        for (index, (path, size)) in SELECTED.iter().enumerate() {
            for prefix in ["", "./"] {
                let name = format!("{prefix}{path}");
                assert_eq!(
                    validate(name.as_bytes(), b'0', *size),
                    Ok((path.to_string(), Some(index)))
                );
                assert!(validate(name.as_bytes(), b'0', size - 1).is_err());
                assert!(validate(name.as_bytes(), b'0', size + 1).is_err());
                assert!(validate(name.as_bytes(), b'5', 0).is_err());
            }
        }
    }

    #[test]
    fn ordinary_unselected_entries_and_empty_directories_are_validated() {
        assert_eq!(
            validate(b"./ventoy-1.1.18/", b'5', 0),
            Ok(("ventoy-1.1.18".into(), None))
        );
        assert_eq!(
            validate(b"ventoy-1.1.18/tool/", b'5', 0),
            Ok(("ventoy-1.1.18/tool".into(), None))
        );
        assert_eq!(
            validate(b"./ventoy-1.1.18/README", b'0', 8192),
            Ok(("ventoy-1.1.18/README".into(), None))
        );
        assert!(validate(b"ventoy-1.1.18/tool/", b'5', 1).is_err());
        assert!(validate(b"ventoy-1.1.18/tool/", b'0', 0).is_err());
        assert!(validate(b"ventoy-1.1.18", b'0', 0).is_err());
    }

    #[test]
    fn links_special_files_and_extension_records_are_never_accepted() {
        for kind in [
            0, b'1', b'2', b'3', b'4', b'6', b'7', b'L', b'K', b'x', b'g', b'S', 255,
        ] {
            assert!(
                validate(b"ventoy-1.1.18/other", kind, 0).is_err(),
                "kind={kind}"
            );
        }
    }

    #[test]
    fn paths_are_strict_relative_ascii_under_exact_version_root() {
        for path in [
            "",
            "/ventoy-1.1.18/a",
            "//host/ventoy-1.1.18/a",
            "C:/ventoy-1.1.18/a",
            "ventoy-1.1.18/../outside",
            "ventoy-1.1.18/./a",
            "././ventoy-1.1.18/a",
            "ventoy-1.1.18//a",
            "ventoy-1.1.18/a/",
            "ventoy-1.1.18/a\\b",
            "ventoy-1.1.18/a\0b",
            "ventoy-1.1.18/a\nb",
            "ventoy-1.1.18/a:stream",
            "ventoy-1.1.18/a ",
            "ventoy-1.1.18/a.",
            "ventoy-1.1.18/é",
            "ventoy-1.1.19/a",
            "Ventoy-1.1.18/a",
            "ventoy-1.1.18x/a",
        ] {
            assert!(validate(path.as_bytes(), b'0', 0).is_err(), "{path:?}");
        }
        assert!(validate(&[b'a'; 257], b'0', 0).is_err());
        assert!(validate(&[255], b'0', 0).is_err());
    }
}
