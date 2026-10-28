// SPDX-License-Identifier: GPL-3.0-or-later
const TRUSTED_INSTALLER: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
const UNSUPPORTED: &str = "Helper elevation requires the protected machine-wide IsoHopper installation in Program Files on the Windows system drive. Portable or writable installations are unsupported.";

#[derive(Clone, Copy, Debug)]
pub(super) enum ObjectKind {
    Ancestor,
    Directory,
    File,
}
#[derive(Clone)]
pub(super) struct Ace {
    pub(super) kind: u8,
    pub(super) flags: u8,
    pub(super) mask: u32,
    pub(super) sid: String,
}

fn trusted(sid: &str) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-32-544") || sid == TRUSTED_INSTALLER
}

pub(super) fn check_acl(
    owner: Option<&str>,
    acl: Option<&[Ace]>,
    kind: ObjectKind,
) -> Result<(), String> {
    if !owner.is_some_and(trusted) {
        return Err(format!("{UNSUPPORTED} Untrusted object owner."));
    }
    let acl = acl.ok_or_else(|| format!("{UNSUPPORTED} Missing or null DACL."))?;
    if acl.len() > 1024 {
        return Err("Installation ACL exceeds the supported bound".into());
    }
    for ace in acl {
        if ace.kind > 1 || ace.flags & !0x1f != 0 {
            return Err("Installation ACL contains an unsupported ACE".into());
        }
        if ace.flags & 8 != 0 || ace.kind == 1 {
            continue;
        }
        // Plain file rights, standard rights and four generic rights only.
        if ace.mask & !0xf01f01ff != 0 {
            return Err("Installation ACL contains unsupported access rights".into());
        }
        if trusted(&ace.sid) {
            continue;
        }
        let mut read_only = 0xa01200a9;
        if matches!(kind, ObjectKind::Ancestor) {
            // Creating a new sibling directory does not replace an existing
            // checked child. ADD_FILE (0x2) is NOT allowed: it also authorizes
            // some FSCTL_SET_REPARSE_POINT requests on a directory.
            read_only |= 4;
        }
        if ace.mask & !read_only != 0 {
            return Err(format!("{UNSUPPORTED} Untrusted mutation permission."));
        }
    }
    Ok(())
}

fn plain_drive_path(path: &str) -> bool {
    let bytes = path.as_bytes();
    bytes.len() >= 4
        && path.encode_utf16().count() < 240
        && bytes[0].is_ascii_alphabetic()
        && &bytes[1..3] == b":\\"
        && path[3..].split('\\').all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.ends_with(['.', ' '])
                && !part
                    .chars()
                    .any(|c| c.is_control() || "<>:\"/|?*".contains(c))
        })
}

pub(super) fn installation_path(
    directory: &str,
    program_files: &str,
    windows: &str,
) -> Result<String, String> {
    if !plain_drive_path(directory)
        || !plain_drive_path(program_files)
        || !plain_drive_path(windows)
        || !program_files[..2].eq_ignore_ascii_case(&windows[..2])
    {
        return Err(UNSUPPORTED.into());
    }
    let expected = format!("{program_files}\\IsoHopper");
    if !directory.eq_ignore_ascii_case(&expected) {
        return Err(UNSUPPORTED.into());
    }
    Ok(expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allow(sid: &str, mask: u32) -> Ace {
        Ace {
            kind: 0,
            flags: 0,
            mask,
            sid: sid.into(),
        }
    }

    #[test]
    fn installation_requires_exact_system_drive_program_files_location() {
        assert_eq!(
            installation_path(
                "c:\\Program Files\\IsoHopper",
                "C:\\Program Files",
                "C:\\Windows"
            )
            .unwrap(),
            "C:\\Program Files\\IsoHopper"
        );
        for candidate in [
            "C:\\Program Files\\IsoHopper2",
            "C:\\Users\\me\\IsoHopper",
            "C:\\Program Files\\x\\..\\IsoHopper",
            "C:\\Program Files\\IsoHopper.",
            "C:\\Program Files\\IsoHopper\\",
            "\\\\server\\Program Files\\IsoHopper",
            "\\\\?\\C:\\Program Files\\IsoHopper",
        ] {
            assert!(
                installation_path(candidate, "C:\\Program Files", "C:\\Windows").is_err(),
                "{candidate}"
            );
        }
        assert!(
            installation_path(
                "D:\\Program Files\\IsoHopper",
                "D:\\Program Files",
                "C:\\Windows"
            )
            .is_err()
        );
        assert!(
            installation_path(
                "C:\\Program Files\\IsoHopper",
                "C:\\Program Files",
                "C:\\Windows\\..\\Windows"
            )
            .is_err()
        );
    }

    #[test]
    fn acl_requires_trusted_owner_and_present_non_null_dacl() {
        let entries = [
            allow("S-1-5-32-544", 0x001f01ff),
            allow("S-1-1-0", 0x001200a9),
        ];
        for owner in ["S-1-5-18", "S-1-5-32-544", TRUSTED_INSTALLER] {
            assert!(check_acl(Some(owner), Some(&entries), ObjectKind::File).is_ok());
        }
        assert!(
            check_acl(
                Some("S-1-5-21-1-2-3-1001"),
                Some(&entries),
                ObjectKind::File
            )
            .is_err()
        );
        assert!(check_acl(None, Some(&entries), ObjectKind::File).is_err());
        assert!(check_acl(Some("S-1-5-18"), None, ObjectKind::File).is_err());
    }

    #[test]
    fn acl_rejects_every_existing_object_mutation_including_reparse_attribute_access() {
        for bit in [
            0x2, 0x10, 0x40, 0x100, 0x10000, 0x40000, 0x80000, 0x10000000, 0x40000000, 0x02000000,
        ] {
            let entries = [allow("S-1-1-0", bit)];
            for kind in [
                ObjectKind::Ancestor,
                ObjectKind::Directory,
                ObjectKind::File,
            ] {
                assert!(
                    check_acl(Some("S-1-5-18"), Some(&entries), kind).is_err(),
                    "{bit:#x} {kind:?}"
                );
            }
        }
        let entries = [allow("S-1-5-11", 0x4)];
        assert!(check_acl(Some("S-1-5-18"), Some(&entries), ObjectKind::Ancestor).is_ok());
        assert!(check_acl(Some("S-1-5-18"), Some(&entries), ObjectKind::Directory).is_err());
        assert!(check_acl(Some("S-1-5-18"), Some(&entries), ObjectKind::File).is_err());
    }

    #[test]
    fn acl_is_conservative_about_denies_unknown_aces_and_inheritance() {
        let mut inherited = allow("S-1-1-0", 0x10000000);
        inherited.flags = 8; // Does not apply to this object; children are checked separately.
        assert!(
            check_acl(
                Some("S-1-5-18"),
                Some(&[inherited.clone()]),
                ObjectKind::Ancestor
            )
            .is_ok()
        );
        inherited.flags = 0x10; // Inherited but effective.
        assert!(check_acl(Some("S-1-5-18"), Some(&[inherited]), ObjectKind::Ancestor).is_err());
        let mut deny = allow("S-1-1-0", 0x10000000);
        deny.kind = 1;
        assert!(check_acl(Some("S-1-5-18"), Some(&[deny.clone()]), ObjectKind::File).is_ok());
        assert!(
            check_acl(
                Some("S-1-5-18"),
                Some(&[deny, allow("S-1-1-0", 0x100)]),
                ObjectKind::File
            )
            .is_err()
        );
        for kind in [5, 9, 11, 17, 255] {
            let mut unknown = allow("S-1-5-18", 0);
            unknown.kind = kind;
            assert!(check_acl(Some("S-1-5-18"), Some(&[unknown]), ObjectKind::File).is_err());
        }
    }
}
