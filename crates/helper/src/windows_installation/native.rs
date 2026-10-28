// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
use super::{
    InstalledRole,
    policy::{Ace, ObjectKind, check_acl, installation_path},
    state::{ImageStamp, image_stamp, wide_name},
};
use std::{
    ffi::{OsStr, c_void},
    fs::{File, OpenOptions},
    io,
    mem::{offset_of, size_of},
    os::windows::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::AsRawHandle,
    },
    path::{Path, PathBuf},
    ptr,
};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::{
        Authorization::{GetSecurityInfo, SE_FILE_OBJECT},
        DACL_SECURITY_INFORMATION, GetAce, GetLengthSid, GetSecurityDescriptorDacl,
        GetSecurityDescriptorOwner, IsValidAcl, IsValidSecurityDescriptor, IsValidSid,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    },
    Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_BASIC_INFO, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_SHARE_READ, FILE_SHARE_WRITE,
        FILE_STANDARD_INFO, FILE_TYPE_DISK, FileBasicInfo, FileIdInfo, FileStandardInfo,
        GetFileInformationByHandleEx, GetFileType, GetFinalPathNameByHandleW,
        GetVolumeInformationByHandleW, QueryDosDeviceW, VOLUME_NAME_NT, WofIsExternalFile,
    },
    System::{
        Com::CoTaskMemFree, SystemInformation::GetSystemWindowsDirectoryW,
        SystemServices::FILE_PERSISTENT_ACLS,
    },
    UI::Shell::{FOLDERID_ProgramFiles, KF_FLAG_DEFAULT_PATH, SHGetKnownFolderPath},
};

fn error(stage: &str) -> String {
    format!("{stage}: {}", io::Error::last_os_error())
}
fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

struct Descriptor(PSECURITY_DESCRIPTOR);
impl Drop for Descriptor {
    fn drop(&mut self) {
        unsafe {
            LocalFree(self.0);
        }
    }
}

// All pointers passed here are returned by the security APIs and remain owned
// by Descriptor. Parsing bounds are checked before reading variable SID data.
unsafe fn sid_text(sid: PSID) -> Result<String, String> {
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        return Err("Invalid installation SID".into());
    }
    let length = unsafe { GetLengthSid(sid) } as usize;
    if !(8..=68).contains(&length) {
        return Err("Oversized installation SID".into());
    }
    let bytes = unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) };
    if bytes[0] != 1 || usize::from(bytes[1]) * 4 + 8 != length {
        return Err("Unsupported installation SID".into());
    }
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |value, byte| value * 256 + u64::from(*byte));
    let mut result = format!("S-1-{authority}");
    for part in bytes[8..].as_chunks::<4>().0 {
        result.push_str(&format!("-{}", u32::from_le_bytes(*part)));
    }
    Ok(result)
}

unsafe fn descriptor_check(sd: PSECURITY_DESCRIPTOR, kind: ObjectKind) -> Result<(), String> {
    if sd.is_null() || unsafe { IsValidSecurityDescriptor(sd) } == 0 {
        return Err("Invalid installation descriptor".into());
    }
    let mut owner = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(sd, &mut owner, &mut defaulted) } == 0 {
        return Err(error("Read installation owner"));
    }
    let owner = unsafe { sid_text(owner) }?;
    let mut present = 0;
    let mut acl = ptr::null_mut();
    if unsafe { GetSecurityDescriptorDacl(sd, &mut present, &mut acl, &mut defaulted) } == 0 {
        return Err(error("Read installation DACL"));
    }
    if present == 0 || acl.is_null() {
        return check_acl(Some(&owner), None, kind);
    }
    if unsafe { IsValidAcl(acl) } == 0 {
        return Err("Invalid installation ACL".into());
    }
    let count = unsafe { (*acl).AceCount };
    let length = usize::from(unsafe { (*acl).AclSize });
    if count > 1024 || length < 8 {
        return Err("Installation ACL exceeds supported bounds".into());
    }
    let mut entries = Vec::with_capacity(usize::from(count));
    for index in 0..u32::from(count) {
        let mut ace: *mut c_void = ptr::null_mut();
        if unsafe { GetAce(acl, index, &mut ace) } == 0 {
            return Err(error("Read installation ACE"));
        }
        let offset = (ace as usize)
            .checked_sub(acl as usize)
            .ok_or("Invalid installation ACE offset")?;
        if offset.checked_add(4).is_none_or(|end| end > length) {
            return Err("Invalid installation ACE header".into());
        }
        let header = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), 4) };
        let size = usize::from(u16::from_le_bytes([header[2], header[3]]));
        if size < 16 || offset.checked_add(size).is_none_or(|end| end > length) || header[0] > 1 {
            return Err("Unsupported installation ACE".into());
        }
        let bytes = unsafe { std::slice::from_raw_parts(ace.cast::<u8>(), size) };
        let sid_len = 8 + usize::from(bytes[9]) * 4;
        if 8 + sid_len != size {
            return Err("Invalid installation ACE SID bounds".into());
        }
        let sid = unsafe { sid_text(ace.cast::<u8>().add(8).cast()) }?;
        entries.push(Ace {
            kind: bytes[0],
            flags: bytes[1],
            mask: u32::from_le_bytes(bytes[4..8].try_into().unwrap()),
            sid,
        });
    }
    check_acl(Some(&owner), Some(&entries), kind)
}

fn check_object(file: &File, kind: ObjectKind) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|e| format!("Inspect installation object: {e}"))?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || matches!(kind, ObjectKind::File) != metadata.is_file()
        || (!matches!(kind, ObjectKind::File) && !metadata.is_dir())
    {
        return Err("Installation contains a reparse point or unexpected object type".into());
    }
    let mut sd = ptr::null_mut();
    // SAFETY: live owned file handle; API allocates the descriptor, retained by
    // the guard until all owner/ACL observations have been copied and checked.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut sd,
        )
    };
    if status != 0 {
        return Err(format!("Read installation security: Win32 {status}"));
    }
    let sd = Descriptor(sd);
    unsafe { descriptor_check(sd.0, kind) }
}

/// Reuse the installation's mutation/owner policy for newly created private
/// staging objects. Creation supplies a stricter private DACL separately.
pub(crate) fn check_stage_object(file: &File, directory: bool) -> Result<(), String> {
    check_object(
        file,
        if directory {
            ObjectKind::Directory
        } else {
            ObjectKind::File
        },
    )
}

fn program_files() -> Result<String, String> {
    let mut value = ptr::null_mut();
    // The fixed machine-wide known folder is obtained from Windows, not an
    // environment variable. DEFAULT_PATH rejects per-user folder redirection.
    let status = unsafe {
        SHGetKnownFolderPath(
            &FOLDERID_ProgramFiles,
            KF_FLAG_DEFAULT_PATH as u32,
            ptr::null_mut(),
            &mut value,
        )
    };
    if status < 0 || value.is_null() {
        return Err(format!(
            "Read Program Files location: HRESULT {status:#010x}"
        ));
    }
    struct Folder(*mut u16);
    impl Drop for Folder {
        fn drop(&mut self) {
            unsafe {
                CoTaskMemFree(self.0.cast());
            }
        }
    }
    let folder = Folder(value);
    let length = (0..32768)
        .find(|i| unsafe { *folder.0.add(*i) } == 0)
        .ok_or("Program Files path exceeds limit")?;
    String::from_utf16(unsafe { std::slice::from_raw_parts(folder.0, length) })
        .map_err(|_| "Program Files path is not Unicode".into())
}

fn system_windows() -> Result<String, String> {
    let mut value = [0u16; 32768];
    let length =
        unsafe { GetSystemWindowsDirectoryW(value.as_mut_ptr(), value.len() as u32) } as usize;
    if length == 0 || length >= value.len() {
        return Err(error("Read system Windows directory"));
    }
    String::from_utf16(&value[..length]).map_err(|_| "System Windows path is not Unicode".into())
}

fn device_mapping(name: &str) -> Result<String, String> {
    let name = wide(OsStr::new(name));
    let mut value = [0u16; 32768];
    let length =
        unsafe { QueryDosDeviceW(name.as_ptr(), value.as_mut_ptr(), value.len() as u32) } as usize;
    if length == 0 || length > value.len() {
        return Err(error("Read system drive mapping"));
    }
    let end = value[..length]
        .iter()
        .position(|c| *c == 0)
        .ok_or("Unterminated system drive mapping")?;
    String::from_utf16(&value[..end]).map_err(|_| "Invalid system drive mapping".into())
}

fn check_mapping(drive: &str, expected: Option<&str>) -> Result<String, String> {
    let current = device_mapping(drive)?;
    let global = device_mapping(&format!("Global\\{drive}"))?;
    let suffix = current
        .strip_prefix("\\Device\\HarddiskVolume")
        .ok_or("Unsupported system drive namespace")?;
    if suffix.is_empty()
        || !suffix.bytes().all(|b| b.is_ascii_digit())
        || current != global
        || expected.is_some_and(|old| old != current)
    {
        return Err("System drive mapping changed or is not the global boot drive".into());
    }
    Ok(current)
}

fn retain_ancestors(directory: &str) -> Result<Vec<(File, ObjectKind)>, String> {
    let drive = &directory[..2];
    let mut ancestors = Vec::new();
    let mut component = PathBuf::from(format!("{drive}\\"));
    let parts: Vec<_> = directory[3..].split('\\').collect();
    for index in 0..=parts.len() {
        if index > 0 {
            component.push(parts[index - 1]);
        }
        let kind = if index == parts.len() {
            ObjectKind::Directory
        } else {
            ObjectKind::Ancestor
        };
        // READ_CONTROL + FILE_READ_ATTRIBUTES, rather than directory data
        // access: existing harmless sibling creators must not block us.
        let file = OpenOptions::new()
            .access_mode(0x00020080)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&component)
            .map_err(|e| format!("Open protected installation ancestor: {e}"))?;
        check_object(&file, kind)?;
        if index == 0 {
            let mut flags = 0;
            if unsafe {
                GetVolumeInformationByHandleW(
                    file.as_raw_handle(),
                    ptr::null_mut(),
                    0,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut flags,
                    ptr::null_mut(),
                    0,
                )
            } == 0
                || flags & FILE_PERSISTENT_ACLS == 0
            {
                return Err("System volume does not provide persistent ACL evidence".into());
            }
        }
        ancestors.push((file, kind));
    }
    Ok(ancestors)
}

struct RetainedImage {
    path: PathBuf,
    file: File,
    stamp: ImageStamp,
    name: Vec<u16>,
}

impl RetainedImage {
    fn open(directory: &Path, role: InstalledRole) -> Result<Self, String> {
        let path = directory.join(role.filename());
        let file = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(|e| format!("Open protected installed image: {e}"))?;
        check_object(&file, ObjectKind::File)?;
        let stamp = image_metadata(&file)?;
        let name = final_name(&file)?;
        Ok(Self {
            path,
            file,
            stamp,
            name,
        })
    }

    fn revalidate(&self) -> Result<(), String> {
        check_object(&self.file, ObjectKind::File)?;
        if image_metadata(&self.file)? != self.stamp || final_name(&self.file)? != self.name {
            return Err("Retained installed image changed".into());
        }
        Ok(())
    }
}

/// Retains the protected system-drive installation and both fixed executables.
/// No caller-supplied path is opened. Read handles deny new write/delete opens;
/// ACLs, identity, metadata and final names are rechecked without reopening files.
/// This assumes a fresh protected installation and no privileged mutation. It
/// does not attest loaded code, reject injection, or authorize any disk operation.
pub struct MachineInstallation {
    directory: PathBuf,
    drive: String,
    mapping: String,
    ancestors: Vec<(File, ObjectKind)>,
    studio: RetainedImage,
    helper: RetainedImage,
}
impl MachineInstallation {
    pub fn open() -> Result<Self, String> {
        let base = program_files()?;
        let directory =
            installation_path(&format!("{base}\\IsoHopper"), &base, &system_windows()?)?;
        let drive = directory[..2].to_owned();
        // Boot-defined drive aliases are protected from nonadministrator
        // replacement (DefineDosDeviceW). Explicit global comparison rejects
        // local shadows; unsupported namespaces never get a fallback spelling.
        let mapping = check_mapping(&drive, None)?;
        let ancestors = retain_ancestors(&directory)?;
        let directory = PathBuf::from(directory);
        let studio = RetainedImage::open(&directory, InstalledRole::Studio)?;
        let helper = RetainedImage::open(&directory, InstalledRole::Helper)?;
        let result = Self {
            directory,
            drive,
            mapping,
            ancestors,
            studio,
            helper,
        };
        result.revalidate()?;
        Ok(result)
    }

    pub fn revalidate(&self) -> Result<(), String> {
        check_mapping(&self.drive, Some(&self.mapping))?;
        for (file, kind) in &self.ancestors {
            check_object(file, *kind)?;
        }
        self.studio.revalidate()?;
        self.helper.revalidate()
    }

    /// Require explicit WOF evidence that one fixed installed image is stored
    /// inline. This path-taking query is only valid within this retained,
    /// protected fresh installation; it is not a fallback for arbitrary files.
    /// Both successful and failed queries are bracketed by namespace, ACL,
    /// original-handle metadata and final-name checks. Administrators remain
    /// trusted, as for the installation owner; no process or disk is authorized.
    pub fn require_inline_backing(&self, role: InstalledRole) -> Result<(), String> {
        self.revalidate()?;
        let image = self.retained(role);
        let before = image_metadata(&image.file)?;
        let name = final_name(&image.file)?;
        let path = wide(image.path.as_os_str());
        let mut external = i32::MIN;
        // SAFETY: only the fixed path held by this protected installation is
        // passed. Its ancestors and original file remain retained throughout.
        // The terminated input and BOOL output live through the synchronous
        // call; all optional provider/detail outputs are null.
        // https://learn.microsoft.com/windows/win32/api/wofapi/nf-wofapi-wofisexternalfile
        let hresult = unsafe {
            WofIsExternalFile(
                path.as_ptr(),
                &mut external,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        self.revalidate()?;
        if image_metadata(&image.file)? != before || final_name(&image.file)? != name {
            return Err("Installed image changed during backing query".into());
        }
        super::backing::require_inline(hresult, external)
    }

    /// Validate an application resource directory without ever opening it.
    pub fn require_directory(&self, directory: &Path) -> Result<(), String> {
        let directory = directory
            .to_str()
            .ok_or("Installation path is not Unicode")?;
        let expected = self
            .directory
            .to_str()
            .ok_or("Installation path is not Unicode")?;
        if directory.eq_ignore_ascii_case(expected) {
            Ok(())
        } else {
            Err("Resource directory is not the protected machine installation".into())
        }
    }

    fn retained(&self, role: InstalledRole) -> &RetainedImage {
        match role {
            InstalledRole::Studio => &self.studio,
            InstalledRole::Helper => &self.helper,
        }
    }

    /// Retained read-only image, suitable for the Studio build's helper hash
    /// check. Sharing the cursor does not affect metadata/name observations.
    pub fn image(&self, role: InstalledRole) -> &File {
        &self.retained(role).file
    }
    pub fn path(&self, role: InstalledRole) -> &Path {
        &self.retained(role).path
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
    pub(crate) fn native_name(&self, role: InstalledRole) -> &[u16] {
        &self.retained(role).name
    }
}

const _: () = {
    assert!(size_of::<FILE_ID_INFO>() == 24);
    assert!(offset_of!(FILE_ID_INFO, FileId) == 8);
    assert!(size_of::<FILE_BASIC_INFO>() == 40);
    assert!(offset_of!(FILE_BASIC_INFO, CreationTime) == 0);
    assert!(offset_of!(FILE_BASIC_INFO, LastWriteTime) == 16);
    assert!(offset_of!(FILE_BASIC_INFO, ChangeTime) == 24);
    assert!(offset_of!(FILE_BASIC_INFO, FileAttributes) == 32);
    assert!(size_of::<FILE_STANDARD_INFO>() == 24);
    assert!(offset_of!(FILE_STANDARD_INFO, AllocationSize) == 0);
    assert!(offset_of!(FILE_STANDARD_INFO, EndOfFile) == 8);
    assert!(offset_of!(FILE_STANDARD_INFO, NumberOfLinks) == 16);
    assert!(offset_of!(FILE_STANDARD_INFO, DeletePending) == 20);
    assert!(offset_of!(FILE_STANDARD_INFO, Directory) == 21);
};

fn image_metadata(file: &File) -> Result<ImageStamp, String> {
    // SAFETY: the retained regular File stays live through each synchronous
    // query. Integer-only aligned buffers preserve arbitrary BOOLEAN bytes.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err("Installed image is not a disk file".into());
    }
    let mut id = [u64::MAX; 3];
    let mut basic = [u64::MAX; 5];
    let mut standard = [u64::MAX; 3];
    for (class, output) in [
        (FileIdInfo, id.as_mut_slice()),
        (FileBasicInfo, basic.as_mut_slice()),
        (FileStandardInfo, standard.as_mut_slice()),
    ] {
        if unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                class,
                output.as_mut_ptr().cast(),
                size_of_val(output) as u32,
            )
        } == 0
        {
            return Err(error("Inspect retained installed image"));
        }
    }
    fn bytes(words: &[u64]) -> &[u8] {
        // SAFETY: initialized integer storage, borrowed only for this call.
        unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), size_of_val(words)) }
    }
    image_stamp(bytes(&id), bytes(&basic), bytes(&standard))
}

fn final_name(file: &File) -> Result<Vec<u16>, String> {
    let mut buffer = vec![u16::MAX; 32768];
    // SAFETY: retained file plus bounded output. VOLUME_NAME_NT returns the
    // resolved native name for comparison only, never a new path to open.
    // https://learn.microsoft.com/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            VOLUME_NAME_NT,
        )
    } as usize;
    if length == 0 {
        return Err(error("Read installed image native name"));
    }
    wide_name(&buffer, length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    fn descriptor(text: &str) -> Descriptor {
        let text = wide(OsStr::new(text));
        let mut sd = ptr::null_mut();
        assert_ne!(
            unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    ptr::null_mut(),
                )
            },
            0
        );
        Descriptor(sd)
    }
    #[test]
    fn native_installation_security_descriptors_preserve_real_sid_and_ace_semantics() {
        // Exact SDDL emitted by installer-hooks.nsh; keep OWNER_RIGHTS and
        // inheritance coverage here as well as the installed-artifact test.
        let installer = descriptor(
            "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;RC;;;OW)",
        );
        assert!(unsafe { descriptor_check(installer.0, ObjectKind::Directory) }.is_ok());
        assert!(unsafe { descriptor_check(installer.0, ObjectKind::File) }.is_ok());
        let protected = descriptor("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)");
        assert!(unsafe { descriptor_check(protected.0, ObjectKind::File) }.is_ok());
        let root = descriptor("O:BAG:BAD:P(A;;FA;;;BA)(A;;0x4;;;AU)(A;;FRFX;;;BU)");
        assert!(unsafe { descriptor_check(root.0, ObjectKind::Ancestor) }.is_ok());
        assert!(unsafe { descriptor_check(root.0, ObjectKind::Directory) }.is_err());
        for permission in ["0x2", "0x100", "WD", "WO", "DC", "GW"] {
            let writable = descriptor(&format!("O:BAG:BAD:P(A;;FA;;;BA)(A;;{permission};;;BU)"));
            assert!(
                unsafe { descriptor_check(writable.0, ObjectKind::Ancestor) }.is_err(),
                "{permission}"
            );
        }
        let inherited = descriptor("O:BAG:BAD:P(A;IO;FA;;;BU)(A;;FRFX;;;BU)");
        assert!(unsafe { descriptor_check(inherited.0, ObjectKind::File) }.is_ok());
        let null = descriptor("O:BAG:BAD:NO_ACCESS_CONTROL");
        assert!(unsafe { descriptor_check(null.0, ObjectKind::File) }.is_err());
    }
    #[test]
    fn native_machine_install_base_is_protected_and_uses_global_system_drive() {
        // Read-only characterization of the machine's real trust anchors.
        // No application install, ACL change, process launch, or UAC request.
        let base = program_files().unwrap();
        let candidate = format!("{base}\\IsoHopper");
        installation_path(&candidate, &base, &system_windows().unwrap()).unwrap();
        let drive = &base[..2];
        let mapping = check_mapping(drive, None).unwrap();
        let anchors = retain_ancestors(&base).unwrap();
        assert!(anchors.len() >= 2);
        check_mapping(drive, Some(&mapping)).unwrap();
        for (file, kind) in anchors {
            check_object(&file, kind).unwrap();
        }
    }
    #[test]
    fn native_installation_rejects_portable_fixture_before_opening_helper_or_launching() {
        let fixture = tempfile::tempdir().unwrap();
        std::fs::write(
            fixture.path().join("isohopper-helper.exe"),
            b"never executable",
        )
        .unwrap();
        assert!(
            installation_path(
                fixture.path().to_str().unwrap(),
                &program_files().unwrap(),
                &system_windows().unwrap(),
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(fixture.path().join("isohopper-helper.exe")).unwrap(),
            b"never executable"
        );
    }
}
