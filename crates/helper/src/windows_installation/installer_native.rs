// SPDX-License-Identifier: GPL-3.0-or-later
//! Installation only: no device access, registry execution, or user-data paths.
use super::super::installer::{Backend, Error, FILES, payload_path, run};
use super::*;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    os::windows::io::FromRawHandle,
};
use windows_sys::Win32::{
    Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE},
    Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
        SECURITY_ATTRIBUTES,
    },
    Storage::FileSystem::{
        CREATE_NEW, CreateDirectoryW, CreateFileW, DELETE, FILE_ATTRIBUTE_NORMAL,
        FILE_DISPOSITION_INFO, FILE_RENAME_INFO, FileDispositionInfo, FileRenameInfo,
        SetFileInformationByHandle,
    },
};

const MAX_IMAGE_BYTES: u64 = 512 * 1024 * 1024;
// BA ownership and OWNER RIGHTS suppress the creator's implicit WRITE_DAC.
// Standard users can run the installed application, but cannot mutate it.
const INSTALL_SD: &str =
    "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)(A;OICI;RC;;;OW)";

fn descriptor() -> Result<Descriptor, String> {
    descriptor_from(INSTALL_SD)
}

fn descriptor_from(text: &str) -> Result<Descriptor, String> {
    let text = wide(OsStr::new(text));
    let mut result = ptr::null_mut();
    // SAFETY: terminated constant and owned output allocation.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            SDDL_REVISION_1,
            &mut result,
            ptr::null_mut(),
        )
    } == 0
        || result.is_null()
    {
        return Err(error("Create installation descriptor"));
    }
    Ok(Descriptor(result))
}

fn attributes(sd: &Descriptor) -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: 0,
    }
}

fn busy_or_unsafe(context: &str, error: io::Error) -> Error {
    if matches!(error.raw_os_error(), Some(32 | 33)) {
        Error::Busy
    } else {
        Error::Unsafe(format!("{context}: {error}"))
    }
}

fn require_regular(file: &File, nonempty: bool) -> Result<u64, String> {
    check_object(file, ObjectKind::File)?;
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err("Installation object is not a disk file".into());
    }
    // Integer storage avoids interpreting arbitrary native BOOLEAN bytes.
    let mut standard = [0u64; 3];
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileStandardInfo,
            standard.as_mut_ptr().cast(),
            size_of_val(&standard) as u32,
        )
    } == 0
    {
        return Err(error("Read installation file metadata"));
    }
    let bytes = unsafe {
        std::slice::from_raw_parts(standard.as_ptr().cast::<u8>(), size_of_val(&standard))
    };
    let length = i64::from_le_bytes(bytes[8..16].try_into().unwrap());
    let links = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
    if length < 0
        || (nonempty && length == 0)
        || length as u64 > MAX_IMAGE_BYTES
        || links != 1
        || bytes[20] != 0
        || bytes[21] != 0
    {
        return Err("Installation file must be a bounded single-link regular file".into());
    }
    Ok(length as u64)
}

fn digest(file: &mut File, length: u64) -> Result<[u8; 32], String> {
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut read = 0u64;
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        read = read
            .checked_add(count as u64)
            .ok_or("Image length overflow")?;
        if read > length {
            return Err("Installation image grew during verification".into());
        }
        hasher.update(&buffer[..count]);
    }
    if read != length {
        return Err("Installation image changed length".into());
    }
    Ok(hasher.finalize().into())
}

fn rename(file: &File, destination: &Path) -> Result<(), String> {
    let name: Vec<u16> = destination.as_os_str().encode_wide().collect();
    if name.is_empty() || name.len() >= 32768 || name.contains(&0) {
        return Err("Invalid installation destination".into());
    }
    // Win32 accepts a terminated path even though FileNameLength excludes
    // its NUL. Include it in both storage and the API buffer size; alignment
    // padding is not guaranteed to provide a terminator.
    let length = (offset_of!(FILE_RENAME_INFO, FileName) + (name.len() + 1) * 2)
        .max(size_of::<FILE_RENAME_INFO>());
    let mut storage = vec![0u64; length.div_ceil(8)];
    // SAFETY: aligned zeroed allocation covers the fixed header and UTF-16
    // tail including its terminator; the owned DELETE handle remains live.
    // No overwrite is permitted.
    unsafe {
        let info = storage.as_mut_ptr().cast::<FILE_RENAME_INFO>();
        (*info).Anonymous.ReplaceIfExists = false;
        (*info).RootDirectory = ptr::null_mut();
        (*info).FileNameLength = (name.len() * 2) as u32;
        let tail = ptr::addr_of_mut!((*info).FileName).cast::<u16>();
        ptr::copy_nonoverlapping(name.as_ptr(), tail, name.len());
        *tail.add(name.len()) = 0;
        if SetFileInformationByHandle(
            file.as_raw_handle(),
            FileRenameInfo,
            info.cast(),
            length as u32,
        ) == 0
        {
            return Err(error("Rename retained installation file"));
        }
    }
    Ok(())
}

fn remove(file: &File) -> Result<(), String> {
    let info = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: deletion names the retained object, not a re-opened path. On a
    // directory Windows refuses nonempty objects atomically.
    if unsafe {
        SetFileInformationByHandle(
            file.as_raw_handle(),
            FileDispositionInfo,
            (&info as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    } == 0
    {
        return Err(error("Remove retained installation object"));
    }
    Ok(())
}

fn root_handle(path: &Path) -> Result<File, io::Error> {
    open_directory_guard(path)
}

fn require_ordinary_directory(file: &File) -> Result<(), Error> {
    let metadata = file.metadata().map_err(|e| Error::Unsafe(e.to_string()))?;
    if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(Error::Unsafe(
            "Installation root is not an ordinary directory".into(),
        ));
    }
    Ok(())
}

fn prepare_root(path: &Path, sd: &Descriptor) -> Result<File, Error> {
    match root_handle(path) {
        Ok(file) => {
            require_ordinary_directory(&file)?;
            if check_object(&file, ObjectKind::Directory).is_ok() {
                return Ok(file);
            }
            // Never harden/adopt a previously writable directory. Delete the
            // exact retained object only if empty, then create a fresh object.
            // The directory guard denies delete sharing, so release it before
            // obtaining a separate exclusive deletion handle. Recheck its type
            // after reopening; never follow a replacement reparse point.
            drop(file);
            let file = OpenOptions::new()
                .access_mode(0x0002_0080 | DELETE)
                .share_mode(0)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .map_err(|e| busy_or_unsafe("Open empty installation root for replacement", e))?;
            require_ordinary_directory(&file)?;
            // Any concurrent insertion makes disposition fail; a name race
            // after close makes CREATE_DIRECTORY fail rather than adopting it.
            remove(&file).map_err(|e| {
                Error::Unsafe(format!(
                    "An unprotected installation folder must be empty: {e}"
                ))
            })?;
            drop(file);
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(busy_or_unsafe("Open installation root", error)),
    }
    let name = wide(path.as_os_str());
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes(sd)) } == 0 {
        return Err(Error::Unsafe(error("Create protected installation root")));
    }
    let file = root_handle(path).map_err(|e| busy_or_unsafe("Retain installation root", e))?;
    check_object(&file, ObjectKind::Directory).map_err(Error::Unsafe)?;
    Ok(file)
}

struct Source {
    file: File,
    stamp: ImageStamp,
    hash: [u8; 32],
}
struct Transaction {
    directory: PathBuf,
    drive: String,
    mapping: String,
    ancestors: Vec<(File, ObjectKind)>,
    root: Option<File>,
    sources: Vec<Source>,
    old: [Option<File>; 3],
    new: [Option<File>; 3],
    new_paths: [PathBuf; 3],
    old_paths: [PathBuf; 3],
    published: [bool; 3],
    sd: Descriptor,
}

impl Transaction {
    fn open(payload: &str) -> Result<Self, Error> {
        let base = program_files().map_err(Error::Payload)?;
        let windows = system_windows().map_err(Error::Payload)?;
        payload_path(payload, &base, &windows)?;
        let directory = PathBuf::from(
            installation_path(&format!("{base}\\IsoHopper"), &base, &windows)
                .map_err(Error::Unsafe)?,
        );
        let executable = std::env::current_exe().map_err(|e| Error::Payload(e.to_string()))?;
        let expected = Path::new(payload).join(FILES[1]);
        if !super::super::policy::resource_directory_matches(
            executable.to_str().unwrap_or(""),
            expected.to_str().unwrap_or(""),
        ) {
            return Err(Error::Payload(
                "The new helper must run from its protected payload directory".into(),
            ));
        }
        let drive = base[..2].to_owned();
        let mapping = check_mapping(&drive, None).map_err(Error::Payload)?;
        // Includes the protected drive root and Program Files ancestors. They
        // remain retained before the sibling destination is ever inspected.
        let ancestors = retain_ancestors(payload).map_err(Error::Payload)?;
        let mut sources = Vec::new();
        for name in FILES {
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(Path::new(payload).join(name))
                .map_err(|e| Error::Payload(format!("Open {name}: {e}")))?;
            let length = require_regular(&file, true).map_err(Error::Payload)?;
            let stamp = image_metadata(&file).map_err(Error::Payload)?;
            let hash = digest(&mut file, length).map_err(Error::Payload)?;
            if image_metadata(&file).map_err(Error::Payload)? != stamp {
                return Err(Error::Payload("Payload changed while verifying".into()));
            }
            sources.push(Source { file, stamp, hash });
        }
        let mut nonce = [0u8; 16];
        if unsafe {
            BCryptGenRandom(
                ptr::null_mut(),
                nonce.as_mut_ptr(),
                nonce.len() as u32,
                BCRYPT_USE_SYSTEM_PREFERRED_RNG,
            )
        } < 0
        {
            return Err(Error::Unsafe(
                "Cannot create installation transaction identifier".into(),
            ));
        }
        let nonce = hex::encode(nonce);
        let new_paths =
            std::array::from_fn(|i| directory.join(format!(".isohopper-{nonce}-{i}.new")));
        let old_paths =
            std::array::from_fn(|i| directory.join(format!(".isohopper-{nonce}-{i}.old")));
        Ok(Self {
            directory,
            drive,
            mapping,
            ancestors,
            root: None,
            sources,
            old: std::array::from_fn(|_| None),
            new: std::array::from_fn(|_| None),
            new_paths,
            old_paths,
            published: [false; 3],
            sd: descriptor().map_err(Error::Unsafe)?,
        })
    }

    fn revalidate(&self) -> Result<(), String> {
        check_mapping(&self.drive, Some(&self.mapping))?;
        for (file, kind) in &self.ancestors {
            check_object(file, *kind)?;
        }
        if let Some(root) = &self.root {
            check_object(root, ObjectKind::Directory)?;
        }
        for source in &self.sources {
            check_object(&source.file, ObjectKind::File)?;
            if image_metadata(&source.file)? != source.stamp {
                return Err("Retained installer payload changed".into());
            }
        }
        Ok(())
    }
}

impl Backend for Transaction {
    fn preflight(&mut self) -> Result<(), Error> {
        self.revalidate().map_err(Error::Payload)?;
        self.root = Some(prepare_root(&self.directory, &self.sd)?);
        // Every existing fixed file is exclusively opened before staging or
        // renaming anything. An app, helper, or uninstaller holding any one
        // open makes the entire transaction stop before payload mutation.
        for (i, name) in FILES.iter().enumerate() {
            match OpenOptions::new()
                .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
                .share_mode(0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(self.directory.join(name))
            {
                Ok(file) => {
                    require_regular(&file, false).map_err(Error::Unsafe)?;
                    self.old[i] = Some(file);
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(busy_or_unsafe("Open existing installation file", error)),
            }
        }
        self.revalidate().map_err(Error::Unsafe)
    }

    fn stage(&mut self, i: usize) -> Result<(), String> {
        self.revalidate()?;
        let name = wide(self.new_paths[i].as_os_str());
        // CREATE_NEW never truncates an existing object; explicit protected
        // descriptor and zero sharing apply from the instant of creation.
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                0,
                &attributes(&self.sd),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(error("Create fresh installation image"));
        }
        self.new[i] = Some(unsafe { File::from_raw_handle(handle) });
        let source = &mut self.sources[i];
        let destination = self.new[i].as_mut().unwrap();
        source
            .file
            .seek(SeekFrom::Start(0))
            .map_err(|e| e.to_string())?;
        let mut remaining = source.stamp.bytes as u64;
        let mut buffer = [0u8; 64 * 1024];
        while remaining > 0 {
            let wanted = remaining.min(buffer.len() as u64) as usize;
            let count = source
                .file
                .read(&mut buffer[..wanted])
                .map_err(|e| e.to_string())?;
            if count == 0 {
                return Err("Payload truncated during copy".into());
            }
            destination
                .write_all(&buffer[..count])
                .map_err(|e| e.to_string())?;
            remaining -= count as u64;
        }
        destination.sync_all().map_err(|e| e.to_string())?;
        if require_regular(destination, true)? != source.stamp.bytes as u64
            || digest(destination, source.stamp.bytes as u64)? != source.hash
        {
            return Err("Installed payload verification failed".into());
        }
        self.revalidate()
    }
    fn backup(&mut self, i: usize) -> Result<bool, String> {
        self.revalidate()?;
        if let Some(file) = &self.old[i] {
            rename(file, &self.old_paths[i])?;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn publish(&mut self, i: usize) -> Result<(), String> {
        self.revalidate()?;
        rename(
            self.new[i].as_ref().ok_or("Missing fresh image")?,
            &self.directory.join(FILES[i]),
        )?;
        self.published[i] = true;
        Ok(())
    }
    fn remove_new(&mut self, i: usize) -> Result<(), String> {
        if let Some(file) = &self.new[i] {
            remove(file)?;
        }
        self.new[i] = None;
        self.published[i] = false;
        Ok(())
    }
    fn restore_old(&mut self, i: usize) -> Result<(), String> {
        rename(
            self.old[i].as_ref().ok_or("Missing retained old image")?,
            &self.directory.join(FILES[i]),
        )
    }
    fn cleanup_staged(&mut self, i: usize) -> Result<(), String> {
        if self.published[i] {
            return Ok(());
        }
        if let Some(file) = &self.new[i] {
            remove(file)?;
        }
        self.new[i] = None;
        Ok(())
    }
    fn finish(&mut self) -> Result<(), String> {
        self.revalidate()?;
        for (i, file) in self.new.iter_mut().enumerate() {
            let file = file.as_mut().ok_or("Missing committed image")?;
            if require_regular(file, true)? != self.sources[i].stamp.bytes as u64
                || digest(file, self.sources[i].stamp.bytes as u64)? != self.sources[i].hash
            {
                return Err("Committed image verification failed".into());
            }
        }
        for old in &mut self.old {
            if let Some(file) = old {
                remove(file)?;
            }
            *old = None;
        }
        Ok(())
    }
}

pub fn apply(payload: &str) -> Result<(), Error> {
    let mut transaction = Transaction::open(payload)?;
    run(&mut transaction)
    // Dropping the transaction releases all three new-file locks together,
    // after verification and either commit or attempted complete rollback.
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{
        Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW,
        GROUP_SECURITY_INFORMATION, GetSecurityDescriptorControl, SE_DACL_AUTO_INHERITED,
        SE_DACL_PROTECTED, SetSecurityDescriptorControl,
    };

    fn sddl(sd: PSECURITY_DESCRIPTOR) -> String {
        let mut value = ptr::null_mut();
        let mut length = 0;
        assert_ne!(
            unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    sd,
                    SDDL_REVISION_1,
                    OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION,
                    &mut value,
                    &mut length,
                )
            },
            0
        );
        let _allocation = Descriptor(value.cast());
        assert!((1..8192).contains(&length));
        // The reported allocation can exceed the terminated text. Stop at
        // its first NUL instead of treating trailing capacity as string data.
        let end = (0..length as usize)
            .find(|index| unsafe { *value.add(*index) } == 0)
            .expect("terminated SDDL");
        assert!(end > 0);
        String::from_utf16(unsafe { std::slice::from_raw_parts(value, end) }).unwrap()
    }

    fn assert_created_descriptor(file: &File, sd: &Descriptor) {
        let mut observed = ptr::null_mut();
        assert_eq!(
            unsafe {
                GetSecurityInfo(
                    file.as_raw_handle(),
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                        | GROUP_SECURITY_INFORMATION
                        | DACL_SECURITY_INFORMATION,
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    ptr::null_mut(),
                    &mut observed,
                )
            },
            0
        );
        let observed = Descriptor(observed);
        let expected = sddl(sd.0);
        let before = sddl(observed.0);
        let mut before_control = 0;
        let mut after_control = 0;
        let mut revision = 0;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(observed.0, &mut before_control, &mut revision) },
            0
        );
        assert_eq!(before_control & SE_DACL_PROTECTED, SE_DACL_PROTECTED);
        // Match the NSIS check: normalize only the auto-inheritance-processed
        // bit in this local descriptor copy, never change the file's security.
        assert_ne!(
            unsafe { SetSecurityDescriptorControl(observed.0, SE_DACL_AUTO_INHERITED, 0) },
            0
        );
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(observed.0, &mut after_control, &mut revision) },
            0
        );
        assert_eq!(after_control, before_control & !SE_DACL_AUTO_INHERITED);
        let actual = sddl(observed.0);
        // Whole canonical text comparison also proves owner, group, every
        // ACE and protected status survive that one control-bit adjustment.
        assert_eq!(actual, before.replacen("D:PAI", "D:P", 1));
        eprintln!(
            "installer descriptor expected={expected}; observed={before}; normalized={actual}"
        );
        assert_eq!(actual, expected);
    }

    fn fresh_file(path: &Path, sd: &Descriptor) -> File {
        let name = wide(path.as_os_str());
        let handle = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE | DELETE,
                0,
                &attributes(sd),
                CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL,
                ptr::null_mut(),
            )
        };
        assert_ne!(
            handle,
            INVALID_HANDLE_VALUE,
            "{}",
            io::Error::last_os_error()
        );
        unsafe { File::from_raw_handle(handle) }
    }

    fn directory_share_diagnostics(fixture: &Path, sd: &Descriptor) {
        use windows_sys::Win32::Storage::FileSystem::{FILE_LIST_DIRECTORY, FILE_SHARE_DELETE};
        // Test-only matrix reports every candidate before the production
        // assertions. It is evidence, never a runtime fallback or policy probe.
        for (label, access) in [
            ("metadata", READ_CONTROL | FILE_READ_ATTRIBUTES),
            (
                "traverse",
                READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
            ),
            (
                "list",
                READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
            ),
        ] {
            let path = fixture.join(label);
            let name = wide(path.as_os_str());
            assert_ne!(
                unsafe { CreateDirectoryW(name.as_ptr(), &attributes(sd)) },
                0
            );
            let guard = OpenOptions::new()
                .access_mode(access)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path);
            let guard = match guard {
                Ok(guard) => guard,
                Err(error) => {
                    eprintln!(
                        "DIRECTORY_SHARE_DIAGNOSTIC access={label}; open={:?}",
                        error.raw_os_error()
                    );
                    continue;
                }
            };
            let delete = OpenOptions::new()
                .access_mode(DELETE)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&path);
            let delete_code = delete
                .as_ref()
                .err()
                .and_then(io::Error::raw_os_error)
                .unwrap_or(0);
            drop(delete);
            let moved = fixture.join(format!("{label}-moved"));
            let parent_rename = std::fs::rename(&path, &moved);
            let parent_code = parent_rename
                .as_ref()
                .err()
                .and_then(io::Error::raw_os_error)
                .unwrap_or(0);
            let current = if parent_rename.is_ok() { &moved } else { &path };
            let child = OpenOptions::new()
                .write(true)
                .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
                .share_mode(0)
                .create_new(true)
                .open(current.join("source"));
            let child_result = child
                .map_err(|error| error.to_string())
                .and_then(|file| rename(&file, &current.join("renamed")));
            eprintln!(
                "DIRECTORY_SHARE_DIAGNOSTIC access={label}; delete={delete_code}; parent_rename={parent_code}; child_rename={child_result:?}"
            );
            drop(guard);
        }
    }

    fn rename_diagnostics(point: &str, file: &File, root: &Path, expected: &Path) {
        let expected = expected
            .to_string_lossy()
            .chars()
            .take(512)
            .collect::<String>();
        let retained = final_name(file).map(|name| {
            String::from_utf16_lossy(&name)
                .chars()
                .take(512)
                .collect::<String>()
        });
        let entries = std::fs::read_dir(root)
            .map(|entries| {
                entries
                    .take(8)
                    .map(|entry| {
                        entry
                            .map(|entry| {
                                entry
                                    .file_name()
                                    .to_string_lossy()
                                    .chars()
                                    .take(128)
                                    .collect::<String>()
                            })
                            .map_err(|error| error.raw_os_error())
                    })
                    .collect::<Vec<_>>()
            })
            .map_err(|error| error.raw_os_error());
        eprintln!(
            "INSTALLER_RENAME_DIAGNOSTIC point={point}; expected={expected:?}; retained={retained:?}; entries={entries:?}"
        );
    }

    #[test]
    #[ignore = "requires administrator token to create BA-owned fixture objects; no install or device access"]
    fn native_installer_retained_file_operations_and_empty_root_recovery() {
        let fixture = tempfile::tempdir().unwrap();
        let sd = descriptor().unwrap();
        directory_share_diagnostics(fixture.path(), &sd);
        let ancestor = fixture.path().join("ancestor");
        let ancestor_guard = prepare_root(&ancestor, &sd).unwrap();
        // Test the ancestor guard before opening children, so a child handle
        // cannot accidentally supply the protection this assertion expects.
        assert_eq!(
            std::fs::rename(&ancestor, fixture.path().join("ancestor-replaced"))
                .unwrap_err()
                .raw_os_error(),
            Some(32)
        );
        let root = ancestor.join("protected");
        let root_guard = prepare_root(&root, &sd).unwrap();
        assert_created_descriptor(&root_guard, &sd);
        let delete_attempt = OpenOptions::new()
            .access_mode(DELETE)
            .share_mode(
                FILE_SHARE_READ
                    | FILE_SHARE_WRITE
                    | windows_sys::Win32::Storage::FileSystem::FILE_SHARE_DELETE,
            )
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&root)
            .unwrap_err();
        assert_eq!(delete_attempt.raw_os_error(), Some(32));
        assert_eq!(
            std::fs::rename(&root, fixture.path().join("replaced"))
                .unwrap_err()
                .raw_os_error(),
            Some(32)
        );
        // The running test executable supplies a real mapped image section,
        // separately from the explicit read handles used by the install test.
        let mapped = OpenOptions::new()
            .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE)
            .share_mode(0)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(std::env::current_exe().unwrap())
            .unwrap_err();
        assert_eq!(busy_or_unsafe("Mapped executable", mapped).code(), 10);
        let source = root.join("source.exe");
        let mut destination = root.join("destination.exe");
        let mut file = fresh_file(&source, &sd);
        file.write_all(b"verified payload").unwrap();
        file.sync_all().unwrap();
        assert_eq!(require_regular(&file, true).unwrap(), 16);
        assert_eq!(File::open(&source).unwrap_err().raw_os_error(), Some(32));
        rename_diagnostics("before", &file, &root, &source);
        rename(&file, &destination).unwrap();
        rename_diagnostics("after", &file, &root, &destination);
        assert!(!source.exists());
        assert_eq!(
            File::open(&destination).unwrap_err().raw_os_error(),
            Some(32)
        );
        // Exercise every UTF-16 tail alignment against the eight-byte
        // allocation, including the case with no incidental spare padding.
        for extra in 0..4 {
            let next = root.join(format!("renamed{}.exe", "x".repeat(extra)));
            rename(&file, &next).unwrap();
            rename_diagnostics("alignment", &file, &root, &next);
            assert!(!destination.exists());
            assert_eq!(File::open(&next).unwrap_err().raw_os_error(), Some(32));
            destination = next;
        }
        let collision = root.join("existing.exe");
        std::fs::write(&collision, b"must not overwrite").unwrap();
        assert!(rename(&file, &collision).is_err());
        assert_eq!(std::fs::read(&collision).unwrap(), b"must not overwrite");
        assert_eq!(
            digest(&mut file, 16).unwrap(),
            <[u8; 32]>::from(Sha256::digest(b"verified payload"))
        );
        remove(&file).unwrap();
        drop(file);
        assert!(!destination.exists());
        let linked_path = root.join("linked.exe");
        let mut linked = fresh_file(&linked_path, &sd);
        linked.write_all(b"linked payload").unwrap();
        drop(linked);
        std::fs::hard_link(&linked_path, root.join("alias.exe")).unwrap();
        assert!(require_regular(&File::open(&linked_path).unwrap(), true).is_err());
        drop(root_guard);
        drop(ancestor_guard);

        let unsafe_sd = descriptor_from("O:BAG:BAD:P(A;OICI;FA;;;WD)").unwrap();
        for empty in [true, false] {
            let candidate = fixture
                .path()
                .join(if empty { "empty" } else { "nonempty" });
            let path = wide(candidate.as_os_str());
            assert_ne!(
                unsafe { CreateDirectoryW(path.as_ptr(), &attributes(&unsafe_sd)) },
                0
            );
            if !empty {
                std::fs::write(candidate.join("unrelated"), b"preserved").unwrap();
            }
            let result = prepare_root(&candidate, &sd);
            if empty {
                check_object(&result.unwrap(), ObjectKind::Directory).unwrap();
            } else {
                assert_eq!(result.unwrap_err().code(), 11);
                assert_eq!(
                    std::fs::read(candidate.join("unrelated")).unwrap(),
                    b"preserved"
                );
            }
        }
    }
}
