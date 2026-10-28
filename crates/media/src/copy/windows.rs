// SPDX-License-Identifier: GPL-3.0-or-later
//! One-component directory creation relative to an already retained parent.
//!
//! cap-primitives 4.0.3 implements Windows mkdir by obtaining a DOS path, which
//! fails for volumes without a drive letter. File opens are already relative.
//! Keep this operation relative too; do not reconstruct or resolve a pathname.
//! https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
//! https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew

use cap_std::fs::Dir;
use std::{
    fs::File,
    io,
    os::windows::{
        fs::MetadataExt,
        io::{AsRawHandle, FromRawHandle},
    },
    ptr::{null, null_mut},
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_DIRECTORY_FILE, FILE_OPEN_IF, FILE_OPEN_REPARSE_POINT,
            FILE_SYNCHRONOUS_IO_NONALERT, NtCreateFile,
        },
    },
    Win32::{
        Foundation::{
            INVALID_HANDLE_VALUE, OBJ_CASE_INSENSITIVE, RtlNtStatusToDosError, STATUS_SUCCESS,
            UNICODE_STRING,
        },
        Storage::FileSystem::{
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
            FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_READ_EA, FILE_SHARE_READ,
            FILE_SHARE_WRITE, FILE_TRAVERSE, READ_CONTROL, SYNCHRONIZE,
        },
        System::{
            IO::IO_STATUS_BLOCK,
            WindowsProgramming::{FILE_CREATED, FILE_OPENED},
        },
    },
};

pub(super) fn open_or_create_parent(parent: &Dir, component: &str) -> io::Result<Dir> {
    // The full copy path has already passed validate_entry. Repeat the crucial
    // containment and length constraints at this private native API boundary.
    if component.contains('/') || crate::relative_path(component).is_err() {
        return Err(super::invalid(
            "directory name must be one relative component",
        ));
    }
    let mut name: Vec<u16> = component.encode_utf16().collect();
    if name.len() > 255 {
        return Err(super::invalid("directory name exceeds 255 UTF-16 units"));
    }
    let name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_mut_ptr(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle(),
        ObjectName: &name,
        Attributes: OBJ_CASE_INSENSITIVE, // Deliberately no OBJ_INHERIT.
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut status_block = IO_STATUS_BLOCK::default();
    let mut handle = null_mut();
    // SAFETY: the parent and bounded single-component UTF-16 name stay live.
    // The new handle is synchronous, so all output storage remains live until
    // completion. OPEN_IF never overwrites; OPEN_REPARSE_POINT opens an existing
    // final reparse point itself for rejection below. No intermediate component
    // exists to traverse, and no caller-provided flags or absolute paths enter.
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_LIST_DIRECTORY
                | FILE_TRAVERSE
                | FILE_READ_ATTRIBUTES
                | FILE_READ_EA
                | READ_CONTROL
                | SYNCHRONIZE,
            &attributes,
            &mut status_block,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE, // Preserve cap-std's no-delete sharing.
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
            null(),
            0,
        )
    };
    if status != STATUS_SUCCESS {
        // SAFETY: this is a scalar status conversion, with no borrowed storage.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::other(
            "directory open returned an invalid handle",
        ));
    }
    // SAFETY: successful NtCreateFile returned a new, uniquely owned handle.
    let directory = unsafe { File::from_raw_handle(handle) };
    if status_block.Information != FILE_CREATED as usize
        && status_block.Information != FILE_OPENED as usize
    {
        return Err(io::Error::other("unexpected directory open disposition"));
    }
    let attributes = directory.metadata()?.file_attributes();
    if attributes & FILE_ATTRIBUTE_DIRECTORY == 0 || attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(super::invalid(
            "destination parent is not a plain directory",
        ));
    }
    Ok(Dir::from_std_file(directory))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_parent_creation_rejects_non_components_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let root = Dir::open_ambient_dir(temp.path(), cap_std::ambient_authority()).unwrap();
        for component in [
            "",
            ".",
            "..",
            "a/b",
            "a\\b",
            "C:escape",
            "/root",
            "x\0y",
            &"a".repeat(256),
        ] {
            assert_eq!(
                open_or_create_parent(&root, component).unwrap_err().kind(),
                io::ErrorKind::InvalidInput,
                "{component:?}",
            );
        }
        assert_eq!(root.entries().unwrap().count(), 0);
    }

    #[test]
    fn native_parent_handle_is_not_inherited_and_denies_rename_while_retained() {
        use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE_FLAG_INHERIT};

        let temp = tempfile::tempdir().unwrap();
        let root = Dir::open_ambient_dir(temp.path(), cap_std::ambient_authority()).unwrap();
        let child = open_or_create_parent(&root, "child").unwrap();
        let mut flags = 0;
        // SAFETY: retained live handle and initialized writable output.
        assert_ne!(
            unsafe { GetHandleInformation(child.as_raw_handle(), &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        assert!(std::fs::rename(temp.path().join("child"), temp.path().join("renamed")).is_err());
        drop(child);
        std::fs::rename(temp.path().join("child"), temp.path().join("renamed")).unwrap();
    }
}
