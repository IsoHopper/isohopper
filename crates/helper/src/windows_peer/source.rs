// SPDX-License-Identifier: GPL-3.0-or-later
//! Handle-only source transfer. No path lookup, file data reads or write grant.
use super::{PeerError, PeerEvidence, observe};
use std::{
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{DuplicateHandle, GetLastError, INVALID_HANDLE_VALUE, SetLastError},
    Storage::FileSystem::{
        FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_BASIC_INFO, FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_ID_INFO,
        FILE_INFO_BY_HANDLE_CLASS, FILE_SHARE_READ, FILE_STANDARD_INFO, FILE_TYPE_DISK,
        FILE_TYPE_UNKNOWN, FileBasicInfo, FileIdInfo, FileStandardInfo,
        GetFileInformationByHandleEx, GetFileType, ReOpenFile,
    },
    System::Threading::GetCurrentProcess,
};
#[path = "source/decode.rs"]
mod decode;
use decode::{Backend, Snapshot};

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
    assert!(FILE_ATTRIBUTE_DIRECTORY == 0x10);
    assert!(FILE_ATTRIBUTE_DEVICE == 0x40);
    assert!(FILE_ATTRIBUTE_REPARSE_POINT == 0x400);
};

pub(super) fn receive(
    process: &OwnedHandle,
    evidence: &PeerEvidence,
    remote: u64,
) -> Result<File, PeerError> {
    let handle = decode::transfer(&mut Native { process, evidence }, remote)?;
    Ok(File::from(handle))
}

pub(super) fn receive_checked(
    process: &OwnedHandle,
    evidence: &PeerEvidence,
    remote: u64,
) -> Result<Result<File, PeerError>, PeerError> {
    let handle = decode::transfer_checked(&mut Native { process, evidence }, remote)?;
    // Only the synchronous, read-only, reclassified ReOpenFile result reaches
    // this conversion. Unknown duplicated kernel objects never become Files.
    Ok(handle.map(File::from))
}

struct Native<'a> {
    process: &'a OwnedHandle,
    evidence: &'a PeerEvidence,
}

impl Backend for Native<'_> {
    type Handle = OwnedHandle;

    fn peer(&mut self) -> Result<(), PeerError> {
        crate::windows_peer::decode::unchanged(self.evidence, &observe(self.process)?)
    }

    fn duplicate(&mut self, remote: usize) -> Result<OwnedHandle, PeerError> {
        let mut handle = ptr::null_mut();
        // SAFETY: the retained process was classified by ProcessPeer; this call
        // validates the remote value in that process. It never closes the
        // remote handle or transfers ownership of it. Output is local and
        // non-inheritable, with explicit read rights (not SAME_ACCESS).
        // File rights cannot be increased by DuplicateHandle:
        // https://learn.microsoft.com/windows/win32/api/handleapi/nf-handleapi-duplicatehandle
        if unsafe {
            DuplicateHandle(
                self.process.as_raw_handle(),
                remote as _,
                GetCurrentProcess(),
                &mut handle,
                FILE_GENERIC_READ,
                0,
                0,
            )
        } == 0
        {
            return Err(os_error("duplicate source file"));
        }
        owned(handle, "duplicated source handle")
    }

    fn snapshot(&mut self, handle: &OwnedHandle) -> Result<Snapshot, PeerError> {
        // SAFETY: every input is an owned local DuplicateHandle/ReOpenFile
        // result. GetFileType safely rejects other kernel object kinds.
        let kind = unsafe {
            SetLastError(0);
            GetFileType(handle.as_raw_handle())
        };
        if kind != FILE_TYPE_DISK {
            if kind == FILE_TYPE_UNKNOWN && unsafe { GetLastError() } != 0 {
                return Err(os_error("source file type"));
            }
            return Err(PeerError::Invalid("source handle is not a disk file"));
        }
        // Integer-only aligned storage avoids forming Rust bools from the SDK
        // BOOLEAN fields. Fixed ABI assertions above protect decoder offsets.
        let mut id = [u64::MAX; 3];
        let mut basic = [u64::MAX; 5];
        let mut standard = [u64::MAX; 3];
        query(handle, FileIdInfo, &mut id, "source file ID")?;
        query(handle, FileBasicInfo, &mut basic, "source basic metadata")?;
        query(
            handle,
            FileStandardInfo,
            &mut standard,
            "source standard metadata",
        )?;
        decode::snapshot(bytes(&id), bytes(&basic), bytes(&standard))
    }

    fn reopen(&mut self, handle: &OwnedHandle) -> Result<OwnedHandle, PeerError> {
        // SAFETY: a successful regular-file snapshot precedes this call.
        // ReOpenFile uses that retained object, never a pathname. Omitting
        // OVERLAPPED/NO_BUFFERING creates a synchronous buffered read handle;
        // omitting share-write/delete refuses existing incompatible opens.
        // https://learn.microsoft.com/windows/win32/api/winbase/nf-winbase-reopenfile
        let raw = unsafe {
            ReOpenFile(
                handle.as_raw_handle(),
                FILE_GENERIC_READ,
                FILE_SHARE_READ,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        if raw == INVALID_HANDLE_VALUE {
            return Err(os_error("reopen source read-only"));
        }
        owned(raw, "reopened source handle")
    }
}

fn os_error(stage: &'static str) -> PeerError {
    PeerError::Io {
        stage,
        source: io::Error::last_os_error(),
    }
}

fn owned(
    raw: windows_sys::Win32::Foundation::HANDLE,
    label: &'static str,
) -> Result<OwnedHandle, PeerError> {
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(PeerError::Invalid(label));
    }
    // SAFETY: callers invoke this only after successful local-handle creation.
    Ok(unsafe { OwnedHandle::from_raw_handle(raw) })
}

fn query(
    handle: &OwnedHandle,
    class: FILE_INFO_BY_HANDLE_CLASS,
    output: &mut [u64],
    stage: &'static str,
) -> Result<(), PeerError> {
    // SAFETY: retained, classified disk-file handle and aligned initialized
    // output sized to its fixed class. This metadata API is synchronous even
    // when the original file handle was opened for overlapped data I/O.
    if unsafe {
        GetFileInformationByHandleEx(
            handle.as_raw_handle(),
            class,
            output.as_mut_ptr().cast(),
            size_of_val(output) as u32,
        )
    } == 0
    {
        return Err(os_error(stage));
    }
    Ok(())
}

fn bytes(words: &[u64]) -> &[u8] {
    // SAFETY: exposes only initialized integer storage; lifetime stays borrowed.
    unsafe { std::slice::from_raw_parts(words.as_ptr().cast(), size_of_val(words)) }
}
