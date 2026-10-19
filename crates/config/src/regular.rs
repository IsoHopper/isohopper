// SPDX-License-Identifier: GPL-3.0-or-later
//! File handles and path checks shared by configuration and checksum readers.
use same_file::Handle;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io,
    path::Path,
};

pub(crate) fn open(path: &Path) -> io::Result<File> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(io::Error::other(
            "input must be a regular file, not a symlink or device",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options.open(path)?;
    let info = file.metadata()?;
    if !info.is_file() {
        return Err(io::Error::other("opened input is not a regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if info.file_attributes() & 0x400 != 0 {
            return Err(io::Error::other("input is a reparse point"));
        }
    }
    Ok(file)
}

pub(crate) fn identity(file: &File) -> io::Result<Handle> {
    Handle::from_file(file.try_clone()?)
}

pub(crate) fn unchanged(
    path: &Path,
    file: &File,
    before: &Metadata,
    original: &Handle,
    bytes: u64,
) -> io::Result<()> {
    let after = file.metadata()?;
    let current = identity(&open(path)?)?;
    if &current != original
        || before.len() != bytes
        || before.len() != after.len()
        || before.modified()? != after.modified()?
    {
        return Err(io::Error::other("input changed while reading"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replacement_and_same_size_edits_fail_identity_checks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input");
        fs::write(&path, b"abc").unwrap();
        let file = open(&path).unwrap();
        let before = file.metadata().unwrap();
        let original = identity(&file).unwrap();
        fs::rename(&path, directory.path().join("old")).unwrap();
        fs::write(&path, b"abc").unwrap();
        assert!(unchanged(&path, &file, &before, &original, 3).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn regular_input_uses_nonblocking_open() {
        use std::os::fd::AsRawFd;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("input");
        fs::write(&path, b"abc").unwrap();
        let file = open(&path).unwrap();
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0 && flags & libc::O_NONBLOCK != 0);
    }
}
