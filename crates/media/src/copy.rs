// SPDX-License-Identifier: GPL-3.0-or-later
//! Verified copies into a caller-authorized, retained destination directory.
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use same_file::Handle;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read, Seek, Write},
    sync::atomic::{AtomicBool, Ordering},
};

const CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone)]
pub struct CopyEntry {
    pub relative_path: String,
    pub bytes: u64,
    pub sha256: [u8; 32],
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    CheckingSource,
    Writing,
    Flushing,
    Verifying,
    Complete,
}
#[derive(Debug, Clone, Copy)]
pub struct Progress {
    pub phase: Phase,
    pub completed_bytes: u64,
    pub total_bytes: u64,
}
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct CopyError {
    pub message: String,
    pub destination_incomplete: bool,
    pub bytes_written: u64,
    pub cancelled: bool,
}
#[derive(Debug)]
pub struct Report {
    pub bytes_written: u64,
    pub bytes_verified: u64,
    pub sha256: [u8; 32],
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn error(error: io::Error, destination_incomplete: bool, bytes_written: u64) -> CopyError {
    CopyError {
        cancelled: error.get_ref().is_some_and(|e| e.is::<Cancelled>()),
        message: error.to_string(),
        destination_incomplete,
        bytes_written,
    }
}
fn validate_entry(entry: &CopyEntry) -> io::Result<()> {
    crate::relative_path(&entry.relative_path).map_err(|e| invalid(&e.to_string()))?;
    if entry.bytes == 0
        || entry.bytes > i64::MAX as u64
        || entry.relative_path.split('/').count() > 33
    {
        return Err(invalid("image size or directory depth is unsupported"));
    }
    for part in entry.relative_path.split('/') {
        let stem = part
            .split('.')
            .next()
            .unwrap_or("")
            .trim_end()
            .to_uppercase();
        let reserved_port = ["COM", "LPT"].iter().any(|prefix| {
            stem.strip_prefix(prefix).is_some_and(|n| {
                matches!(
                    n,
                    "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        });
        if part.encode_utf16().count() > 255
            || part.ends_with(['.', ' '])
            || part.contains(['<', '>', '"', '|', '?', '*'])
            || matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
            )
            || reserved_port
        {
            return Err(invalid(
                "image path contains a name that is not portable to Windows",
            ));
        }
    }
    Ok(())
}

/// Validate all paths before mutation. `available` must already exclude the
/// caller's filesystem metadata reserve; this is an allocation estimate only.
/// Actual create/write failures (including filesystem-specific collisions) are
/// still handled without overwriting an existing destination.
pub fn validate_manifest(
    entries: &[CopyEntry],
    available: u64,
    allocation_unit: u64,
) -> Result<u64, CopyError> {
    let validate = || -> io::Result<u64> {
        if entries.is_empty()
            || entries.len() > 10_000
            || !(512..=2 * 1024 * 1024).contains(&allocation_unit)
            || !allocation_unit.is_power_of_two()
        {
            return Err(invalid("invalid copy manifest count or allocation unit"));
        }
        let mut files = BTreeSet::new();
        let mut folders = BTreeSet::new();
        let mut allocated = 0u64;
        for entry in entries {
            validate_entry(entry)?;
            let path = entry.relative_path.to_uppercase();
            if folders.contains(&path) || !files.insert(path.clone()) {
                return Err(invalid("duplicate or conflicting destination path"));
            }
            for (offset, _) in path.match_indices('/') {
                let parent = &path[..offset];
                if files.contains(parent) {
                    return Err(invalid("image path conflicts with a parent directory"));
                }
                folders.insert(parent.to_string());
            }
            let rounded = entry
                .bytes
                .checked_add(allocation_unit - 1)
                .map(|n| n / allocation_unit * allocation_unit)
                .ok_or_else(|| invalid("copy size overflow"))?;
            allocated = allocated
                .checked_add(rounded)
                .ok_or_else(|| invalid("copy size overflow"))?;
        }
        if allocated > available {
            return Err(invalid("insufficient destination space"));
        }
        Ok(allocated)
    };
    validate().map_err(|e| error(e, false, 0))
}

#[derive(Debug, thiserror::Error)]
#[error("copy cancelled")]
struct Cancelled;

fn check_cancel(cancel: &AtomicBool) -> io::Result<()> {
    if cancel.load(Ordering::Relaxed) {
        Err(io::Error::new(io::ErrorKind::Interrupted, Cancelled))
    } else {
        Ok(())
    }
}
fn at_eof(reader: &mut impl Read, cancel: &AtomicBool) -> io::Result<bool> {
    loop {
        check_cancel(cancel)?;
        match reader.read(&mut [0]) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => return result.map(|count| count == 0),
        }
    }
}
fn emit(progress: &mut impl FnMut(Progress), phase: Phase, completed_bytes: u64, total_bytes: u64) {
    progress(Progress {
        phase,
        completed_bytes,
        total_bytes,
    });
}
fn hash_exact(
    reader: &mut impl Read,
    bytes: u64,
    cancel: &AtomicBool,
    progress: &mut impl FnMut(Progress),
    phase: Phase,
    buffer: &mut [u8],
) -> io::Result<[u8; 32]> {
    let mut hash = Sha256::new();
    let mut completed = 0;
    emit(progress, phase, 0, bytes);
    while completed < bytes {
        check_cancel(cancel)?;
        let count = (bytes - completed).min(buffer.len() as u64) as usize;
        reader.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        completed += count as u64;
        emit(progress, phase, completed, bytes);
    }
    check_cancel(cancel)?;
    if !at_eof(reader, cancel)? {
        return Err(invalid("file grew beyond its declared size"));
    }
    Ok(hash.finalize().into())
}

// Account only confirmed bytes, retrying OS interruption separately from cancellation.
fn write_chunk(
    destination: &mut impl Write,
    buffer: &[u8],
    cancel: &AtomicBool,
    written: &mut u64,
) -> io::Result<()> {
    let mut offset = 0;
    while offset < buffer.len() {
        check_cancel(cancel)?;
        let count = match destination.write(&buffer[offset..]) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if count == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        if count > buffer.len() - offset {
            return Err(invalid("invalid write byte count"));
        }
        offset += count;
        *written += count as u64;
    }
    Ok(())
}

/// Copy from an already retained regular source into an already authorized
/// directory capability. This does not select/elevate/authorize a USB device.
/// Caller must hold its target-volume identity/ownership through this call.
/// Parent directories are opened without following symlinks. Files are always
/// create-new; incomplete files remain on failure for an explicit retry policy.
/// Cancellation is observed between synchronous I/O operations.
pub fn copy_one(
    root: &Dir,
    source: &mut File,
    entry: &CopyEntry,
    cancel: &AtomicBool,
    mut progress: impl FnMut(Progress),
) -> Result<Report, CopyError> {
    let mut destination_created = false;
    let mut written = 0;
    let mut operation = || -> io::Result<Report> {
        validate_entry(entry)?;
        check_cancel(cancel)?;
        let before = source.metadata()?;
        if !before.is_file() || before.len() != entry.bytes {
            return Err(invalid("source is not a regular file of the declared size"));
        }
        let modified = before.modified()?;
        let mut buffer = vec![0; CHUNK_BYTES];
        source.rewind()?;
        if hash_exact(
            source,
            entry.bytes,
            cancel,
            &mut progress,
            Phase::CheckingSource,
            &mut buffer,
        )? != entry.sha256
        {
            return Err(invalid("source SHA-256 changed since import"));
        }
        let checked = source.metadata()?;
        if checked.len() != entry.bytes || checked.modified()? != modified {
            return Err(invalid("source changed while checking"));
        }
        check_cancel(cancel)?;
        source.rewind()?;
        let mut parent = root.try_clone()?;
        let components: Vec<_> = entry.relative_path.split('/').collect();
        for component in &components[..components.len() - 1] {
            check_cancel(cancel)?;
            match parent.create_dir(component) {
                Ok(()) => (),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e),
            }
            parent = parent.open_dir_nofollow(component)?;
        }
        let mut options = OpenOptions::new();
        options
            .read(true)
            .write(true)
            .create_new(true)
            .follow(FollowSymlinks::No);
        let mut destination = parent.open_with(components.last().unwrap(), &options)?;
        destination_created = true;
        let destination_identity = Handle::from_file(destination.try_clone()?.into_std())?;
        let mut source_hash = Sha256::new();
        emit(&mut progress, Phase::Writing, 0, entry.bytes);
        while written < entry.bytes {
            check_cancel(cancel)?;
            let count = (entry.bytes - written).min(buffer.len() as u64) as usize;
            source.read_exact(&mut buffer[..count])?;
            source_hash.update(&buffer[..count]);
            write_chunk(&mut destination, &buffer[..count], cancel, &mut written)?;
            emit(&mut progress, Phase::Writing, written, entry.bytes);
        }
        if !at_eof(source, cancel)? || <[u8; 32]>::from(source_hash.finalize()) != entry.sha256 {
            return Err(invalid("source changed during copy"));
        }
        let after = source.metadata()?;
        if after.len() != entry.bytes || after.modified()? != modified {
            return Err(invalid("source metadata changed during copy"));
        }
        check_cancel(cancel)?;
        emit(&mut progress, Phase::Flushing, written, entry.bytes);
        destination.sync_all()?;
        destination.rewind()?;
        let digest = hash_exact(
            &mut destination,
            entry.bytes,
            cancel,
            &mut progress,
            Phase::Verifying,
            &mut buffer,
        )?;
        if digest != entry.sha256 {
            return Err(invalid("destination SHA-256 failed readback verification"));
        }
        if destination.metadata()?.len() != entry.bytes {
            return Err(invalid("destination length changed during verification"));
        }
        // Re-resolve every parent from the retained root. Checking only the
        // earlier parent handle misses a directory renamed/replaced mid-copy.
        let mut current_parent = root.try_clone()?;
        for component in &components[..components.len() - 1] {
            current_parent = current_parent.open_dir_nofollow(component)?;
        }
        let mut read_options = OpenOptions::new();
        read_options.read(true).follow(FollowSymlinks::No);
        #[cfg(unix)]
        {
            use cap_std::fs::OpenOptionsExt;
            read_options.custom_flags(rustix::fs::OFlags::NONBLOCK.bits() as i32);
        }
        if !current_parent
            .symlink_metadata(components.last().unwrap())?
            .is_file()
        {
            return Err(invalid("destination path no longer names a regular file"));
        }
        let current = current_parent.open_with(components.last().unwrap(), &read_options)?;
        if Handle::from_file(current.into_std())? != destination_identity {
            return Err(invalid("destination path was replaced during copy"));
        }
        check_cancel(cancel)?;
        emit(&mut progress, Phase::Complete, written, entry.bytes);
        Ok(Report {
            bytes_written: written,
            bytes_verified: entry.bytes,
            sha256: digest,
        })
    };
    operation().map_err(|e| error(e, destination_created, written))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn an_os_interruption_is_not_a_user_cancellation() {
        assert!(!error(io::ErrorKind::Interrupted.into(), true, 23).cancelled);
    }

    struct ShortWriter {
        calls: usize,
        fail: bool,
        data: Vec<u8>,
    }
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.calls += 1;
            if self.calls == 1 {
                return Err(io::ErrorKind::Interrupted.into());
            }
            if self.fail && self.calls == 3 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            let count = bytes.len().min(2);
            self.data.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn interrupted_short_writes_retry_and_failed_write_keeps_exact_byte_count() {
        for fail in [false, true] {
            let mut target = ShortWriter {
                calls: 0,
                fail,
                data: Vec::new(),
            };
            let mut written = 0;
            let result = write_chunk(
                &mut target,
                b"abcdef",
                &AtomicBool::new(false),
                &mut written,
            );
            if fail {
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WriteZero);
                assert_eq!(written, 2);
                assert_eq!(target.data, b"ab");
            } else {
                result.unwrap();
                assert_eq!(written, 6);
                assert_eq!(target.data, b"abcdef");
            }
        }
    }
}
