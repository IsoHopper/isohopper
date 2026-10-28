// SPDX-License-Identifier: GPL-3.0-or-later
//! Whole-image execution on an already authorized, locked, retained device.
//! This module performs no elevation, device selection, path opening or locking.
use sha2::{Digest, Sha256};
use std::{
    alloc::{Layout, alloc_zeroed, dealloc},
    io::{self, Read, Seek, SeekFrom},
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

#[cfg(windows)]
pub mod windows;
#[cfg(any(windows, test))]
mod windows_metadata;

pub const CHUNK_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Geometry {
    pub size_bytes: u64,
    pub logical_sector_size: u32,
    pub physical_sector_size: u32,
}

impl Geometry {
    pub fn validate(&self) -> Result<(), Failure> {
        if ![512, 4096].contains(&self.logical_sector_size)
            || self.physical_sector_size < self.logical_sector_size
            || self.physical_sector_size > 65_536
            || u64::from(self.physical_sector_size) > self.size_bytes
            || !self.physical_sector_size.is_power_of_two()
            || self.size_bytes == 0
            || self.size_bytes > i64::MAX as u64
            || !self
                .size_bytes
                .is_multiple_of(u64::from(self.logical_sector_size))
        {
            return Err(Failure::Geometry);
        }
        Ok(())
    }

    #[cfg(any(windows, test))]
    fn check_io(&self, offset: u64, pointer: usize, length: usize) -> io::Result<()> {
        self.validate()
            .map_err(|_| io::Error::other("unsupported device geometry"))?;
        if length == 0
            || length > CHUNK_BYTES
            || !length.is_multiple_of(self.logical_sector_size as usize)
            || !offset.is_multiple_of(u64::from(self.logical_sector_size))
            || !pointer.is_multiple_of(self.physical_sector_size as usize)
            || offset > self.size_bytes
            || length as u64 > self.size_bytes - offset
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unaligned or out-of-bounds device I/O",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StableDeviceId([u8; 16]);

impl StableDeviceId {
    /// A device-associated, binary IEEE registered extended (NAA 6) identifier.
    /// This validates the supported encoding, not the device's trustworthiness.
    pub fn from_naa128(bytes: [u8; 16]) -> Result<Self, Failure> {
        if bytes[0] >> 4 != 6 {
            return Err(Failure::Identity);
        }
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceSnapshot {
    pub device_number: u32,
    /// Actual hardware serial, empty only when the device reports none.
    pub serial: String,
    pub device_id: Option<StableDeviceId>,
    pub bus_type: u32,
    pub geometry: Geometry,
}

impl DeviceSnapshot {
    pub(crate) fn validate_identity(&self) -> Result<(), Failure> {
        if (self.serial.is_empty() && self.device_id.is_none())
            || (!self.serial.is_empty() && self.serial.trim().is_empty())
            || self.serial.len() > 4096
            || self.serial.chars().any(char::is_control)
        {
            return Err(Failure::Identity);
        }
        Ok(())
    }
}

/// Implementations must use the same device handle throughout the job.
/// Reads and writes must return actual byte counts, never silently pad data.
pub trait RetainedDevice {
    fn snapshot(&mut self) -> io::Result<DeviceSnapshot>;
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> io::Result<usize>;
    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> io::Result<usize>;
    fn flush(&mut self) -> io::Result<()>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    CheckingSource,
    Writing,
    Flushing,
    Verifying,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Progress {
    pub phase: Phase,
    pub completed_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum Failure {
    #[error("invalid or unsupported device geometry")]
    Geometry,
    #[error("device identity is missing or invalid")]
    Identity,
    #[error("device identity or geometry changed")]
    IdentityChanged,
    #[error("source length does not exactly equal device capacity")]
    SourceSize,
    #[error("source SHA-256 does not match the approved image")]
    SourceDigest,
    #[error("device readback SHA-256 does not match the approved image")]
    ReadbackDigest,
    #[error("operation cancelled")]
    Cancelled,
    #[error("device returned a short read")]
    ShortRead,
    #[error("device returned a short write")]
    ShortWrite,
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
#[error(
    "{failure}; phase={phase:?}, target_may_be_incomplete={target_may_be_incomplete}, confirmed_bytes_written={bytes_written}"
)]
pub struct WriteError {
    pub failure: Failure,
    pub phase: Phase,
    pub target_may_be_incomplete: bool,
    pub bytes_written: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub bytes_written: u64,
    pub bytes_verified: u64,
    pub sha256: [u8; 32],
}

/// Copy an approved whole-device image, then flush and hash its full readback.
///
/// The caller must independently authorize the target, retain all volume locks,
/// and bind the source handle and digest to the approved job. This function does
/// not establish those permissions. Source changes detected after the first
/// write leave an explicitly incomplete target. Cancellation is checked between
/// I/O calls; it cannot interrupt an already blocked synchronous driver call.
pub fn write_image(
    device: &mut impl RetainedDevice,
    source: &mut (impl Read + Seek),
    expected: &DeviceSnapshot,
    expected_sha256: [u8; 32],
    cancel: &AtomicBool,
    mut progress: impl FnMut(Progress),
) -> Result<Report, WriteError> {
    let mut state = State {
        phase: Phase::CheckingSource,
        started: false,
        written: 0,
    };
    execute(
        device,
        source,
        expected,
        expected_sha256,
        cancel,
        &mut progress,
        &mut state,
    )
    .map_err(|failure| WriteError {
        failure,
        phase: state.phase,
        target_may_be_incomplete: state.started,
        bytes_written: state.written,
    })
}

struct State {
    phase: Phase,
    started: bool,
    written: u64,
}

fn cancelled(cancel: &AtomicBool) -> Result<(), Failure> {
    if cancel.load(Ordering::Acquire) {
        Err(Failure::Cancelled)
    } else {
        Ok(())
    }
}

fn unchanged(device: &mut impl RetainedDevice, expected: &DeviceSnapshot) -> Result<(), Failure> {
    if device.snapshot()? != *expected {
        return Err(Failure::IdentityChanged);
    }
    Ok(())
}

fn source_size(source: &mut (impl Read + Seek), size: u64) -> Result<(), Failure> {
    if source.seek(SeekFrom::End(0))? != size {
        return Err(Failure::SourceSize);
    }
    source.seek(SeekFrom::Start(0))?;
    Ok(())
}

fn read_source(
    source: &mut impl Read,
    mut buffer: &mut [u8],
    cancel: &AtomicBool,
) -> Result<(), Failure> {
    while !buffer.is_empty() {
        cancelled(cancel)?;
        match source.read(buffer) {
            Ok(0) => return Err(Failure::SourceSize),
            Ok(count) => buffer = &mut buffer[count..],
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn source_eof(source: &mut impl Read, cancel: &AtomicBool) -> Result<(), Failure> {
    loop {
        cancelled(cancel)?;
        match source.read(&mut [0; 1]) {
            Ok(0) => return Ok(()),
            Ok(_) => return Err(Failure::SourceSize),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

fn execute(
    device: &mut impl RetainedDevice,
    source: &mut (impl Read + Seek),
    expected: &DeviceSnapshot,
    digest: [u8; 32],
    cancel: &AtomicBool,
    progress: &mut impl FnMut(Progress),
    state: &mut State,
) -> Result<Report, Failure> {
    expected.geometry.validate()?;
    expected.validate_identity()?;
    cancelled(cancel)?;
    unchanged(device, expected)?;
    let size = expected.geometry.size_bytes;
    let mut allocation = AlignedBuffer::new(expected.geometry.physical_sector_size as usize)?;
    let buffer = allocation.as_mut();
    source_size(source, size)?;
    progress(Progress {
        phase: state.phase,
        completed_bytes: 0,
        total_bytes: size,
    });
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < size {
        let count = (size - offset).min(CHUNK_BYTES as u64) as usize;
        read_source(source, &mut buffer[..count], cancel)?;
        hash.update(&buffer[..count]);
        offset += count as u64;
        progress(Progress {
            phase: state.phase,
            completed_bytes: offset,
            total_bytes: size,
        });
    }
    source_eof(source, cancel)?;
    if <[u8; 32]>::from(hash.finalize()) != digest {
        return Err(Failure::SourceDigest);
    }
    source_size(source, size)?;
    unchanged(device, expected)?;
    state.phase = Phase::Writing;
    progress(Progress {
        phase: state.phase,
        completed_bytes: 0,
        total_bytes: size,
    });
    let mut copied = Sha256::new();
    while state.written < size {
        let count = (size - state.written).min(CHUNK_BYTES as u64) as usize;
        read_source(source, &mut buffer[..count], cancel)?;
        cancelled(cancel)?;
        // A failing write may still modify media. Mark the target incomplete
        // before the call, even if the driver does not return a byte count.
        state.started = true;
        if device.write_at(state.written, &buffer[..count])? != count {
            return Err(Failure::ShortWrite);
        }
        copied.update(&buffer[..count]);
        state.written += count as u64;
        progress(Progress {
            phase: state.phase,
            completed_bytes: state.written,
            total_bytes: size,
        });
    }
    source_eof(source, cancel)?;
    if <[u8; 32]>::from(copied.finalize()) != digest {
        return Err(Failure::SourceDigest);
    }
    state.phase = Phase::Flushing;
    progress(Progress {
        phase: state.phase,
        completed_bytes: 0,
        total_bytes: size,
    });
    cancelled(cancel)?;
    device.flush()?;
    unchanged(device, expected)?;
    state.phase = Phase::Verifying;
    progress(Progress {
        phase: state.phase,
        completed_bytes: 0,
        total_bytes: size,
    });
    let mut verified = Sha256::new();
    offset = 0;
    while offset < size {
        cancelled(cancel)?;
        let count = (size - offset).min(CHUNK_BYTES as u64) as usize;
        if device.read_at(offset, &mut buffer[..count])? != count {
            return Err(Failure::ShortRead);
        }
        verified.update(&buffer[..count]);
        offset += count as u64;
        progress(Progress {
            phase: state.phase,
            completed_bytes: offset,
            total_bytes: size,
        });
    }
    cancelled(cancel)?;
    if <[u8; 32]>::from(verified.finalize()) != digest {
        return Err(Failure::ReadbackDigest);
    }
    unchanged(device, expected)?;
    state.phase = Phase::Complete;
    progress(Progress {
        phase: state.phase,
        completed_bytes: size,
        total_bytes: size,
    });
    Ok(Report {
        bytes_written: size,
        bytes_verified: size,
        sha256: digest,
    })
}

struct AlignedBuffer {
    pointer: NonNull<u8>,
    layout: Layout,
}

impl AlignedBuffer {
    fn new(alignment: usize) -> io::Result<Self> {
        let layout = Layout::from_size_align(CHUNK_BYTES, alignment)
            .map_err(|_| io::Error::other("invalid buffer alignment"))?;
        // SAFETY: layout has a nonzero size and a validated power-of-two alignment.
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) }).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::OutOfMemory,
                "aligned buffer allocation failed",
            )
        })?;
        Ok(Self { pointer, layout })
    }

    fn as_mut(&mut self) -> &mut [u8] {
        // SAFETY: the allocation is live, initialized, exactly layout.size()
        // bytes long, and exclusively borrowed for the slice's lifetime.
        unsafe { std::slice::from_raw_parts_mut(self.pointer.as_ptr(), self.layout.size()) }
    }
}

impl Drop for AlignedBuffer {
    fn drop(&mut self) {
        // SAFETY: pointer came from alloc_zeroed with this exact layout and
        // has not been freed; all borrowed slices end before drop.
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_transfer_bounds_reject_overflow_and_all_alignment_errors() {
        let g = Geometry {
            size_bytes: 2 * CHUNK_BYTES as u64,
            logical_sector_size: 512,
            physical_sector_size: 4096,
        };
        assert!(g.check_io(0, 4096, CHUNK_BYTES).is_ok());
        assert!(g.check_io(g.size_bytes - 512, 4096, 512).is_ok());
        for (offset, pointer, length) in [
            (0, 4096, 0),
            (0, 4096, 513),
            (1, 4096, 512),
            (0, 4097, 512),
            (0, 4096, CHUNK_BYTES + 512),
            (g.size_bytes, 4096, 512),
            (u64::MAX, 4096, 512),
            (u64::MAX - 511, 4096, CHUNK_BYTES),
        ] {
            assert!(g.check_io(offset, pointer, length).is_err());
        }
        let mut invalid = g;
        invalid.logical_sector_size = 0;
        assert!(invalid.check_io(0, 0, 512).is_err());
    }
}
