// SPDX-License-Identifier: GPL-3.0-or-later
use super::PeerError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Snapshot {
    pub volume: u64,
    pub id: [u8; 16],
    pub bytes: i64,
    pub allocated: i64,
    pub created: i64,
    pub written: i64,
    pub changed: i64,
    pub attributes: u32,
    pub links: u32,
}

pub(super) fn snapshot(id: &[u8], basic: &[u8], standard: &[u8]) -> Result<Snapshot, PeerError> {
    if id.len() != 24 || basic.len() != 40 || standard.len() != 24 {
        return Err(PeerError::Invalid("source metadata buffer size"));
    }
    let u32_at =
        |bytes: &[u8], offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let i64_at =
        |bytes: &[u8], offset| i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let attributes = u32_at(basic, 32);
    let allocated = i64_at(standard, 0);
    let bytes = i64_at(standard, 8);
    let links = u32_at(standard, 16);
    // DIRECTORY, DEVICE and REPARSE_POINT are not accepted regular sources.
    // Require false for both BOOLEAN fields without ever constructing a Rust
    // bool from driver bytes. Sparse/compressed lengths need not equal storage.
    if attributes & (0x10 | 0x40 | 0x400) != 0
        || standard[20] != 0
        || standard[21] != 0
        || allocated < 0
        || bytes < 0
        || links == 0
    {
        return Err(PeerError::Invalid("source is not a retained regular file"));
    }
    Ok(Snapshot {
        volume: u64::from_le_bytes(id[..8].try_into().unwrap()),
        id: id[8..24].try_into().unwrap(),
        bytes,
        allocated,
        created: i64_at(basic, 0),
        written: i64_at(basic, 16),
        changed: i64_at(basic, 24),
        attributes,
        links,
    })
}

pub(super) fn remote_handle(value: u64) -> Result<usize, PeerError> {
    // Windows uses 32-bit handle values for interoperability. This interface
    // deliberately supports only positive values: null, pseudo handles and
    // sign-extended/negative encodings never enter DuplicateHandle.
    // https://learn.microsoft.com/windows/win32/winprog64/interprocess-communication
    if value == 0 || value > i32::MAX as u64 {
        return Err(PeerError::Invalid("unsupported remote source handle value"));
    }
    Ok(value as usize)
}

pub(super) trait Backend {
    type Handle;
    fn peer(&mut self) -> Result<(), PeerError>;
    fn duplicate(&mut self, remote: usize) -> Result<Self::Handle, PeerError>;
    fn snapshot(&mut self, handle: &Self::Handle) -> Result<Snapshot, PeerError>;
    fn reopen(&mut self, handle: &Self::Handle) -> Result<Self::Handle, PeerError>;
}

pub(super) fn transfer<B: Backend>(backend: &mut B, remote: u64) -> Result<B::Handle, PeerError> {
    transfer_checked(backend, remote)?
}

// An outer failure means peer authentication failed. An inner failure means
// the selected file was rejected, so an authenticated caller may report why.
pub(super) fn transfer_checked<B: Backend>(
    backend: &mut B,
    remote: u64,
) -> Result<Result<B::Handle, PeerError>, PeerError> {
    match classified_transfer(backend, remote) {
        Ok(handle) => Ok(Ok(handle)),
        Err(TransferError::Source(error)) => Ok(Err(error)),
        Err(TransferError::Peer(error)) => Err(error),
    }
}

enum TransferError {
    Peer(PeerError),
    Source(PeerError),
}
fn classified_transfer<B: Backend>(
    backend: &mut B,
    remote: u64,
) -> Result<B::Handle, TransferError> {
    use TransferError::{Peer, Source};
    let remote = remote_handle(remote).map_err(Source)?;
    backend.peer().map_err(Peer)?;
    let original = backend.duplicate(remote).map_err(Source)?;
    let before = backend.snapshot(&original).map_err(Source)?;
    let reopened = backend.reopen(&original).map_err(Source)?;
    unchanged(&before, &backend.snapshot(&reopened).map_err(Source)?).map_err(Source)?;
    unchanged(&before, &backend.snapshot(&original).map_err(Source)?).map_err(Source)?;
    // The sender must still retain the same source. A closed/reused remote
    // value must not silently change which file this transfer describes.
    let fresh = backend.duplicate(remote).map_err(Source)?;
    unchanged(&before, &backend.snapshot(&fresh).map_err(Source)?).map_err(Source)?;
    backend.peer().map_err(Peer)?;
    Ok(reopened)
}

fn unchanged(before: &Snapshot, after: &Snapshot) -> Result<(), PeerError> {
    if before != after {
        return Err(PeerError::Invalid("source file changed during transfer"));
    }
    Ok(())
}
