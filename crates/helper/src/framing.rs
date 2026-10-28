// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded byte framing only; peer authentication and request semantics are separate.
//! Reads and writes can block. The transport owns cancellation and deadlines.
//! Close the connection after a framing or I/O error: bytes may have been
//! consumed or transmitted, so retrying does not safely resume the same frame.
use std::io::{self, Read, Write};

pub const MAX_FRAME_BYTES: usize = 65_536;

/// Read one nonempty frame with a four-byte big-endian payload length.
/// Clean EOF before the first header byte returns `None`; EOF inside a header
/// or payload is `UnexpectedEof`. Invalid lengths are rejected before payload
/// allocation or reads. A following frame is left untouched.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; 4];
    loop {
        match reader.read(&mut header[..1]) {
            Ok(0) => return Ok(None),
            Ok(_) => break,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    reader.read_exact(&mut header[1..])?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid frame length",
        ));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload)?;
    Ok(Some(payload))
}

/// Validate the payload, write its complete header and bytes, then flush once.
/// Invalid lengths produce `InvalidInput` without writing or flushing. Partial
/// and interrupted writes are handled by `write_all`; any final flush error is
/// returned. Successful flushing is not acknowledgement by the receiver.
pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.is_empty() || payload.len() > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid frame length",
        ));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}
