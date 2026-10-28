// SPDX-License-Identifier: GPL-3.0-or-later
use std::io;

pub(super) const MAX_DESCRIPTOR: usize = 65_536;
const DESCRIPTOR_PREFIX: usize = 36;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid storage device descriptor",
    )
}

fn number(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let value = bytes.get(offset..offset + 4).ok_or_else(invalid)?;
    Ok(u32::from_le_bytes(value.try_into().map_err(|_| invalid())?))
}

pub(super) fn descriptor_size(header: &[u8]) -> io::Result<usize> {
    let version = number(header, 0)? as usize;
    let size = number(header, 4)? as usize;
    if !(DESCRIPTOR_PREFIX..=MAX_DESCRIPTOR).contains(&size)
        || !(DESCRIPTOR_PREFIX..=size).contains(&version)
    {
        return Err(invalid());
    }
    Ok(size)
}

pub(super) fn parse_descriptor(bytes: &[u8]) -> io::Result<(String, u32)> {
    let size = descriptor_size(bytes)?;
    let bytes = bytes.get(..size).ok_or_else(invalid)?;
    if bytes[8] != 0 || number(bytes, 32)? as usize > size - DESCRIPTOR_PREFIX {
        return Err(invalid());
    }
    let offset = number(bytes, 24)? as usize;
    if !(DESCRIPTOR_PREFIX..size).contains(&offset) {
        return Err(invalid());
    }
    let serial = &bytes[offset..];
    let end = serial
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(invalid)?;
    if end == 0 || end > 4096 || !serial[..end].iter().all(|b| (0x20..=0x7e).contains(b)) {
        return Err(invalid());
    }
    let serial = std::str::from_utf8(&serial[..end])
        .map_err(|_| invalid())?
        .trim()
        .to_owned();
    if serial.is_empty() {
        return Err(invalid());
    }
    Ok((serial, number(bytes, 28)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> Vec<u8> {
        let mut bytes = vec![0; 48];
        bytes[..4].copy_from_slice(&36u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&48u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&36u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&7u32.to_le_bytes());
        bytes[36..43].copy_from_slice(b"SERIAL1");
        bytes
    }

    #[test]
    fn bounded_descriptor_extracts_serial_and_bus() {
        let bytes = descriptor();
        assert_eq!(descriptor_size(&bytes[..8]).unwrap(), 48);
        assert_eq!(parse_descriptor(&bytes).unwrap(), ("SERIAL1".into(), 7));
    }

    #[test]
    fn descriptor_rejects_missing_short_oversized_or_inconsistent_data() {
        let original = descriptor();
        for len in 0..original.len() {
            assert!(parse_descriptor(&original[..len]).is_err());
        }
        for (at, value) in [
            (0, 0),
            (0, 49),
            (4, u32::MAX),
            (4, 35),
            (24, 0),
            (24, 8),
            (24, 48),
            (24, u32::MAX),
            (32, u32::MAX),
        ] {
            let mut bytes = original.clone();
            bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert!(parse_descriptor(&bytes).is_err(), "{at}, {value}");
        }
    }

    #[test]
    fn descriptor_rejects_non_disk_missing_terminator_and_invalid_serial() {
        for (at, value) in [(8, 5), (36, 0), (36, 0xff), (36, b'\n')] {
            let mut bytes = descriptor();
            bytes[at] = value;
            assert!(parse_descriptor(&bytes).is_err());
        }
        let mut bytes = descriptor();
        bytes[36..].fill(b'X');
        assert!(parse_descriptor(&bytes).is_err());
        bytes[36..43].fill(b' ');
        bytes[43] = 0;
        assert!(parse_descriptor(&bytes).is_err());
    }
}
