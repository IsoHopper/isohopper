// SPDX-License-Identifier: GPL-3.0-or-later
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ImageStamp {
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

pub(super) fn image_stamp(id: &[u8], basic: &[u8], standard: &[u8]) -> Result<ImageStamp, String> {
    if id.len() != 24 || basic.len() != 40 || standard.len() != 24 {
        return Err("Invalid installed-image metadata length".into());
    }
    let word =
        |bytes: &[u8], offset| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let wide =
        |bytes: &[u8], offset| i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
    let attributes = word(basic, 32);
    let allocated = wide(standard, 0);
    let bytes = wide(standard, 8);
    let links = word(standard, 16);
    // Integer storage avoids constructing a Rust bool from either BOOLEAN.
    if attributes & (0x10 | 0x40 | 0x400) != 0
        || standard[20] != 0
        || standard[21] != 0
        || allocated < 0
        || bytes <= 0
        || links == 0
    {
        return Err("Installed image is not a nonempty retained regular file".into());
    }
    Ok(ImageStamp {
        volume: u64::from_le_bytes(id[..8].try_into().unwrap()),
        id: id[8..24].try_into().unwrap(),
        bytes,
        allocated,
        created: wide(basic, 0),
        written: wide(basic, 16),
        changed: wide(basic, 24),
        attributes,
        links,
    })
}

pub(crate) fn wide_name(buffer: &[u16], length: usize) -> Result<Vec<u16>, String> {
    if length == 0
        || length >= 32768
        || length >= buffer.len()
        || buffer[length] != 0
        || buffer[..length].contains(&0)
        || String::from_utf16(&buffer[..length]).is_err()
    {
        return Err("Invalid or unsupported native image name".into());
    }
    Ok(buffer[..length].to_vec())
}
