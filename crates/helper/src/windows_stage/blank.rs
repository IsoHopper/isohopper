// SPDX-License-Identifier: GPL-3.0-or-later
//! Content proof for a newly created, privately owned staging disk only.
use super::StageError;
use crate::windows_lock::TargetCoverage;
use std::{
    io::{self, Read, Seek},
    sync::atomic::{AtomicBool, Ordering},
};

pub(super) fn verify(
    reader: &mut (impl Read + Seek),
    coverage: &TargetCoverage,
    cancel: &AtomicBool,
) -> Result<(), StageError> {
    let fail = |operation, source| StageError::Io { operation, source };
    coverage
        .device
        .geometry
        .validate()
        .map_err(|_| StageError::Geometry)?;
    if coverage.device.bus_type != 15
        || ![0, 2].contains(&coverage.partition_style)
        || !coverage.partitions.is_empty()
    {
        return Err(fail(
            "blank stage layout",
            io::Error::other(format!(
                "style={} partitions={} bus={}",
                coverage.partition_style,
                coverage.partitions.len(),
                coverage.device.bus_type
            )),
        ));
    }
    if cancel.load(Ordering::Relaxed) {
        return Err(StageError::Invalid("staging cancelled"));
    }
    reader.rewind().map_err(|e| fail("rewind blank stage", e))?;
    let mut buffer = [0u8; 65536];
    let mut offset = 0;
    let bytes = coverage.device.geometry.size_bytes;
    while offset < bytes {
        if cancel.load(Ordering::Relaxed) {
            return Err(StageError::Invalid("staging cancelled"));
        }
        let length = (bytes - offset).min(buffer.len() as u64) as usize;
        reader
            .read_exact(&mut buffer[..length])
            .map_err(|e| fail("read blank stage", e))?;
        if let Some(index) = buffer[..length].iter().position(|&byte| byte != 0) {
            return Err(fail(
                "blank stage contents",
                io::Error::other(format!("nonzero byte at offset {}", offset + index as u64)),
            ));
        }
        offset += length as u64;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        windows_lock::PartitionCoverage,
        writer::{DeviceSnapshot, Geometry},
    };
    use std::io::{Cursor, SeekFrom};

    fn coverage(style: u32) -> TargetCoverage {
        TargetCoverage {
            device: DeviceSnapshot {
                device_number: 8,
                serial: "owned-fixture".into(),
                device_id: None,
                bus_type: 15,
                geometry: Geometry {
                    size_bytes: 131_072,
                    logical_sector_size: 512,
                    physical_sector_size: 4096,
                },
            },
            partition_style: style,
            layout_identity: [0; 16],
            partitions: vec![],
        }
    }
    #[test]
    fn blank_mbr_and_raw_read_exact_capacity_from_zero() {
        for style in [0, 2] {
            let mut reader = Cursor::new(vec![0; 131_072]);
            reader.seek(SeekFrom::Start(512)).unwrap();
            verify(&mut reader, &coverage(style), &AtomicBool::new(false)).unwrap();
            assert_eq!(reader.position(), 131_072);
        }
    }
    #[test]
    fn nonzero_first_middle_and_last_byte_are_refused() {
        for offset in [0, 440, 65536, 131071] {
            let mut bytes = vec![0; 131_072];
            bytes[offset] = 1;
            assert!(
                verify(
                    &mut Cursor::new(bytes),
                    &coverage(0),
                    &AtomicBool::new(false)
                )
                .is_err()
            );
        }
    }
    #[test]
    fn truncated_and_cancelled_scans_are_refused() {
        assert!(
            verify(
                &mut Cursor::new(vec![0; 65536]),
                &coverage(2),
                &AtomicBool::new(false)
            )
            .is_err()
        );
        let mut reader = Cursor::new(vec![0; 131_072]);
        assert!(verify(&mut reader, &coverage(2), &AtomicBool::new(true)).is_err());
        assert_eq!(reader.position(), 0);
    }
    #[test]
    fn other_layouts_partitions_and_nonvirtual_devices_are_refused_before_io() {
        let mut cases: Vec<_> = [1, 3, u32::MAX].into_iter().map(coverage).collect();
        let mut partitioned = coverage(0);
        partitioned.partitions.push(PartitionCoverage {
            partition_number: 1,
            start_offset: 512,
            length_bytes: 512,
            partition_type: [0; 16],
            partition_identity: [0; 16],
            volume_guid: None,
            volume_required: false,
        });
        cases.push(partitioned);
        let mut physical = coverage(2);
        physical.device.bus_type = 7;
        cases.push(physical);
        for item in cases {
            let mut reader = Cursor::new(vec![0; 131_072]);
            assert!(verify(&mut reader, &item, &AtomicBool::new(false)).is_err());
            assert_eq!(reader.position(), 0);
        }
    }
}
