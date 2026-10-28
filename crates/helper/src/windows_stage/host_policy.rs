// SPDX-License-Identifier: GPL-3.0-or-later
use super::StageError;
use crate::{windows_sources::SourceExtent, writer::DeviceSnapshot};

pub(super) fn single_host(
    extents: &[SourceExtent],
    host: &DeviceSnapshot,
    target: &DeviceSnapshot,
) -> Result<(), StageError> {
    let [extent] = extents else {
        return Err(StageError::Invalid(
            "stage volume requires one physical extent",
        ));
    };
    host.geometry
        .validate()
        .map_err(|_| StageError::Invalid("stage host geometry"))?;
    target
        .geometry
        .validate()
        .map_err(|_| StageError::Invalid("stage target geometry"))?;
    let sector = u64::from(host.geometry.logical_sector_size);
    if host.device_number != extent.disk_number
        || host.device_number == target.device_number
        || extent.length_bytes == 0
        || !extent.start_offset.is_multiple_of(sector)
        || !extent.length_bytes.is_multiple_of(sector)
        || extent
            .start_offset
            .checked_add(extent.length_bytes)
            .is_none_or(|end| end > host.geometry.size_bytes)
    {
        return Err(StageError::Invalid(
            "stage host extent differs or overlaps target",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::Geometry;
    fn disk(number: u32) -> DeviceSnapshot {
        DeviceSnapshot {
            device_number: number,
            serial: format!("disk-{number}"),
            device_id: None,
            bus_type: 17,
            geometry: Geometry {
                size_bytes: 1 << 30,
                logical_sector_size: 512,
                physical_sector_size: 4096,
            },
        }
    }
    #[test]
    fn host_requires_one_matching_extent_disjoint_from_target() {
        let extent = SourceExtent {
            disk_number: 1,
            start_offset: 1 << 20,
            length_bytes: 512 << 20,
        };
        assert!(single_host(std::slice::from_ref(&extent), &disk(1), &disk(2)).is_ok());
        assert!(single_host(&[], &disk(1), &disk(2)).is_err());
        assert!(single_host(&[extent.clone(), extent.clone()], &disk(1), &disk(2)).is_err());
        assert!(single_host(std::slice::from_ref(&extent), &disk(3), &disk(2)).is_err());
        assert!(single_host(&[extent], &disk(1), &disk(1)).is_err());
    }
    #[test]
    fn host_rejects_unaligned_empty_overflowing_or_outside_ranges() {
        for (start, length) in [
            (1, 512),
            (512, 1),
            (512, 0),
            (u64::MAX - 511, 1024),
            (1 << 30, 512),
        ] {
            assert!(
                single_host(
                    &[SourceExtent {
                        disk_number: 1,
                        start_offset: start,
                        length_bytes: length
                    }],
                    &disk(1),
                    &disk(2)
                )
                .is_err()
            );
        }
    }
}
