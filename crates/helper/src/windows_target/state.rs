// SPDX-License-Identifier: GPL-3.0-or-later
use super::{
    HandleObservation, TargetError, TargetObservation, assess, candidate, resolve_interface,
};
use crate::windows_lock::TargetCoverage;
use isohopper_inventory::windows::WindowsEvidence;

// Deliberately read-only operations. A refresh always queries the retained
// target and coverage again after attempting provider collection, even when
// collection or path opening failed. No successful result survives a mismatch.
pub(super) trait Backend {
    type Handle;
    fn target(&mut self) -> Result<HandleObservation, TargetError>;
    fn coverage(&mut self) -> Result<TargetCoverage, TargetError>;
    fn collect(&mut self) -> Result<WindowsEvidence, TargetError>;
    fn interfaces(&mut self) -> Result<Vec<String>, TargetError>;
    fn open(&mut self, path: &str) -> Result<Self::Handle, TargetError>;
    fn inspect(&mut self, handle: &Self::Handle) -> Result<HandleObservation, TargetError>;
}

pub(super) fn refresh<B: Backend>(
    backend: &mut B,
    expected: &HandleObservation,
    previous: Option<(&B::Handle, &TargetObservation)>,
) -> Result<(TargetObservation, B::Handle), TargetError> {
    let before = backend.target()?;
    let coverage = backend.coverage()?;
    if &before != expected || before.device != coverage.device {
        return Err(TargetError::Mismatch(
            "retained target before provider query",
        ));
    }
    if let Some((handle, observed)) = previous
        && (backend.inspect(handle)? != before || coverage != observed.coverage)
    {
        return Err(TargetError::Mismatch(
            "retained provider or coverage before query",
        ));
    }
    let attempted = (|| {
        let evidence = backend.collect()?;
        let interfaces = backend.interfaces()?;
        let disk = candidate(&evidence, before.device.device_number)?;
        let path = disk
            .path
            .as_deref()
            .ok_or(TargetError::Invalid("provider disk path"))?;
        let interface = resolve_interface(path, &interfaces)?;
        // Open the exact enumerated spelling, never a rewritten provider path.
        let handle = backend.open(interface)?;
        let provider = backend.inspect(&handle)?;
        let result = assess(&before, &coverage, &provider, &evidence, &interfaces)?;
        Ok::<_, TargetError>((result, handle))
    })();
    let after_coverage = backend.coverage()?;
    let after = backend.target()?;
    if after != before || after_coverage != coverage {
        return Err(TargetError::Mismatch(
            "retained target or coverage after provider query",
        ));
    }
    if let Some((handle, _)) = previous
        && backend.inspect(handle)? != before
    {
        return Err(TargetError::Mismatch("retained provider after query"));
    }
    let (observed, handle) = attempted?;
    if backend.inspect(&handle)? != before {
        return Err(TargetError::Mismatch("fresh provider handle after query"));
    }
    if previous.is_some_and(|(_, old)| old != &observed) {
        return Err(TargetError::Mismatch("provider record changed"));
    }
    Ok((observed, handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        windows_identity::parse_identity,
        writer::{DeviceSnapshot, Geometry},
    };
    use isohopper_inventory::windows::WindowsEvidenceCompleteness;

    const PATH: &str = "opaque local disk interface from the OS";

    struct Mock {
        observed: HandleObservation,
        evidence: WindowsEvidence,
        events: Vec<&'static str>,
        collected: bool,
        bad_path: bool,
        os_case_variant: bool,
        ambiguous_interfaces: bool,
        collect_fails: bool,
        target_changes: bool,
        old_changes: bool,
        fresh_changes: bool,
    }

    fn fixture() -> Mock {
        let mut bytes = [0; 40];
        for (offset, value) in [(0, 40u32), (4, 40), (8, 4), (12, 7), (16, 3)] {
            bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        }
        bytes[20..36].fill(1);
        let observed = HandleObservation {
            identity: parse_identity(&bytes).unwrap(),
            device: DeviceSnapshot {
                device_number: 3,
                serial: "disk".into(),
                device_id: None,
                bus_type: 7,
                geometry: Geometry {
                    size_bytes: 1024 * 1024,
                    logical_sector_size: 512,
                    physical_sector_size: 512,
                },
            },
        };
        Mock {
            observed,
            evidence: WindowsEvidence {
                source: "mock".into(),
                disks: vec![
                    serde_json::from_value(serde_json::json!({
                        "Number":3, "Path":PATH, "UniqueId":"opaque", "UniqueIdFormat":8,
                        "SerialNumber":"disk", "FriendlyName":"disk", "Size":1048576,
                        "LogicalSectorSize":512, "PhysicalSectorSize":512, "BusType":7,
                        "IsBoot":false, "IsSystem":false, "IsReadOnly":false, "IsOffline":false,
                        "IsClustered":false, "NumberOfPartitions":0
                    }))
                    .unwrap(),
                ],
                partitions: vec![],
                issues: vec![],
                completeness: WindowsEvidenceCompleteness {
                    partition_query_complete: true,
                    partition_membership_consistent: true,
                    identity_fields_present: true,
                    geometry_fields_present: true,
                    status_fields_present: true,
                    identity_values_unique: true,
                    command_clean: true,
                },
            },
            events: vec![],
            collected: false,
            bad_path: false,
            os_case_variant: false,
            ambiguous_interfaces: false,
            collect_fails: false,
            target_changes: false,
            old_changes: false,
            fresh_changes: false,
        }
    }

    impl Backend for Mock {
        type Handle = u8;
        fn target(&mut self) -> Result<HandleObservation, TargetError> {
            self.events.push("target");
            let mut result = self.observed.clone();
            if self.target_changes && self.collected {
                result.device.serial.push('x');
            }
            Ok(result)
        }
        fn coverage(&mut self) -> Result<TargetCoverage, TargetError> {
            self.events.push("coverage");
            Ok(TargetCoverage {
                device: self.observed.device.clone(),
                partition_style: 2,
                layout_identity: [0; 16],
                partitions: vec![],
            })
        }
        fn collect(&mut self) -> Result<WindowsEvidence, TargetError> {
            self.events.push("collect");
            self.collected = true;
            if self.collect_fails {
                return Err(TargetError::Invalid("mock provider failure"));
            }
            let mut result = self.evidence.clone();
            if self.bad_path {
                result.disks[0].path = Some(r"\\.\pipe\untrusted".into());
            }
            Ok(result)
        }
        fn interfaces(&mut self) -> Result<Vec<String>, TargetError> {
            self.events.push("interfaces");
            if self.ambiguous_interfaces {
                return Ok(vec![PATH.into(), PATH.to_ascii_uppercase()]);
            }
            Ok(vec![if self.os_case_variant {
                PATH.to_ascii_uppercase()
            } else {
                PATH.into()
            }])
        }
        fn open(&mut self, path: &str) -> Result<u8, TargetError> {
            self.events.push("open");
            let expected = if self.os_case_variant {
                PATH.to_ascii_uppercase()
            } else {
                PATH.into()
            };
            assert_eq!(path, expected);
            Ok(2)
        }
        fn inspect(&mut self, handle: &u8) -> Result<HandleObservation, TargetError> {
            self.events.push(if *handle == 1 { "old" } else { "fresh" });
            let mut result = self.observed.clone();
            if (*handle == 1 && self.old_changes && self.collected)
                || (*handle == 2 && self.fresh_changes)
            {
                result.device.serial.push('x');
            }
            Ok(result)
        }
    }

    #[test]
    fn refresh_brackets_collection_and_retains_fresh_handle() {
        let mut backend = fixture();
        let expected = backend.observed.clone();
        let (old, handle) = refresh(&mut backend, &expected, None).unwrap();
        assert_eq!(handle, 2);
        backend.events.clear();
        backend.collected = false;
        let (again, _) = refresh(&mut backend, &expected, Some((&1, &old))).unwrap();
        assert_eq!(again, old);
        assert_eq!(
            backend.events,
            [
                "target",
                "coverage",
                "old",
                "collect",
                "interfaces",
                "open",
                "fresh",
                "coverage",
                "target",
                "old",
                "fresh"
            ]
        );
    }

    #[test]
    fn case_matching_opens_original_os_entry_and_keeps_provider_spelling() {
        let mut backend = fixture();
        backend.os_case_variant = true;
        let expected = backend.observed.clone();
        let (observed, _) = refresh(&mut backend, &expected, None).unwrap();
        assert_eq!(observed.interface_path, PATH.to_ascii_uppercase());
        assert_eq!(observed.disk.path.as_deref(), Some(PATH));
        assert!(backend.events.contains(&"open"));
        backend.collected = false;
        assert_eq!(
            refresh(&mut backend, &expected, Some((&1, &observed)))
                .unwrap()
                .0,
            observed
        );
        backend.collected = false;
        backend.os_case_variant = false;
        assert!(matches!(
            refresh(&mut backend, &expected, Some((&1, &observed))),
            Err(TargetError::Mismatch("provider record changed"))
        ));
    }

    #[test]
    fn unlisted_paths_never_reach_open_and_failed_collection_is_bracketed() {
        let mut ambiguous = fixture();
        ambiguous.ambiguous_interfaces = true;
        let expected = ambiguous.observed.clone();
        assert!(refresh(&mut ambiguous, &expected, None).is_err());
        assert!(!ambiguous.events.contains(&"open"));
        let mut backend = fixture();
        let expected = backend.observed.clone();
        backend.bad_path = true;
        assert!(refresh(&mut backend, &expected, None).is_err());
        assert_eq!(
            backend.events,
            [
                "target",
                "coverage",
                "collect",
                "interfaces",
                "coverage",
                "target"
            ]
        );
        backend.events.clear();
        backend.collect_fails = true;
        backend.target_changes = true;
        backend.collected = false;
        assert!(matches!(
            refresh(&mut backend, &expected, None),
            Err(TargetError::Mismatch(
                "retained target or coverage after provider query"
            ))
        ));
        assert_eq!(
            backend.events,
            ["target", "coverage", "collect", "coverage", "target"]
        );
    }

    #[test]
    fn same_path_rebinding_and_retained_provider_changes_are_rejected() {
        let mut backend = fixture();
        let expected = backend.observed.clone();
        let (old, _) = refresh(&mut backend, &expected, None).unwrap();
        backend.collected = false;
        backend.fresh_changes = true;
        assert!(refresh(&mut backend, &expected, Some((&1, &old))).is_err());
        backend.collected = false;
        backend.fresh_changes = false;
        backend.old_changes = true;
        assert!(matches!(
            refresh(&mut backend, &expected, Some((&1, &old))),
            Err(TargetError::Mismatch("retained provider after query"))
        ));
    }

    #[test]
    fn provider_identity_and_safety_flags_must_remain_exact_on_refresh() {
        for mutate in [
            (|e: &mut WindowsEvidence| e.disks[0].unique_id = Some("Opaque".into()))
                as fn(&mut WindowsEvidence),
            |e| e.disks[0].unique_id_format = Some(3),
            |e| e.disks[0].is_system = Some(true),
            |e| e.disks[0].is_read_only = None,
        ] {
            let mut backend = fixture();
            let expected = backend.observed.clone();
            let (old, _) = refresh(&mut backend, &expected, None).unwrap();
            backend.collected = false;
            mutate(&mut backend.evidence);
            assert!(matches!(
                refresh(&mut backend, &expected, Some((&1, &old))),
                Err(TargetError::Mismatch("provider record changed"))
            ));
        }
    }

    #[test]
    fn interface_multisz_requires_termination_valid_utf16_and_unique_bounded_entries() {
        let list: Vec<_> = "one\0two\0\0".encode_utf16().collect();
        assert_eq!(
            super::super::parse_interfaces(&list).unwrap(),
            ["one", "two"]
        );
        assert!(super::super::parse_interfaces(&[0]).unwrap().is_empty());
        for invalid in [
            vec![],
            vec![b'a' as u16],
            vec![b'a' as u16, 0],
            vec![0, b'a' as u16],
            vec![0xd800, 0, 0],
            "one\0one\0\0".encode_utf16().collect(),
            "line\n\0\0".encode_utf16().collect(),
        ] {
            assert!(super::super::parse_interfaces(&invalid).is_err());
        }
        assert!(
            super::super::parse_interfaces(&vec![b'a' as u16; super::super::MAX_PATH_UNITS + 2])
                .is_err()
        );
        let many: Vec<_> = (0..257)
            .flat_map(|i| format!("{i}\0").encode_utf16().collect::<Vec<_>>())
            .chain(Some(0))
            .collect();
        assert!(super::super::parse_interfaces(&many).is_err());
    }
}
