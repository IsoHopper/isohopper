// SPDX-License-Identifier: GPL-3.0-or-later
use super::{
    HandleObservation, MAX_INTERFACE_UNITS, TargetError, TargetObservation, parse_interfaces,
    resolve_interface,
    state::{self, Backend},
};
use crate::{
    windows_identity::query_identity,
    windows_lock::{TargetCoverage, TargetVolumeProbe},
    writer::{DeviceSnapshot, windows::inspect},
};
use isohopper_inventory::windows::{WindowsEvidence, collect_evidence};
use std::{
    fs::OpenOptions,
    os::windows::{fs::OpenOptionsExt, io::OwnedHandle},
    ptr,
};
use windows_sys::Win32::{
    Devices::DeviceAndDriverInstallation::{
        CM_GET_DEVICE_INTERFACE_LIST_PRESENT, CM_Get_Device_Interface_List_SizeW,
        CM_Get_Device_Interface_ListW, CR_BUFFER_SMALL, CR_SUCCESS,
    },
    Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE},
    System::Ioctl::GUID_DEVINTERFACE_DISK,
};

/// Owns read-only target/provider handles and complete target volume coverage.
/// This owner exposes observations only: no handle extraction, writing, locks,
/// dismounts, elevation or overall safety verdict. Synchronous OS calls may
/// block. Retention detects identity changes but does not freeze device state.
pub struct BoundTarget {
    target: OwnedHandle,
    provider: OwnedHandle,
    probe: TargetVolumeProbe,
    observation: TargetObservation,
}

impl BoundTarget {
    /// Acquire a read-only target using a current disk-interface selector.
    /// The candidate is never opened directly: only one matching entry from
    /// the current GUID_DEVINTERFACE_DISK list may be opened, using that entry's
    /// exact spelling. Native identity, geometry and provider/volume coverage
    /// are derived from retained handles; no caller snapshot is trusted.
    ///
    /// This performs no write, lock, dismount or elevation and grants no
    /// preparation permission. Synchronous device/provider queries may block.
    pub fn open_present_interface(candidate: &str) -> Result<Self, TargetError> {
        let interfaces = present_interfaces()?;
        let selected = resolve_interface(candidate, &interfaces)?;
        let target = open_enumerated_interface(selected)?;
        // SAFETY: the selected interface was opened read-only, synchronously,
        // without OVERLAPPED; this owner retains it throughout every query.
        let initial = unsafe { observe_handle(&target)? };
        // SAFETY: ownership of that same synchronous read-only handle moves
        // into the existing full binding path, with its own observed snapshot.
        let bound = unsafe { Self::from_owned_handle(target, &initial.device)? };
        if bound.observation.handle != initial {
            return Err(TargetError::Mismatch(
                "selected interface changed during binding",
            ));
        }
        Ok(bound)
    }

    /// Correlate a fresh provider record with an already retained target.
    /// The target path is never reconstructed from an OS disk number. Full-path
    /// ASCII case comparison selects one present GUID_DEVINTERFACE_DISK entry;
    /// its exact enumerated spelling is opened and native identity is checked.
    /// Other spelling differences are unsupported. UniqueId and UniqueIdFormat
    /// are retained as opaque metadata.
    ///
    /// # Safety
    /// `target` must be a live whole-disk handle opened with read access only,
    /// synchronously without FILE_FLAG_OVERLAPPED. No other user of a duplicate
    /// handle may close it or change its synchronous I/O contract. `expected`
    /// describes this target; disagreement is rejected before provider access.
    pub unsafe fn from_owned_handle(
        target: OwnedHandle,
        expected: &DeviceSnapshot,
    ) -> Result<Self, TargetError> {
        // SAFETY: the caller establishes a live synchronous target handle.
        let initial = unsafe { observe_handle(&target)? };
        if &initial.device != expected {
            return Err(TargetError::Mismatch("initial retained target"));
        }
        let duplicate = target.try_clone().map_err(|source| TargetError::Io {
            stage: "retaining target coverage handle",
            source,
        })?;
        // SAFETY: this is a duplicate of the same synchronous read-only disk
        // object; the probe performs metadata IOCTLs without changing offsets.
        let mut probe = unsafe { TargetVolumeProbe::from_owned_handle(duplicate, expected)? };
        let (observation, provider) = state::refresh(
            &mut Native {
                target: &target,
                probe: &mut probe,
            },
            &initial,
            None,
        )?;
        Ok(Self {
            target,
            provider,
            probe,
            observation,
        })
    }

    /// Last validated diagnostic record. Call `revalidate` before relying on
    /// its freshness. A previous successful observation is not a current grant.
    pub fn observation(&self) -> &TargetObservation {
        &self.observation
    }

    /// Observe BitLocker for this owner's exact retained volume coverage.
    /// Recheck native identity, provider records and topology on both sides of
    /// collection, including when collection fails. The report preserves
    /// unsupported providers and unknown values; it is not permission to write.
    /// No independently reconstructed probe or caller-supplied disk is used.
    pub fn observe_encryption(
        &mut self,
    ) -> Result<crate::windows_encryption_check::EncryptionReport, TargetError> {
        self.revalidate()?;
        let report = crate::windows_encryption_check::observe_for_probe(&mut self.probe);
        self.revalidate()?;
        let report = report?;
        if report.coverage != self.observation.coverage {
            return Err(TargetError::Mismatch("encryption target coverage"));
        }
        Ok(report)
    }

    /// Requery both retained handles, target volume topology, present disk
    /// interfaces, the current path binding, and exact provider disk/partition
    /// records. Failures do not update the last successful observation.
    pub fn revalidate(&mut self) -> Result<&TargetObservation, TargetError> {
        let (observed, fresh) = state::refresh(
            &mut Native {
                target: &self.target,
                probe: &mut self.probe,
            },
            &self.observation.handle,
            Some((&self.provider, &self.observation)),
        )?;
        // Keep the original provider handle throughout future revalidations;
        // the fresh handle was held through this round's final observations.
        drop(fresh);
        self.observation = observed;
        Ok(&self.observation)
    }

    /// Internal preparation handoff. Re-enumerate the exact interface and
    /// independently compare the new writable handle before acquiring locks.
    /// The preparation owner has already checked protected storage and status;
    /// this method does not create a generic path-based writer capability.
    pub(crate) fn lock_for_preparation(
        mut self,
    ) -> Result<crate::windows_lock::LockedWindowsDevice, crate::windows_lock::ObservedLockError>
    {
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_NO_BUFFERING, FILE_FLAG_WRITE_THROUGH,
        };
        self.revalidate()?;
        let interfaces = present_interfaces()?;
        let selected = resolve_interface(&self.observation.interface_path, &interfaces)?;
        let handle: OwnedHandle = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .custom_flags(FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH)
            .open(selected)
            .map_err(|source| TargetError::Io {
                stage: "opening observed preparation target",
                source,
            })?
            .into();
        // SAFETY: unique synchronous handle opened above without OVERLAPPED.
        // Metadata comparison precedes any lock, dismount or write operation.
        if unsafe { observe_handle(&handle)? } != self.observation.handle {
            return Err(TargetError::Mismatch("writable target handoff").into());
        }
        // SAFETY: this exact owned handle was opened read/write, unbuffered and
        // write-through, is not duplicated, and moves into its private owner.
        let device = unsafe { crate::writer::windows::WindowsRawDevice::from_owned_handle(handle) }
            .map_err(|source| TargetError::Io {
                stage: "validating writable target",
                source,
            })?;
        if device.initial_snapshot() != &self.observation.handle.device {
            return Err(TargetError::Mismatch("writable device snapshot").into());
        }
        crate::windows_lock::lock_observed(device, self)
    }
}

struct Native<'a> {
    target: &'a OwnedHandle,
    probe: &'a mut TargetVolumeProbe,
}

impl Backend for Native<'_> {
    type Handle = OwnedHandle;
    fn target(&mut self) -> Result<HandleObservation, TargetError> {
        // SAFETY: BoundTarget's constructor establishes synchronous ownership.
        unsafe { observe_handle(self.target) }
    }
    fn coverage(&mut self) -> Result<TargetCoverage, TargetError> {
        Ok(self.probe.revalidate()?.clone())
    }
    fn collect(&mut self) -> Result<WindowsEvidence, TargetError> {
        Ok(collect_evidence()?)
    }
    fn interfaces(&mut self) -> Result<Vec<String>, TargetError> {
        present_interfaces()
    }
    fn open(&mut self, path: &str) -> Result<OwnedHandle, TargetError> {
        // state::refresh selected this exact entry from the immediately preceding
        // present disk-interface query. No string enters a shell or command.
        open_enumerated_interface(path)
    }
    fn inspect(&mut self, handle: &OwnedHandle) -> Result<HandleObservation, TargetError> {
        // SAFETY: every provider handle comes from the synchronous read-only
        // open above and remains owned while all metadata queries complete.
        unsafe { observe_handle(handle) }
    }
}

// Both callers first resolve this exact string from the current CM list.
fn open_enumerated_interface(path: &str) -> Result<OwnedHandle, TargetError> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
        .open(path)
        .map(Into::into)
        .map_err(|source| TargetError::Io {
            stage: "opening provider disk interface read-only",
            source,
        })
}

unsafe fn observe_handle(handle: &OwnedHandle) -> Result<HandleObservation, TargetError> {
    // SAFETY: callers maintain live synchronous handle ownership for both calls.
    let identity = unsafe { query_identity(handle)? };
    let device = unsafe { inspect(handle) }.map_err(|source| TargetError::Io {
        stage: "querying retained target metadata",
        source,
    })?;
    if identity.device_number() != device.device_number {
        return Err(TargetError::Mismatch("native identity queries"));
    }
    Ok(HandleObservation { identity, device })
}

// The class identifies disk interfaces, not arbitrary paths. Microsoft says
// not to parse device-interface symbolic names; only original CM entries are
// opened, then native handle identity establishes the target.
// https://learn.microsoft.com/en-us/windows-hardware/drivers/install/guid-devinterface-disk
// https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetdeviceinterfacedetailw
// Lengths are UTF-16 units. Hotplug can grow the list between the two calls;
// only CR_BUFFER_SMALL retries, and a continually changing list remains unknown.
// https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_get_device_interface_listw
fn present_interfaces() -> Result<Vec<String>, TargetError> {
    for _ in 0..3 {
        let mut length = 0u32;
        // SAFETY: all pointers refer to live initialized storage; a null device
        // ID requests all currently present interfaces of this fixed class.
        let status = unsafe {
            CM_Get_Device_Interface_List_SizeW(
                &mut length,
                &GUID_DEVINTERFACE_DISK,
                ptr::null(),
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
            )
        };
        if status != CR_SUCCESS {
            return Err(TargetError::ConfigurationManager(status));
        }
        if length == 0 || length as usize > MAX_INTERFACE_UNITS {
            return Err(TargetError::Invalid("present disk interface list size"));
        }
        let mut units = vec![0u16; length as usize];
        // SAFETY: the initialized UTF-16 buffer has exactly the advertised
        // capacity. This API is synchronous and retains no caller pointers.
        let status = unsafe {
            CM_Get_Device_Interface_ListW(
                &GUID_DEVINTERFACE_DISK,
                ptr::null(),
                units.as_mut_ptr(),
                length,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT,
            )
        };
        if status == CR_BUFFER_SMALL {
            continue;
        }
        if status != CR_SUCCESS {
            return Err(TargetError::ConfigurationManager(status));
        }
        return parse_interfaces(&units);
    }
    Err(TargetError::Invalid(
        "present disk interface list kept changing",
    ))
}
