// SPDX-License-Identifier: GPL-3.0-or-later
//! Storage binding for this module's own sealed file, never an arbitrary path.
use super::*;
use crate::{
    windows_preparation_target::require_stage_host_pool,
    windows_sources::{SourceExtent, no_virtual_dependencies, source_guid, volume_extents},
    windows_target::BoundTarget,
    writer::DeviceSnapshot,
};
use isohopper_inventory::{
    windows::collect_evidence,
    windows_pools::{self, PhysicalDiskPools},
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFinalPathNameByHandleW, VOLUME_NAME_GUID, WofIsExternalFile,
};

fn evidence(operation: &'static str, e: impl std::fmt::Display) -> StageError {
    error(operation, io::Error::other(e.to_string()))
}
fn final_name(file: &File) -> Result<Vec<u16>, StageError> {
    let mut path = vec![0; 32768];
    // SAFETY: live synchronous file and bounded initialized UTF16 output.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            path.as_mut_ptr(),
            path.len() as u32,
            VOLUME_NAME_GUID,
        )
    } as usize;
    if length == 0 {
        return Err(error("sealed file name", io::Error::last_os_error()));
    }
    if length >= path.len() || path[length] != 0 {
        return Err(StageError::Invalid("sealed file name bounds"));
    }
    path.truncate(length);
    Ok(path)
}
fn inline(stage: &SealedStage) -> Result<(), StageError> {
    stage.revalidate()?;
    let before = final_name(&stage.reader)?;
    let path = wide(&stage.owner.directory.join(FINAL))?;
    let mut external = i32::MIN;
    // SAFETY: fixed file created by this owner, protected retained ancestor
    // chain and nondelete-share final handle. Optional provider outputs unused.
    let status = unsafe {
        WofIsExternalFile(
            path.as_ptr(),
            &mut external,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    stage.revalidate()?;
    if final_name(&stage.reader)? != before {
        return Err(StageError::Invalid("sealed file name changed"));
    }
    if status != 0 {
        return Err(evidence(
            "sealed inline backing",
            format_args!("HRESULT {:#010x}", status as u32),
        ));
    }
    if external != 0 {
        return Err(StageError::Invalid(
            "sealed file is externally backed or status unknown",
        ));
    }
    Ok(())
}

/// A sealed image whose one native host disk is distinct from the expected
/// target, has no reported virtual ancestry, and has standalone pool evidence.
/// It retains its file/volume/host handles. This is not target authorization;
/// the writer must independently retain and recheck the actual target.
pub struct TargetBoundStage {
    // File closes before its protected directory owner, then mapping handles.
    stage: SealedStage,
    volume: File,
    host: BoundTarget,
    guid: String,
    extents: Vec<SourceExtent>,
    pool: PhysicalDiskPools,
    target: DeviceSnapshot,
}
impl SealedStage {
    pub fn bind_target(self, target: &DeviceSnapshot) -> Result<TargetBoundStage, StageError> {
        self.revalidate()?;
        inline(&self)?;
        let guid = source_guid(&self.reader).map_err(|e| evidence("sealed volume GUID", e))?;
        let volume = OpenOptions::new()
            .access_mode(0)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(&guid[..guid.len() - 1])
            .map_err(|e| error("retain sealed volume", e))?;
        // SAFETY: this is our synchronous retained volume handle, not a file.
        let extents =
            unsafe { volume_extents(&volume) }.map_err(|e| evidence("sealed volume extents", e))?;
        let [extent] = extents.as_slice() else {
            return Err(StageError::Invalid(
                "stage volume requires one physical extent",
            ));
        };
        if extent.disk_number == target.device_number {
            return Err(StageError::Invalid("stage resides on target"));
        }
        unsafe { no_virtual_dependencies(&volume) }
            .map_err(|e| evidence("sealed volume ancestry", e))?;
        // This number selects a provider candidate only. BoundTarget then opens
        // a current CM-listed interface and independently proves native identity.
        let inventory = collect_evidence().map_err(|e| evidence("sealed host inventory", e))?;
        let mut candidates = inventory
            .disks
            .iter()
            .filter(|d| d.number == extent.disk_number);
        let candidate = candidates
            .next()
            .ok_or(StageError::Invalid("sealed host missing"))?;
        if candidates.next().is_some() {
            return Err(StageError::Invalid("sealed host ambiguous"));
        }
        let selector = candidate
            .path
            .as_deref()
            .ok_or(StageError::Invalid("sealed host has no interface"))?;
        let mut host = BoundTarget::open_present_interface(selector)
            .map_err(|e| evidence("bind sealed host", e))?;
        super::super::super::host_policy::single_host(
            &extents,
            &host.observation().handle.device,
            target,
        )?;
        let pools = windows_pools::collect().map_err(|e| evidence("sealed host pools", e))?;
        let pool = require_stage_host_pool(
            &host
                .revalidate()
                .map_err(|e| evidence("refresh sealed host", e))?
                .disk,
            &pools,
        )
        .map_err(|e| evidence("sealed host pool binding", e))?
        .clone();
        let mut bound = TargetBoundStage {
            stage: self,
            volume,
            host,
            guid,
            extents,
            pool,
            target: target.clone(),
        };
        bound.revalidate_readiness(target)?;
        Ok(bound)
    }
}
impl TargetBoundStage {
    pub fn fingerprint(&self) -> &ImageFingerprint {
        self.stage.fingerprint()
    }
    pub fn engine(&self) -> &Image {
        self.stage.engine()
    }
    /// Full provider/pool/backing refresh before confirmation is committed.
    pub fn revalidate_readiness(&mut self, target: &DeviceSnapshot) -> Result<(), StageError> {
        if target != &self.target {
            return Err(StageError::Invalid("sealed target changed"));
        }
        self.check()?;
        self.host
            .revalidate()
            .map_err(|e| evidence("refresh sealed host", e))?;
        let pools =
            windows_pools::collect().map_err(|e| evidence("refresh sealed host pools", e))?;
        if require_stage_host_pool(&self.host.observation().disk, &pools)
            .map_err(|e| evidence("sealed host pool binding", e))?
            != &self.pool
        {
            return Err(StageError::Invalid("sealed host pool evidence changed"));
        }
        inline(&self.stage)?;
        self.host
            .revalidate()
            .map_err(|e| evidence("refresh sealed host", e))?;
        self.check()
    }
    fn check(&self) -> Result<(), StageError> {
        self.stage.revalidate()?;
        self.host
            .revalidate_handles()
            .map_err(|e| evidence("sealed host identity", e))?;
        if source_guid(&self.stage.reader).map_err(|e| evidence("sealed volume GUID", e))?
            != self.guid
        {
            return Err(StageError::Invalid("sealed file volume changed"));
        }
        // SAFETY: constructor retained a synchronous volume handle throughout.
        let extents = unsafe { volume_extents(&self.volume) }
            .map_err(|e| evidence("sealed volume extents", e))?;
        if extents != self.extents {
            return Err(StageError::Invalid("sealed volume extents changed"));
        }
        super::super::super::host_policy::single_host(
            &extents,
            &self.host.observation().handle.device,
            &self.target,
        )?;
        unsafe { no_virtual_dependencies(&self.volume) }
            .map_err(|e| evidence("sealed volume ancestry", e))?;
        self.stage.revalidate()
    }
}
impl Read for TargetBoundStage {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.check().map_err(io::Error::other)?;
        let result = self.stage.reader.read(bytes);
        self.check().map_err(io::Error::other)?;
        result
    }
}
impl Seek for TargetBoundStage {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        self.check().map_err(io::Error::other)?;
        let result = self.stage.reader.seek(position);
        self.check().map_err(io::Error::other)?;
        result
    }
}
