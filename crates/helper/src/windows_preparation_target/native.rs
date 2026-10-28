// SPDX-License-Identifier: GPL-3.0-or-later
use super::*;
use crate::{
    windows_installation::{InstalledRole, MachineInstallation},
    windows_lock::LockedWindowsDevice,
    windows_protected::{self, ProtectedFileBinding, SystemDirectoryBinding},
    windows_target::BoundTarget,
    writer::RetainedDevice,
};
use std::{io, sync::Arc};

struct ProtectedStorage {
    system: SystemDirectoryBinding,
    studio: ProtectedFileBinding,
    helper: ProtectedFileBinding,
    target: DeviceSnapshot,
}

impl ProtectedStorage {
    fn bind(
        installation: Arc<MachineInstallation>,
        target: &DeviceSnapshot,
    ) -> Result<Self, PreparationError> {
        Ok(Self {
            system: windows_protected::bind_system_directory(target)?,
            studio: windows_protected::bind_installed_file(
                installation.clone(),
                InstalledRole::Studio,
                target,
            )?,
            helper: windows_protected::bind_installed_file(
                installation,
                InstalledRole::Helper,
                target,
            )?,
            target: target.clone(),
        })
    }
    fn revalidate(&self) -> Result<(), PreparationError> {
        self.system.revalidate(&self.target)?;
        self.studio.revalidate(&self.target)?;
        self.helper.revalidate(&self.target)?;
        Ok(())
    }
}

/// Read-only target bound to native identity, provider coverage, standalone
/// storage and protected installation/OS storage. This alone authorizes no
/// operation: the coordinator must authenticate the peer, seal/exclude its
/// source image and consume the exact one-shot confirmation before locking.
pub struct PreparationTarget {
    target: BoundTarget,
    protected: ProtectedStorage,
    pool: PhysicalDiskPools,
}

impl PreparationTarget {
    pub fn open(
        installation: Arc<MachineInstallation>,
        selector: &str,
    ) -> Result<Self, PreparationError> {
        let target = BoundTarget::open_present_interface(selector)?;
        let observation = target.observation();
        require_target_policy(
            &observation.handle.device,
            &observation.disk,
            &observation.partitions,
        )?;
        let pools = isohopper_inventory::windows_pools::collect()?;
        let pool = require_standalone_pool(&observation.disk, &pools)?.clone();
        let protected = ProtectedStorage::bind(installation, &observation.handle.device)?;
        let mut result = Self {
            target,
            protected,
            pool,
        };
        result.revalidate_readiness()?;
        Ok(result)
    }

    pub fn snapshot(&self) -> &DeviceSnapshot {
        &self.target.observation().handle.device
    }

    /// Repeat provider, native identity, all partition status, encryption and
    /// pool observations. No old partition layout is consulted after writing.
    pub fn revalidate_readiness(&mut self) -> Result<(), PreparationError> {
        let observation = self.target.revalidate()?;
        require_target_policy(
            &observation.handle.device,
            &observation.disk,
            &observation.partitions,
        )?;
        let pools = isohopper_inventory::windows_pools::collect()?;
        if require_standalone_pool(&observation.disk, &pools)? != &self.pool {
            return Err(PreparationError::Refused("storage pool evidence changed"));
        }
        self.protected.revalidate()?;
        require_clear_encryption(&self.target.observe_encryption()?)?;
        let observation = self.target.revalidate()?;
        require_target_policy(
            &observation.handle.device,
            &observation.disk,
            &observation.partitions,
        )?;
        self.protected.revalidate()
    }

    /// Used only after coordinator authentication, source release and exact
    /// confirmation. Acquires every observed volume lock; a system/pagefile or
    /// other open-file volume must fail that lock, never force a dismount.
    pub fn into_locked(mut self) -> Result<PreparationDevice, PreparationError> {
        self.revalidate_readiness()?;
        let device = self.target.lock_for_preparation()?;
        self.protected.revalidate()?;
        Ok(PreparationDevice {
            device,
            protected: self.protected,
        })
    }
}

/// Close the raw device and locks before releasing protected-source guards.
/// Retains the preflight's protected file and directory handles for all I/O.
pub struct PreparationDevice {
    device: LockedWindowsDevice,
    protected: ProtectedStorage,
}

impl PreparationDevice {
    fn check(&self) -> io::Result<()> {
        self.protected.revalidate().map_err(io::Error::other)
    }
}

impl RetainedDevice for PreparationDevice {
    fn snapshot(&mut self) -> io::Result<DeviceSnapshot> {
        self.check()?;
        self.device.snapshot()
    }
    fn read_at(&mut self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        self.device.read_at(offset, buffer)
    }
    fn write_at(&mut self, offset: u64, buffer: &[u8]) -> io::Result<usize> {
        self.check()?;
        self.device.write_at(offset, buffer)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.check()?;
        self.device.flush()
    }
}
