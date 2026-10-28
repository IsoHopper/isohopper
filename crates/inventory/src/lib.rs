// SPDX-License-Identifier: GPL-3.0-or-later
//! Read-only physical-disk discovery. Discovery is not authorization to write.
use isohopper_core::guard::Disk;
use serde::Serialize;
use std::io;
use thiserror::Error;

mod linux;
mod macos;
mod native;
mod windows;
pub use native::NativeCommandRunner;

const MAX_OUTPUT: usize = 2 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
    Windows,
    Other,
}

#[derive(Debug, Serialize)]
pub struct Inventory {
    pub source: String,
    pub disks: Vec<Disk>,
    pub warnings: Vec<Warning>,
}

#[derive(Debug, Serialize)]
pub struct Warning {
    pub disk_id: Option<String>,
    pub code: String,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct CommandOutput {
    pub success: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput>;
}

#[derive(Debug, Error)]
pub enum InventoryError {
    #[error("read-only disk inventory is unsupported on {0:?}")]
    Unsupported(Platform),
    #[error("invalid disk inventory: {0}")]
    Invalid(String),
    #[error("disk inventory command failed: {0}")]
    Command(String),
}

/// Detect the host platform and use only its read-only inventory provider.
pub fn discover() -> Result<Inventory, InventoryError> {
    discover_with(&NativeCommandRunner)
}

pub fn discover_with(runner: &impl CommandRunner) -> Result<Inventory, InventoryError> {
    let platform = if cfg!(target_os = "macos") {
        Platform::MacOs
    } else if cfg!(target_os = "linux") {
        Platform::Linux
    } else if cfg!(target_os = "windows") {
        Platform::Windows
    } else {
        Platform::Other
    };
    discover_for(platform, runner)
}

/// An explicit platform permits deterministic fixture testing on any host.
pub fn discover_for(
    platform: Platform,
    runner: &impl CommandRunner,
) -> Result<Inventory, InventoryError> {
    match platform {
        Platform::MacOs => macos::discover(runner),
        Platform::Linux => linux::discover(runner),
        Platform::Windows => windows::discover(runner),
        other => Err(InventoryError::Unsupported(other)),
    }
}

fn warning(warnings: &mut Vec<Warning>, disk_id: Option<&str>, code: &str, message: &str) {
    warnings.push(Warning {
        disk_id: disk_id.map(str::to_owned),
        code: code.into(),
        message: message.into(),
    });
}
