// SPDX-License-Identifier: GPL-3.0-or-later
//! Retained evidence for the fixed, protected machine installation. This is a
//! narrow ACL policy, not general access evaluation or authority to write disks.
//! A fresh protected install is required: changing a writable tree's ACL does
//! not revoke earlier handles. Administrators and SYSTEM remain trusted.
//!
//! Process image-name correlation does not identify the mapped image's file ID
//! or prevent same-user injection. Job, device and source checks remain separate.

/// Fixed executable names inside the machine installation; no caller path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstalledRole {
    Studio,
    Helper,
}

impl InstalledRole {
    pub fn filename(self) -> &'static str {
        match self {
            Self::Studio => "isohopper-studio.exe",
            Self::Helper => "isohopper-helper.exe",
        }
    }
}

#[cfg(windows)]
mod native;
#[cfg(any(windows, test))]
mod policy;
#[cfg(windows)]
pub use native::MachineInstallation;
#[cfg(windows)]
mod state;
#[cfg(windows)]
pub(crate) use state::wide_name;
