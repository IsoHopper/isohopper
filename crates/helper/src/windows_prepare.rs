// SPDX-License-Identifier: GPL-3.0-or-later
//! One authenticated preparation job. No caller-provided disk snapshot, raw
//! path, shell command, format argument, or byte offset enters this flow.
#[cfg(any(windows, test))]
pub(crate) mod coordinator;
#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::serve;
