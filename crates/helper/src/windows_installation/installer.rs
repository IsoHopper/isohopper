// SPDX-License-Identifier: GPL-3.0-or-later
//! Fixed-file installer transaction. No registry command or target path input.
pub const FILES: [&str; 3] = [
    "isohopper-studio.exe",
    "isohopper-helper.exe",
    "uninstall.exe",
];

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Close IsoHopper and wait for its helper to finish, then retry installation.")]
    Busy,
    #[error("The existing installation cannot be safely repaired: {0}")]
    Unsafe(String),
    #[error("The installer payload is invalid: {0}")]
    Payload(String),
    #[error("Installation failed; the previous files were restored: {0}")]
    RolledBack(String),
    #[error("Installation needs repair; protected recovery files were retained: {0}")]
    Incomplete(String),
}
impl Error {
    pub fn code(&self) -> i32 {
        match self {
            Self::Busy => 10,
            Self::Unsafe(_) => 11,
            Self::Payload(_) => 12,
            Self::RolledBack(_) => 13,
            Self::Incomplete(_) => 14,
        }
    }
}

#[cfg(windows)]
pub use super::native::installer::apply;

#[cfg(any(windows, test))]
pub(super) fn payload_path(path: &str, base: &str, windows: &str) -> Result<(), Error> {
    super::policy::installation_path(&format!("{base}\\IsoHopper"), base, windows)
        .map_err(Error::Payload)?;
    let prefix = format!("{base}\\.IsoHopper-setup-");
    let Some(head) = path.get(..prefix.len()) else {
        return Err(Error::Payload("staging location".into()));
    };
    let suffix = &path[prefix.len()..];
    if !head.eq_ignore_ascii_case(&prefix)
        || suffix.len() != 38
        || !suffix.starts_with('{')
        || !suffix.ends_with('}')
    {
        return Err(Error::Payload("staging location".into()));
    }
    for (index, byte) in suffix.as_bytes()[1..37].iter().enumerate() {
        if if [8, 13, 18, 23].contains(&index) {
            *byte != b'-'
        } else {
            !byte.is_ascii_hexdigit()
        } {
            return Err(Error::Payload("staging identifier".into()));
        }
    }
    Ok(())
}

#[cfg(any(windows, test))]
pub(super) trait Backend {
    fn preflight(&mut self) -> Result<(), Error>;
    fn stage(&mut self, index: usize) -> Result<(), String>;
    fn backup(&mut self, index: usize) -> Result<bool, String>;
    fn publish(&mut self, index: usize) -> Result<(), String>;
    fn remove_new(&mut self, index: usize) -> Result<(), String>;
    fn restore_old(&mut self, index: usize) -> Result<(), String>;
    fn cleanup_staged(&mut self, index: usize) -> Result<(), String>;
    fn finish(&mut self) -> Result<(), String>;
}

#[cfg(any(windows, test))]
pub(super) fn run(backend: &mut impl Backend) -> Result<(), Error> {
    backend.preflight()?;
    let mut backed_up = [false; 3];
    let mut published = [false; 3];
    let attempt = (|| {
        for index in 0..FILES.len() {
            backend.stage(index)?;
        }
        for (index, backed_up) in backed_up.iter_mut().enumerate() {
            *backed_up = backend.backup(index)?;
        }
        for (index, published) in published.iter_mut().enumerate() {
            backend.publish(index)?;
            *published = true;
        }
        Ok::<_, String>(())
    })();
    if let Err(error) = attempt {
        let mut complete = true;
        for index in (0..FILES.len()).rev() {
            if published[index] && backend.remove_new(index).is_err() {
                complete = false;
            }
            if backed_up[index] && backend.restore_old(index).is_err() {
                complete = false;
            }
            // A failed stage operation can have created a partial file too.
            if backend.cleanup_staged(index).is_err() {
                complete = false;
            }
        }
        return Err(if complete {
            Error::RolledBack(error)
        } else {
            Error::Incomplete(error)
        });
    }
    // All new files remain locked until finish returns. Once old-file cleanup
    // starts, preserve any remaining backups if cleanup fails; do not roll a
    // complete new installation back to a partially deleted old installation.
    backend.finish().map_err(Error::Incomplete)
}

#[cfg(test)]
#[path = "installer_tests.rs"]
mod tests;
