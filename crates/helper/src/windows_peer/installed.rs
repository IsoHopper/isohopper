// SPDX-License-Identifier: GPL-3.0-or-later
use super::PeerError;

pub(super) trait Backend {
    fn peer(&mut self) -> Result<(), PeerError>;
    fn installation(&mut self) -> Result<(), PeerError>;
    fn process_image(&mut self) -> Result<Vec<u16>, PeerError>;
    fn installed_image(&self) -> &[u16];
}

pub(super) fn check<B: Backend>(backend: &mut B) -> Result<(), PeerError> {
    backend.peer()?;
    backend.installation()?;
    if backend.process_image()? != backend.installed_image() {
        return Err(PeerError::Invalid(
            "process image does not match installed role",
        ));
    }
    backend.installation()?;
    backend.peer()?;
    Ok(())
}
