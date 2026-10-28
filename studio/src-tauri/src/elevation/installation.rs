// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
#[cfg(windows)]
use isohopper_helper::windows_installation::MachineInstallation;
#[cfg(windows)]
use std::{path::Path, sync::Arc};

#[cfg(windows)]
pub(super) fn open(directory: &Path) -> Result<Arc<MachineInstallation>, String> {
    let installation = MachineInstallation::open()?;
    installation.require_directory(directory)?;
    Ok(Arc::new(installation))
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use isohopper_helper::windows_installation::InstalledRole;

    #[test]
    #[ignore = "requires the matching NSIS package to be installed on this Windows test machine"]
    fn native_installed_helper_is_protected_and_matches_build() {
        let expected = env!("ISOHOPPER_HELPER_SHA256");
        let installation = MachineInstallation::open().unwrap();
        let mut helper = installation.image(InstalledRole::Helper);
        let digest = crate::elevation::check_digest(&mut helper, expected).unwrap();
        assert_eq!(digest, expected);
        installation.revalidate().unwrap();
        assert!(
            installation
                .require_directory(installation.directory())
                .is_ok()
        );
        assert!(
            installation
                .require_directory(Path::new(r"C:\Users\portable\IsoHopper"))
                .is_err()
        );
        let installation = Arc::new(installation);
        installed_processes_keep_their_expected_roles(&installation);
    }

    fn installed_processes_keep_their_expected_roles(installation: &Arc<MachineInstallation>) {
        use isohopper_helper::{windows_peer::ProcessPeer, windows_probe::current_peer};
        use std::{
            mem::size_of,
            os::windows::{
                ffi::OsStrExt,
                io::{AsHandle, AsRawHandle, FromRawHandle, OwnedHandle},
            },
            ptr,
        };
        use windows_sys::Win32::{
            Foundation::WAIT_OBJECT_0,
            System::Threading::{
                CREATE_SUSPENDED, CreateProcessW, PROCESS_INFORMATION, STARTUPINFOW,
                TerminateProcess, WaitForSingleObject,
            },
        };
        // These are owned suspended test children; no executable entrypoint or
        // UI runs, and this test never requests elevation. Keep both handles
        // until termination so an assertion cannot leave a suspended child.
        struct Child {
            process: OwnedHandle,
            _thread: OwnedHandle,
        }
        impl Drop for Child {
            fn drop(&mut self) {
                unsafe {
                    TerminateProcess(self.process.as_raw_handle(), 0);
                }
                assert_eq!(
                    unsafe { WaitForSingleObject(self.process.as_raw_handle(), 5000) },
                    WAIT_OBJECT_0
                );
            }
        }
        assert!(
            current_peer()
                .unwrap()
                .bind_installation(Arc::clone(installation), InstalledRole::Studio)
                .is_err()
        );
        for (role, other) in [
            (InstalledRole::Studio, InstalledRole::Helper),
            (InstalledRole::Helper, InstalledRole::Studio),
        ] {
            let path: Vec<u16> = installation
                .path(role)
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect();
            let startup = STARTUPINFOW {
                cb: size_of::<STARTUPINFOW>() as u32,
                ..Default::default()
            };
            let mut info = PROCESS_INFORMATION::default();
            installation.revalidate().unwrap();
            assert_ne!(
                unsafe {
                    CreateProcessW(
                        path.as_ptr(),
                        ptr::null_mut(),
                        ptr::null(),
                        ptr::null(),
                        0,
                        CREATE_SUSPENDED,
                        ptr::null(),
                        ptr::null(),
                        &startup,
                        &mut info,
                    )
                },
                0,
                "create owned suspended installed process: {}",
                std::io::Error::last_os_error()
            );
            // SAFETY: successful CreateProcessW transfers exactly these two
            // handles. They are never taken from a PID or another process.
            let child = Child {
                process: unsafe { OwnedHandle::from_raw_handle(info.hProcess) },
                _thread: unsafe { OwnedHandle::from_raw_handle(info.hThread) },
            };
            let peer = || {
                ProcessPeer::from_owned_handle(
                    child.process.as_handle().try_clone_to_owned().unwrap(),
                )
                .unwrap()
            };
            assert!(
                peer()
                    .bind_installation(Arc::clone(installation), other)
                    .is_err()
            );
            let mut bound = peer()
                .bind_installation(Arc::clone(installation), role)
                .unwrap();
            bound.revalidate().unwrap();
            assert!(
                bound
                    .bind_installation(Arc::clone(installation), role)
                    .is_err()
            );
            drop(child);
            installation.revalidate().unwrap();
        }
    }
}
