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

#[cfg(test)]
mod backing_diagnostic {
    pub(super) fn observation(
        role: &str,
        hresult: i32,
        external: i32,
        provider: u32,
    ) -> Result<serde_json::Value, &'static str> {
        if !matches!(role, "studio" | "helper") {
            return Err("unexpected installed role");
        }
        let (is_external, provider) = if hresult < 0 {
            // Failure leaves output arguments undefined, even when they look
            // like a valid FALSE. Never classify an unavailable query as clear.
            (None, None)
        } else {
            match external {
                0 => (Some(false), None),
                1 if matches!(provider, 1 | 2) => (Some(true), Some(provider)),
                _ => return Err("invalid successful WOF query output"),
            }
        };
        Ok(serde_json::json!({
            "role": role,
            "hresult": hresult as u32,
            "is_external": is_external,
            "provider": provider,
        }))
    }

    #[test]
    fn failed_query_outputs_are_never_reported_as_backing_evidence() {
        for (external, provider) in [(0, 0), (1, 1), (i32::MIN, u32::MAX)] {
            assert_eq!(
                observation("helper", 0x80070001_u32 as i32, external, provider).unwrap(),
                serde_json::json!({
                    "role": "helper", "hresult": 2147942401_u32,
                    "is_external": null, "provider": null
                })
            );
        }
    }

    #[test]
    fn success_requires_initialized_boolean_and_external_provider() {
        assert_eq!(
            observation("studio", 0, 0, u32::MAX).unwrap(),
            serde_json::json!({
                "role": "studio", "hresult": 0,
                "is_external": false, "provider": null
            })
        );
        for provider in [1, 2] {
            assert_eq!(
                observation("helper", 0, 1, provider).unwrap(),
                serde_json::json!({
                    "role": "helper", "hresult": 0,
                    "is_external": true, "provider": provider
                })
            );
        }
        for external in [i32::MIN, -1, 2, i32::MAX] {
            assert!(observation("helper", 0, external, 1).is_err());
        }
        for provider in [0, 3, u32::MAX] {
            assert!(observation("helper", 0, 1, provider).is_err());
        }
        assert!(observation("unexpected role", 0, 0, 0).is_err());
    }
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
        observe_installed_backing(&installation);
        installed_processes_keep_their_expected_roles(&installation);
    }

    fn observe_installed_backing(installation: &MachineInstallation) {
        use std::{os::windows::ffi::OsStrExt, ptr};
        use windows_sys::Win32::Storage::FileSystem::{
            WOF_PROVIDER_FILE, WOF_PROVIDER_WIM, WofIsExternalFile,
        };
        const _: () = {
            assert!(WOF_PROVIDER_WIM == 1);
            assert!(WOF_PROVIDER_FILE == 2);
        };
        // Diagnostic only. This path-taking API is restricted to the fixed
        // installation whose files, ancestors, ACLs and namespace remain
        // retained/revalidated. It is not an arbitrary source-path fallback.
        // Contract: https://learn.microsoft.com/en-us/windows/win32/api/wofapi/nf-wofapi-wofisexternalfile
        for (role, name) in [
            (InstalledRole::Studio, "studio"),
            (InstalledRole::Helper, "helper"),
        ] {
            installation.revalidate().unwrap();
            let before = retained_digest(installation.image(role));
            let path: Vec<u16> = installation
                .path(role)
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect();
            installation.revalidate().unwrap();
            let mut external = i32::MIN;
            let mut provider = u32::MAX;
            // SAFETY: the guarded fixed path is NUL-terminated and remains
            // alive; scalar outputs are writable. Optional provider-detail
            // buffers are both null. No handle/path is accepted from a caller.
            let hresult = unsafe {
                WofIsExternalFile(
                    path.as_ptr(),
                    &mut external,
                    &mut provider,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            // Bracket errors too, and verify bytes using the original retained
            // file, not a pathname reopened after the WOF call.
            installation.revalidate().unwrap();
            assert_eq!(before, retained_digest(installation.image(role)));
            installation.revalidate().unwrap();
            let observation =
                backing_diagnostic::observation(name, hresult, external, provider).unwrap();
            println!("INSTALLED_WOF_DIAGNOSTIC {observation}");
        }
    }

    fn retained_digest(mut file: &std::fs::File) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        use std::io::{Read, Seek};
        let length = file.metadata().unwrap().len();
        assert!((1..=256 * 1024 * 1024).contains(&length));
        file.rewind().unwrap();
        let mut limited = file.take(length + 1);
        let mut digest = Sha256::new();
        let mut total = 0;
        let mut buffer = [0u8; 65536];
        loop {
            let count = limited.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            total += count as u64;
            digest.update(&buffer[..count]);
        }
        assert_eq!(total, length);
        digest.finalize().into()
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
