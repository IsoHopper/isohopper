// SPDX-License-Identifier: GPL-3.0-or-later
use std::process::Command;

#[test]
fn helper_has_no_default_write_mode_and_probe_arguments_are_closed() {
    let binary = env!("CARGO_BIN_EXE_isohopper-helper");
    assert!(
        Command::new(binary)
            .arg("--version")
            .output()
            .unwrap()
            .status
            .success()
    );
    for args in [
        vec![],
        vec!["--version", "--write"],
        vec!["--probe-broker-v1"],
        vec!["--write"],
        vec![
            "--probe-broker-v1",
            "--pipe-nonce",
            "00",
            "--studio-pid",
            "0",
            "--studio-created",
            "0",
        ],
    ] {
        let output = Command::new(binary).args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stdout.is_empty());
    }
}

#[cfg(all(windows, target_env = "msvc"))]
#[test]
fn built_helper_embeds_an_as_invoker_manifest() {
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::{FreeLibrary, HMODULE},
        System::LibraryLoader::{
            FindResourceW, LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE, LOAD_LIBRARY_AS_IMAGE_RESOURCE,
            LoadLibraryExW, LoadResource, LockResource, SizeofResource,
        },
    };
    struct Module(HMODULE);
    impl Drop for Module {
        fn drop(&mut self) {
            // SAFETY: this owns one successful data-only module mapping.
            unsafe { FreeLibrary(self.0) };
        }
    }
    let name: Vec<_> = std::ffi::OsStr::new(env!("CARGO_BIN_EXE_isohopper-helper"))
        .encode_wide()
        .chain([0])
        .collect();
    // SAFETY: valid terminated path; data/resource flags never execute code.
    let raw = unsafe {
        LoadLibraryExW(
            name.as_ptr(),
            ptr::null_mut(),
            LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE,
        )
    };
    assert!(
        !raw.is_null(),
        "map built helper: {}",
        std::io::Error::last_os_error()
    );
    let module = Module(raw);
    // SAFETY: MAKEINTRESOURCE-style numeric identifiers: executable ID=1,
    // RT_MANIFEST=24. The retained module bounds all returned resource data.
    let resource = unsafe { FindResourceW(module.0, 1usize as *const u16, 24usize as *const u16) };
    assert!(!resource.is_null(), "missing embedded executable manifest");
    let size = unsafe { SizeofResource(module.0, resource) } as usize;
    assert!((1..=65_536).contains(&size), "unexpected manifest size");
    let loaded = unsafe { LoadResource(module.0, resource) };
    assert!(!loaded.is_null(), "manifest resource could not load");
    let data = unsafe { LockResource(loaded) };
    assert!(!data.is_null(), "manifest resource has no data");
    let bytes = unsafe { std::slice::from_raw_parts(data.cast::<u8>(), size) };
    let text = std::str::from_utf8(bytes).unwrap().replace('\'', "\"");
    assert!(
        text.contains("level=\"asInvoker\""),
        "helper must not request elevation itself"
    );
    assert!(text.contains("uiAccess=\"false\""));
    assert!(!text.contains("requireAdministrator"));
    assert!(!text.contains("highestAvailable"));
}
