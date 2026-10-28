// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[tauri::command]
fn capabilities() -> serde_json::Value {
    serde_json::json!({
        "mode": "native",
        "platform": std::env::consts::OS,
        "file_import": true,
        "host_inventory": cfg!(any(target_os = "windows", target_os = "macos", target_os = "linux")),
        "helper_probe": cfg!(windows),
        "physical_preparation": false,
        "preparation_unavailable_reason": "Physical preparation is unavailable. Disk preparation and OS boot integration are unfinished."
    })
}
#[tauri::command]
fn check_config(text: String, format: String) -> serde_json::Value {
    match isohopper_config::parse(text.as_bytes(), &format) {
        Ok(config) => serde_json::json!({"valid":true,"warnings":config.warnings}),
        Err(error) => serde_json::json!({"valid":false,"error":error.to_string()}),
    }
}
#[cfg(any(windows, test))]
mod elevation;
mod imports;
#[tauri::command]
fn release_sources(ids: Vec<String>) -> Result<(), String> {
    imports::release_sources(&ids)
}
#[tauri::command]
fn list_sources() -> Result<Vec<imports::ImportedImage>, String> {
    imports::list_sources()
}
use std::sync::atomic::{AtomicBool, Ordering};
static NATIVE_JOB_ACTIVE: AtomicBool = AtomicBool::new(false);
static HELPER_PROBE_ACTIVE: AtomicBool = AtomicBool::new(false);
struct NativeJob;
impl NativeJob {
    fn begin() -> Result<Self, String> {
        NATIVE_JOB_ACTIVE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| Self)
            .map_err(|_| "Another native operation is running".into())
    }
}
impl Drop for NativeJob {
    fn drop(&mut self) {
        NATIVE_JOB_ACTIVE.store(false, Ordering::Release);
    }
}
#[cfg(windows)]
struct HelperProbeGuard {
    _native: NativeJob,
}
#[cfg(windows)]
impl HelperProbeGuard {
    fn begin() -> Result<Self, String> {
        let native = NativeJob::begin()?;
        HELPER_PROBE_ACTIVE.store(true, Ordering::Release);
        Ok(Self { _native: native })
    }
}
#[cfg(windows)]
impl Drop for HelperProbeGuard {
    fn drop(&mut self) {
        HELPER_PROBE_ACTIVE.store(false, Ordering::Release);
    }
}

#[tauri::command]
async fn probe_helper(window: tauri::WebviewWindow) -> Result<serde_json::Value, String> {
    #[cfg(windows)]
    {
        use tauri::Manager;
        if window.label() != "main" {
            return Err("Helper probe requires the main Studio window".into());
        }
        let guard = HelperProbeGuard::begin()?;
        let directory = window
            .app_handle()
            .path()
            .resource_dir()
            .map_err(|e| e.to_string())?;
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let owner = window.clone();
        window
            .run_on_main_thread(move || {
                let _ = sender.send(
                    owner
                        .hwnd()
                        .map(|hwnd| hwnd.0 as usize)
                        .map_err(|e| e.to_string()),
                );
            })
            .map_err(|e| e.to_string())?;
        tauri::async_runtime::spawn_blocking(move || {
            let _guard = guard;
            let hwnd = receiver
                .recv_timeout(std::time::Duration::from_secs(10))
                .map_err(|_| "Could not obtain Studio owner window")??;
            // A fresh thread guarantees this operation controls its COM apartment.
            let outcome = std::thread::spawn(move || {
                elevation::run(hwnd, &directory, env!("ISOHOPPER_HELPER_SHA256"))
            })
            .join()
            .map_err(|_| "Helper launch thread failed")??;
            serde_json::to_value(outcome).map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    }
    #[cfg(not(windows))]
    {
        let _ = window;
        Err("Elevated helper probe is available only on Windows".into())
    }
}
#[tauri::command]
async fn pick_images() -> Result<Vec<imports::ImportedImage>, String> {
    let job = NativeJob::begin()?;
    tauri::async_runtime::spawn_blocking(move || {
        let _job = job;
        let Some(paths) = rfd::FileDialog::new()
            .set_title("Choose boot images to hash locally")
            .add_filter("Boot images", &["iso", "img", "wim", "vhd", "vhdx", "efi"])
            .pick_files()
        else {
            return Ok(Vec::new());
        };
        imports::import_files(&paths)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn pick_directory() -> Result<imports::ImportedDirectory, String> {
    let job = NativeJob::begin()?;
    tauri::async_runtime::spawn_blocking(move || {
        let _job = job;
        let Some(path) = rfd::FileDialog::new()
            .set_title("Choose image library folder")
            .pick_folder()
        else {
            return Ok(imports::ImportedDirectory::default());
        };
        imports::import_directory(&path)
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
async fn inspect_devices() -> Result<isohopper_inventory::Inventory, String> {
    let job = NativeJob::begin()?;
    tauri::async_runtime::spawn_blocking(move || {
        let _job = job;
        isohopper_inventory::discover().map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())?
}
fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            capabilities,
            check_config,
            pick_images,
            pick_directory,
            release_sources,
            list_sources,
            inspect_devices,
            probe_helper
        ])
        .on_window_event(|_, event| {
            if HELPER_PROBE_ACTIVE.load(Ordering::Acquire)
                && let tauri::WindowEvent::CloseRequested { api, .. } = event
            {
                api.prevent_close();
            }
        })
        .build(tauri::generate_context!())
        .expect("could not start IsoHopper Studio")
        .run(|_, event| {
            if HELPER_PROBE_ACTIVE.load(Ordering::Acquire)
                && let tauri::RunEvent::ExitRequested { api, .. } = event
            {
                api.prevent_exit();
            }
        });
}

#[cfg(test)]
mod tests {
    #[test]
    fn release_command_retains_leased_sources_and_releases_after_the_lease_ends() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("boot.iso");
        std::fs::write(&path, b"abc").unwrap();
        let image = super::imports::import_file(&path).unwrap();
        let lease = super::imports::source_catalog()
            .lock()
            .unwrap()
            .lease(&image.source_id)
            .unwrap();
        assert!(super::release_sources(vec![image.source_id.clone()]).is_err());
        drop(lease);
        super::release_sources(vec![image.source_id.clone()]).unwrap();
        assert!(super::release_sources(vec![image.source_id]).is_err());
        assert!(super::release_sources(vec![path.display().to_string()]).is_err());
        assert_eq!(std::fs::read(path).unwrap(), b"abc");
    }
}
