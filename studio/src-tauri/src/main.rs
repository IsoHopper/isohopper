// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#[tauri::command]
fn list_disks() -> Vec<isohopper_cli::DiskView> {
    isohopper_cli::demo_disks()
}
#[tauri::command]
fn plan_disk(id: String) -> Result<isohopper_core::layout::Layout, String> {
    isohopper_cli::demo_plan(&id)
}
#[tauri::command]
fn check_config(text: String, format: String) -> serde_json::Value {
    match isohopper_config::parse(text.as_bytes(), &format) {
        Ok(config) => serde_json::json!({"valid":true,"warnings":config.warnings}),
        Err(error) => serde_json::json!({"valid":false,"error":error.to_string()}),
    }
}
mod imports;
use std::sync::atomic::{AtomicBool, Ordering};
static NATIVE_JOB_ACTIVE: AtomicBool = AtomicBool::new(false);
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
        paths
            .iter()
            .map(|path| imports::import_file(path))
            .collect()
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
            list_disks,
            plan_disk,
            check_config,
            pick_images,
            pick_directory,
            inspect_devices
        ])
        .run(tauri::generate_context!())
        .expect("could not start IsoHopper Studio");
}
