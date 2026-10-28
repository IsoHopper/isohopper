// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
//! Harmless QEMU fixture. Built only with the explicit `test-utility` feature.
#![cfg_attr(target_os = "uefi", no_std)]
#![cfg_attr(target_os = "uefi", no_main)]

#[cfg(target_os = "uefi")]
#[uefi::entry]
fn main() -> uefi::Status {
    if uefi::helpers::init().is_err() {
        return uefi::Status::ABORTED;
    }
    if let Ok(handle) =
        uefi::boot::get_handle_for_protocol::<uefi::proto::console::serial::Serial>()
    {
        if let Ok(mut serial) =
            uefi::boot::open_protocol_exclusive::<uefi::proto::console::serial::Serial>(handle)
        {
            let _ = serial.write(b"ISOHOPPER:TEST_UTILITY:ENTRY\r\n");
        }
    }
    uefi::Status::SUCCESS
}

#[cfg(not(target_os = "uefi"))]
fn main() {
    eprintln!("Build for x86_64-unknown-uefi to run the test utility.");
    std::process::exit(2);
}
