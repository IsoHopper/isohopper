// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G
#![cfg_attr(target_os = "uefi", no_std)]
#![cfg_attr(target_os = "uefi", no_main)]

#[cfg(target_os = "uefi")]
mod firmware {
    use isohopper_launcher::power::{Action, Confirmation, PowerConfig, firmware_indications};
    use uefi::{
        cstr16,
        prelude::*,
        proto::console::{serial::Serial, text::Key},
        proto::media::file::{File, FileAttribute, FileMode},
        runtime::{self, ResetType, VariableAttributes, VariableVendor},
    };

    fn serial(message: &[u8]) {
        if let Ok(handle) = uefi::boot::get_handle_for_protocol::<Serial>() {
            if let Ok(mut serial) = uefi::boot::open_protocol_exclusive::<Serial>(handle) {
                let _ = serial.write(message);
            }
        }
    }
    fn read_u64(name: &uefi::CStr16) -> Result<u64, Status> {
        let mut buffer = [0; 8];
        let (bytes, _) = runtime::get_variable(name, &VariableVendor::GLOBAL_VARIABLE, &mut buffer)
            .map_err(|e| e.status())?;
        if bytes.len() != 8 {
            return Err(Status::COMPROMISED_DATA);
        }
        Ok(u64::from_le_bytes(
            bytes.try_into().map_err(|_| Status::COMPROMISED_DATA)?,
        ))
    }
    fn preferences() -> PowerConfig {
        let read = || -> Result<PowerConfig, Status> {
            let mut fs = uefi::boot::get_image_file_system(uefi::boot::image_handle())
                .map_err(|e| e.status())?;
            let mut root = fs.open_volume().map_err(|e| e.status())?;
            let file = match root.open(
                cstr16!("\\IHPOWER.CFG"),
                FileMode::Read,
                FileAttribute::empty(),
            ) {
                Ok(file) => file,
                Err(error) if error.status() == Status::NOT_FOUND => return Ok(PowerConfig::ALL),
                Err(error) => return Err(error.status()),
            };
            let mut file = file.into_regular_file().ok_or(Status::INVALID_PARAMETER)?;
            let mut bytes = [0; 9];
            let len = file.read(&mut bytes).map_err(|e| e.status())?;
            PowerConfig::decode(&bytes[..len]).ok_or(Status::COMPROMISED_DATA)
        };
        match read() {
            Ok(config) => config,
            Err(status) => {
                uefi::println!("Power preferences unreadable ({status:?}); actions disabled.");
                PowerConfig::NONE
            }
        }
    }
    fn key() -> Option<char> {
        loop {
            match uefi::system::with_stdin(|stdin| stdin.read_key()) {
                Ok(Some(Key::Printable(c))) => return Some(char::from(c)),
                Ok(Some(_)) => return None,
                Err(_) => return None,
                Ok(None) => uefi::boot::stall(core::time::Duration::from_millis(10)),
            }
        }
    }
    fn perform(action: Action) {
        match action {
            Action::Reboot => {
                serial(b"ISOHOPPER:POWER:REBOOT\r\n");
                runtime::reset(ResetType::COLD, Status::SUCCESS, None)
            }
            Action::Shutdown => {
                serial(b"ISOHOPPER:POWER:SHUTDOWN\r\n");
                runtime::reset(ResetType::SHUTDOWN, Status::SUCCESS, None)
            }
            Action::FirmwareSetup => {
                if !read_u64(cstr16!("OsIndicationsSupported")).is_ok_and(|flags| flags & 1 != 0) {
                    uefi::println!("Firmware setup request is unsupported.");
                    return;
                }
                let existing = match read_u64(cstr16!("OsIndications")) {
                    Ok(value) => value,
                    Err(Status::NOT_FOUND) => 0,
                    Err(error) => {
                        uefi::println!("Cannot read firmware indications: {error:?}");
                        return;
                    }
                };
                let attrs = VariableAttributes::NON_VOLATILE
                    | VariableAttributes::BOOTSERVICE_ACCESS
                    | VariableAttributes::RUNTIME_ACCESS;
                match runtime::set_variable(
                    cstr16!("OsIndications"),
                    &VariableVendor::GLOBAL_VARIABLE,
                    attrs,
                    &firmware_indications(existing).to_le_bytes(),
                ) {
                    Ok(()) => {
                        serial(b"ISOHOPPER:POWER:FIRMWARE_SETUP\r\n");
                        runtime::reset(ResetType::COLD, Status::SUCCESS, None)
                    }
                    Err(error) => {
                        uefi::println!("Firmware rejected setup request: {:?}", error.status())
                    }
                }
            }
        }
    }
    pub fn run() -> Status {
        if uefi::helpers::init().is_err() {
            return Status::ABORTED;
        }
        if let Err(error) = uefi::boot::set_watchdog_timer(0, 0x10000, None)
            && error.status() != Status::UNSUPPORTED
        {
            uefi::println!("Cannot disable firmware watchdog: {:?}", error.status());
            return error.status();
        }
        uefi::println!("ISOHOPPER 0.1 | experimental | x86_64 UEFI");
        uefi::println!(
            "Firmware: {} revision {:#x}",
            uefi::system::firmware_vendor(),
            uefi::system::firmware_revision()
        );
        let mut secure = [0; 1];
        let secure_state = match runtime::get_variable(
            cstr16!("SecureBoot"),
            &VariableVendor::GLOBAL_VARIABLE,
            &mut secure,
        ) {
            Ok((b, _)) if b == [1] => "enabled",
            Ok((b, _)) if b == [0] => "disabled",
            _ => "unknown",
        };
        uefi::println!("Firmware Secure Boot: {secure_state}");
        uefi::println!("No OS boot provider installed. OS compatibility untested.");
        let config = preferences();
        let supported =
            read_u64(cstr16!("OsIndicationsSupported")).is_ok_and(|value| value & 1 != 0);
        uefi::println!("Power menu:");
        if config.allows(Action::Reboot, supported) {
            uefi::println!("  R  Reboot");
        }
        if config.allows(Action::Shutdown, supported) {
            uefi::println!("  S  Shut down");
        }
        if config.mask & 4 != 0 {
            uefi::println!(
                "  F  Firmware setup{}",
                if supported { "" } else { " [unsupported]" }
            );
        }
        uefi::println!("  X  Return to firmware boot manager");
        serial(b"ISOHOPPER:SMOKE:ENTRY\r\n");
        let mut confirmation = Confirmation::default();
        loop {
            let action = match key().map(|c| c.to_ascii_lowercase()) {
                Some('r') => Action::Reboot,
                Some('s') => Action::Shutdown,
                Some('f') => Action::FirmwareSetup,
                Some('x') => return Status::SUCCESS,
                _ => continue,
            };
            if !confirmation.select(action, config, supported) {
                uefi::println!("Action disabled or unsupported.");
                continue;
            }
            uefi::println!("Confirm {action:?}: press Y. Any other key cancels.");
            if let Some(action) = confirmation.answer(key().unwrap_or('\0')) {
                perform(action);
            } else {
                uefi::println!("Cancelled.");
            }
        }
    }
}
#[cfg(target_os = "uefi")]
#[uefi::entry]
fn main() -> uefi::Status {
    firmware::run()
}
#[cfg(not(target_os = "uefi"))]
fn main() {
    eprintln!("Build for x86_64-unknown-uefi to run the firmware application.");
    std::process::exit(2);
}
