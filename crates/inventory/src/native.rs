// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{CommandOutput, CommandRunner, linux, macos::whole_identifier, windows};
use std::io;
#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
use std::path::Path;

pub struct NativeCommandRunner;

fn allowed(program: &str, args: &[&str]) -> bool {
    (program == "/usr/sbin/diskutil"
        && match args {
            ["list", "-plist", "physical"] => true,
            ["info", "-plist", id] => *id == "/" || whole_identifier(id),
            _ => false,
        })
        || (program == linux::LSBLK && args == linux::ARGS)
        || (program == windows::POWERSHELL && args == windows::ARGS)
}

impl CommandRunner for NativeCommandRunner {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        if !allowed(program, args) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "only read-only inventory commands are permitted",
            ));
        }
        #[cfg(target_os = "macos")]
        if program == "/usr/sbin/diskutil" {
            return execute(Path::new(program), args);
        }
        #[cfg(target_os = "linux")]
        if program == linux::LSBLK {
            return execute(Path::new(program), args);
        }
        #[cfg(target_os = "windows")]
        if program == windows::POWERSHELL {
            return execute(&powershell_path()?, args);
        }
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "inventory command does not match the host platform",
        ))
    }
}

#[cfg(target_os = "windows")]
fn powershell_path() -> io::Result<std::path::PathBuf> {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    let mut buffer = vec![0u16; 32768];
    // SAFETY: the writable buffer contains exactly the supplied number of u16s.
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    };
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    if length as usize >= buffer.len() {
        return Err(io::Error::other(
            "Windows system directory exceeds the path limit",
        ));
    }
    let system = std::path::PathBuf::from(OsString::from_wide(&buffer[..length as usize]));
    if !system.is_absolute() {
        return Err(io::Error::other("Windows system directory is not absolute"));
    }
    Ok(system.join(r"WindowsPowerShell\v1.0\powershell.exe"))
}

#[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
fn execute(program: &Path, args: &[&str]) -> io::Result<CommandOutput> {
    use crate::MAX_OUTPUT;
    use std::{
        io::Read,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    let mut command = Command::new(program);
    command
        .args(args)
        .env("LC_ALL", "C")
        .env_remove("LIBSMARTCOLS_JSON")
        .env_remove("LSBLK_DEBUG")
        .env_remove("LIBBLKID_DEBUG")
        .env_remove("LIBMOUNT_DEBUG")
        .env_remove("LIBSMARTCOLS_DEBUG")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        // Restrict module discovery as well as the executable. No user profile,
        // shell wrapper, execution-policy bypass, elevation, or device path is passed.
        command.env(
            "PSModulePath",
            program
                .parent()
                .expect("absolute PowerShell path")
                .join("Modules"),
        );
        command.current_dir(program.parent().expect("absolute PowerShell path"));
        command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let mut child = command.spawn()?;
    let stdout = child.stdout.take().expect("piped stdout");
    let stderr = child.stderr.take().expect("piped stderr");
    fn capped(reader: impl Read) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        reader
            .take((MAX_OUTPUT + 1) as u64)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    }
    let stdout = thread::spawn(move || capped(stdout));
    let stderr = thread::spawn(move || capped(stderr));
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                break Err(result.err().unwrap_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        "read-only inventory command timed out",
                    )
                }));
            }
        }
    };
    let stdout = stdout
        .join()
        .map_err(|_| io::Error::other("inventory stdout reader failed"))??;
    let stderr = stderr
        .join()
        .map_err(|_| io::Error::other("inventory stderr reader failed"))??;
    Ok(CommandOutput {
        success: status?.success(),
        stdout,
        stderr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_allowlist_rejects_writes_shells_and_untrusted_device_paths() {
        let runner = NativeCommandRunner;
        for (program, args) in [
            ("/bin/sh", vec!["-c", "echo test"]),
            (
                "/usr/sbin/diskutil",
                vec!["eraseDisk", "FAT32", "TEST", "disk4"],
            ),
            ("/usr/sbin/diskutil", vec!["unmount", "disk4"]),
            ("/usr/sbin/diskutil", vec!["info", "-plist", "/dev/disk4"]),
            ("/usr/sbin/diskutil", vec!["info", "-plist", "disk4;echo"]),
            ("diskutil", vec!["list", "-plist", "physical"]),
            ("lsblk", vec!["--json"]),
            ("/usr/bin/lsblk", vec!["--json", "/dev/sda"]),
            ("/usr/bin/lsblk", vec!["--json", "--sysroot", "/tmp"]),
        ] {
            assert_eq!(
                runner.run(program, &args).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        assert!(allowed(
            "/usr/sbin/diskutil",
            &["list", "-plist", "physical"]
        ));
        assert!(allowed("/usr/sbin/diskutil", &["info", "-plist", "/"]));
        assert!(allowed("/usr/sbin/diskutil", &["info", "-plist", "disk4"]));
        assert!(allowed(linux::LSBLK, linux::ARGS));
        let mut injected = linux::ARGS.to_vec();
        injected.push("/dev/sda");
        assert!(!allowed(linux::LSBLK, &injected));
    }

    #[test]
    fn windows_allows_only_the_fixed_read_only_script() {
        use crate::windows;
        assert!(allowed(windows::POWERSHELL, windows::ARGS));
        let mut changed = windows::ARGS.to_vec();
        changed[4] = "Get-Disk | Clear-Disk";
        assert!(!allowed(windows::POWERSHELL, &changed));
        let mut extra = windows::ARGS.to_vec();
        extra.push("untrusted-device");
        assert!(!allowed(windows::POWERSHELL, &extra));
        assert!(!allowed("pwsh", windows::ARGS));
        assert!(!allowed(r"C:\untrusted\powershell.exe", windows::ARGS));
        #[cfg(not(target_os = "windows"))]
        assert_eq!(
            NativeCommandRunner
                .run(windows::POWERSHELL, windows::ARGS)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Unsupported
        );
    }
}
