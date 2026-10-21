// SPDX-License-Identifier: GPL-3.0-or-later
use crate::{CommandOutput, CommandRunner, macos::whole_identifier};
use std::io;

pub struct NativeCommandRunner;

fn allowed(program: &str, args: &[&str]) -> bool {
    program == "/usr/sbin/diskutil"
        && match args {
            ["list", "-plist", "physical"] => true,
            ["info", "-plist", id] => *id == "/" || whole_identifier(id),
            _ => false,
        }
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
        {
            execute(program, args)
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native disk inventory is not implemented on this platform",
            ))
        }
    }
}

#[cfg(target_os = "macos")]
fn execute(program: &str, args: &[&str]) -> io::Result<CommandOutput> {
    use crate::MAX_OUTPUT;
    use std::{
        io::Read,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    let mut child = Command::new(program)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
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
    }
}
