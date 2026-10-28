// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_inventory::{CommandOutput, CommandRunner, InventoryError, windows_pagefiles};
use serde_json::json;
use std::{cell::RefCell, io};

struct Mock {
    output: CommandOutput,
    error: Option<io::ErrorKind>,
    calls: RefCell<Vec<(String, Vec<String>)>>,
}

impl Mock {
    fn bytes(stdout: Vec<u8>) -> Self {
        Self {
            output: CommandOutput {
                success: true,
                stdout,
                stderr: vec![],
            },
            error: None,
            calls: RefCell::default(),
        }
    }

    fn names(names: &[&str]) -> Self {
        Self::bytes(
            serde_json::to_vec(&json!({
                "pagefiles": names.iter().map(|name| json!({"Name": name})).collect::<Vec<_>>(),
                "query_complete": true
            }))
            .unwrap(),
        )
    }
}

impl CommandRunner for Mock {
    fn run(&self, program: &str, args: &[&str]) -> io::Result<CommandOutput> {
        self.calls
            .borrow_mut()
            .push((program.into(), args.iter().map(|s| (*s).into()).collect()));
        if let Some(kind) = self.error {
            Err(io::Error::new(kind, "private mock path must not appear"))
        } else {
            Ok(self.output.clone())
        }
    }
}

#[test]
fn fixed_local_runtime_query_preserves_observed_paths_and_valid_empty_list() {
    let runner = Mock::names(&[r"D:\swap\pagefile.sys", r"C:\PAGEFILE.SYS"]);
    let observed = windows_pagefiles::collect_with(&runner).unwrap();
    assert_eq!(observed.source, "windows_cim_pagefile_usage");
    assert_eq!(
        observed
            .pagefiles
            .iter()
            .map(|p| p.path.as_str())
            .collect::<Vec<_>>(),
        [r"C:\PAGEFILE.SYS", r"D:\swap\pagefile.sys"]
    );
    let calls = runner.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "powershell.exe");
    assert_eq!(
        &calls[0].1[..4],
        ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]
    );
    assert_eq!(calls[0].1.len(), 5);
    let script = &calls[0].1[4];
    assert!(script.contains(
        "Import-Module ($PSHOME + '\\Modules\\CimCmdlets\\CimCmdlets.psd1') -ErrorAction Stop"
    ));
    assert!(script.contains("CimCmdlets\\Get-CimInstance -Namespace root/cimv2 -ClassName Win32_PageFileUsage -Property Name -OperationTimeoutSec 15 -ErrorAction Stop"));
    assert!(script.contains("Select-Object -First 65"));
    assert!(!script.contains("Win32_PageFileSetting"));
    assert!(!script.contains("-ComputerName"));
    assert!(!script.contains("Set-CimInstance"));
    assert!(!script.contains(r"D:\swap"));
    let empty = windows_pagefiles::collect_with(&Mock::names(&[])).unwrap();
    assert!(empty.pagefiles.is_empty());
}

#[test]
fn query_failures_and_stderr_never_become_empty_success() {
    for kind in [
        io::ErrorKind::PermissionDenied,
        io::ErrorKind::NotFound,
        io::ErrorKind::TimedOut,
    ] {
        let mut runner = Mock::names(&[]);
        runner.error = Some(kind);
        let error = windows_pagefiles::collect_with(&runner).unwrap_err();
        assert!(matches!(error, InventoryError::Command(_)));
        assert!(!error.to_string().contains("private mock path"));
    }
    let mut runner = Mock::names(&[]);
    runner.output.success = false;
    assert!(windows_pagefiles::collect_with(&runner).is_err());
    runner.output.success = true;
    runner.output.stderr = b"private provider error".to_vec();
    let error = windows_pagefiles::collect_with(&runner).unwrap_err();
    assert!(!error.to_string().contains("private provider error"));
}

#[test]
fn missing_wrong_duplicate_or_unknown_json_fields_are_errors() {
    for bytes in [
        b"".as_slice(), b"null", b"[]", b"{}", b"not json",
        &[0xff, 0xfe],
        br#"{"pagefiles":[]}"#,
        br#"{"pagefiles":null,"query_complete":true}"#,
        br#"{"pagefiles":[],"query_complete":null}"#,
        br#"{"pagefiles":[],"query_complete":false}"#,
        br#"{"pagefiles":[],"query_complete":"true"}"#,
        br#"{"pagefiles":[],"query_complete":true,"private_field":1}"#,
        br#"{"pagefiles":[],"pagefiles":[],"query_complete":true}"#,
        br#"{"pagefiles":[],"query_complete":true,"query_complete":true}"#,
        br#"{"pagefiles":[{}],"query_complete":true}"#,
        br#"{"pagefiles":[{"Name":null}],"query_complete":true}"#,
        br#"{"pagefiles":[{"Name":123}],"query_complete":true}"#,
        br#"{"pagefiles":[{"Name":true}],"query_complete":true}"#,
        br#"{"pagefiles":[{"Name":{}}],"query_complete":true}"#,
        br#"{"pagefiles":[{"Name":"C:\\pagefile.sys","private_field":1}],"query_complete":true}"#,
        br#"{"pagefiles":[{"Name":"C:\\pagefile.sys","Name":"D:\\pagefile.sys"}],"query_complete":true}"#,
    ] {
        let error = windows_pagefiles::collect_with(&Mock::bytes(bytes.to_vec())).unwrap_err();
        assert!(!error.to_string().contains("private_field"));
        assert!(!error.to_string().contains("pagefile.sys"));
    }
}

#[test]
fn duplicate_names_and_ambiguous_or_nonlocal_paths_are_errors() {
    assert!(
        windows_pagefiles::collect_with(&Mock::names(&[r"C:\PAGEFILE.SYS", r"c:\pagefile.sys"]))
            .is_err()
    );
    for name in [
        "",
        r"C:",
        r"C:\",
        r"C:pagefile.sys",
        r"\pagefile.sys",
        r"\\host\share\pagefile.sys",
        r"\\?\C:\pagefile.sys",
        r"\\.\PhysicalDrive1",
        r"\??\C:\pagefile.sys",
        r"C:\folder\..\pagefile.sys",
        r"C:\.\pagefile.sys",
        r"C:\\pagefile.sys",
        r"C:\pagefile.sys:stream",
        r"C:/pagefile.sys",
        r"C:\pagefile.sys.",
        r"C:\pagefile.sys ",
        r"C:\folder.\pagefile.sys",
        r"C:\NUL.sys",
        r"C:\COM1\pagefile.sys",
        "C:\\pagefile\0.sys",
        r"C:\*.sys",
        r"C:\page?file.sys",
        "C:\\page\nfile.sys",
    ] {
        assert!(
            windows_pagefiles::collect_with(&Mock::names(&[name])).is_err(),
            "accepted ambiguous path"
        );
    }
}

#[test]
fn records_paths_and_both_output_streams_are_bounded() {
    let names: Vec<_> = (0..65).map(|i| format!(r"C:\pagefile{i}.sys")).collect();
    assert_eq!(
        windows_pagefiles::collect_with(&Mock::names(
            &names[..64].iter().map(String::as_str).collect::<Vec<_>>()
        ))
        .unwrap()
        .pagefiles
        .len(),
        64
    );
    assert!(
        windows_pagefiles::collect_with(&Mock::names(
            &names.iter().map(String::as_str).collect::<Vec<_>>()
        ))
        .is_err()
    );
    let path = format!("C:\\{}", "x".repeat(4096));
    assert!(windows_pagefiles::collect_with(&Mock::names(&[&path])).is_err());
    let mut runner = Mock::names(&[]);
    runner.output.stdout = vec![b' '; 2 * 1024 * 1024 + 1];
    assert!(windows_pagefiles::collect_with(&runner).is_err());
    runner = Mock::names(&[]);
    runner.output.stderr = vec![b' '; 2 * 1024 * 1024 + 1];
    assert!(windows_pagefiles::collect_with(&runner).is_err());
}

#[test]
fn valid_unicode_and_shell_characters_remain_data_never_command_inputs() {
    let name = r"D:\Mémoire\swap-$value;'quoted'.sys";
    let baseline = Mock::names(&[]);
    windows_pagefiles::collect_with(&baseline).unwrap();
    let runner = Mock::names(&[name]);
    let observed = windows_pagefiles::collect_with(&runner).unwrap();
    assert_eq!(observed.pagefiles[0].path, name);
    assert_eq!(*runner.calls.borrow(), *baseline.calls.borrow());
}

#[cfg(not(target_os = "windows"))]
#[test]
fn native_collection_is_explicitly_unsupported_off_windows() {
    assert!(matches!(
        windows_pagefiles::collect(),
        Err(InventoryError::Unsupported(_))
    ));
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "observes current Windows pagefile metadata; never creates or modifies pagefiles"]
fn native_windows_pagefiles_observes_only_active_runtime_names() {
    let observed = windows_pagefiles::collect().expect("read-only active-pagefile query failed");
    assert_eq!(observed.source, "windows_cim_pagefile_usage");
    assert!(observed.pagefiles.len() <= 64);
    // Names remain private even when the smoke test runs with --nocapture.
    println!("active_pagefiles={}", observed.pagefiles.len());
}
