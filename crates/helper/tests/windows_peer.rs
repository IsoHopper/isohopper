// SPDX-License-Identifier: GPL-3.0-or-later
use isohopper_helper::windows_peer::Sid;

#[test]
fn binary_sids_require_exact_bounded_revision_one_layout() {
    let valid = [1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0];
    assert_eq!(Sid::from_bytes(&valid).unwrap().as_bytes(), valid);
    for end in 0..valid.len() {
        assert!(Sid::from_bytes(&valid[..end]).is_err());
    }
    let mut bad = valid.to_vec();
    bad.push(0);
    assert!(Sid::from_bytes(&bad).is_err());
    for revision in [0, 2, 255] {
        bad = valid.to_vec();
        bad[0] = revision;
        assert!(Sid::from_bytes(&bad).is_err());
    }
    let mut maximum = vec![0; 68];
    maximum[0] = 1;
    maximum[1] = 15;
    assert!(Sid::from_bytes(&maximum).is_ok());
    maximum[1] = 16;
    maximum.extend([0; 4]);
    assert!(Sid::from_bytes(&maximum).is_err());
}

#[test]
fn sid_comparison_is_exact_and_debug_output_is_redacted() {
    let first = Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 21, 0, 0, 0]).unwrap();
    let second = Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5, 22, 0, 0, 0]).unwrap();
    assert_eq!(first, first.clone());
    assert_ne!(first, second);
    assert_eq!(format!("{first:?}"), "Sid(<redacted>)");
}

#[cfg(windows)]
#[test]
#[ignore = "internal child of windows_peer_observes_current_process_and_owned_child"]
fn windows_peer_child_waits_for_parent() {
    use std::io::Read;
    // General `cargo test -- --ignored` must not wait for interactive stdin.
    // Only the parent's disposable child receives this test-local marker.
    if std::env::var_os("ISOHOPPER_PEER_TEST_CHILD").as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    let mut byte = [0];
    std::io::stdin().read_exact(&mut byte).unwrap();
    assert_eq!(byte, [0x5a]);
}

#[cfg(windows)]
#[test]
#[ignore = "read-only current/owned-child process token observations; no UAC or device access"]
fn windows_peer_observes_current_process_and_owned_child() -> Result<(), Box<dyn std::error::Error>>
{
    use isohopper_helper::windows_peer::{PeerError, ProcessPeer};
    use std::{
        io::Write,
        os::windows::io::{AsHandle, FromRawHandle, OwnedHandle},
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
    };

    // Cleanup applies only to the test child created below, even on failures.
    struct OwnChild(Child);
    impl Drop for OwnChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    // SAFETY: opens only this process with the two required read-only rights.
    let own_id = unsafe { GetCurrentProcessId() };
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            own_id,
        )
    };
    if raw.is_null() {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful OpenProcess returned one new owned handle.
    let mut current = ProcessPeer::from_owned_handle(unsafe { OwnedHandle::from_raw_handle(raw) })?;
    assert!(
        current.evidence().process_id == own_id,
        "current process binding mismatch"
    );
    let baseline = current.evidence().clone();
    assert!(
        current.revalidate()? == &baseline,
        "current process changed unexpectedly"
    );

    let mut child = OwnChild(
        Command::new(std::env::current_exe()?)
            .args([
                "--exact",
                "windows_peer_child_waits_for_parent",
                "--ignored",
                "--nocapture",
            ])
            .env("ISOHOPPER_PEER_TEST_CHILD", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let handle = child.0.as_handle().try_clone_to_owned()?;
    let mut observed = ProcessPeer::from_owned_handle(handle)?;
    assert!(
        observed.evidence().process_id == child.0.id(),
        "child binding mismatch"
    );
    assert!(
        observed.evidence().process_id != own_id,
        "child reused current PID"
    );
    assert!(
        observed.evidence().token.user == baseline.token.user,
        "child user mismatch"
    );
    assert!(
        observed.evidence().token.logon == baseline.token.logon,
        "child logon mismatch"
    );
    assert!(
        observed.evidence().token.session_id == baseline.token.session_id,
        "child session mismatch"
    );
    observed.revalidate()?;
    child
        .0
        .stdin
        .take()
        .ok_or("missing child stdin")?
        .write_all(&[0x5a])?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.0.try_wait()? {
            assert!(status.success(), "owned peer test child failed");
            break;
        }
        if Instant::now() >= deadline {
            return Err("owned peer test child timed out".into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        matches!(observed.revalidate(), Err(PeerError::Exited)),
        "exited child was not rejected"
    );
    println!(
        "Windows peer observation passed: current=1 child=1 exited_child_rejected=1; no UAC or device access"
    );
    Ok(())
}
