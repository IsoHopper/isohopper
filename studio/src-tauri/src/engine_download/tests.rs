use super::*;
use std::{
    cell::Cell,
    fs,
    io::{self, Cursor},
};

const TEST_PIN: Pin = Pin {
    bytes: 3,
    sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
};
fn fixture(body: &[u8], length: Option<u64>) -> Result<Download, String> {
    Ok(Download {
        body: Box::new(Cursor::new(body.to_vec())),
        length,
    })
}
fn job() -> Job {
    Job::new("a".repeat(64), TEST_PIN)
}
fn entries(path: &Path) -> Vec<PathBuf> {
    fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect()
}

#[test]
fn verified_download_is_published_before_selection_without_partial_files() {
    let root = tempfile::tempdir().unwrap();
    let selected = Cell::new(false);
    let download_job = job();
    assert!(
        !obtain(
            root.path(),
            &download_job,
            TEST_PIN,
            || fixture(b"abc", None),
            |path| {
                assert_eq!(fs::read(path).unwrap(), b"abc");
                let files = entries(root.path());
                assert_eq!(files.len(), 1);
                assert_eq!(fs::canonicalize(&files[0]).unwrap(), path);
                selected.set(true);
                Ok(())
            }
        )
        .unwrap()
    );
    assert!(selected.get());
    assert_eq!(fs::read(root.path().join(FILE_NAME)).unwrap(), b"abc");
    assert_eq!(download_job.snapshot().unwrap().completed_bytes, 3);
}

#[test]
fn truncation_oversize_hash_and_lying_length_never_publish_or_select() {
    for (bytes, length, reason) in [
        (&b"ab"[..], None, "size"),
        (&b"abcd"[..], None, "size"),
        (&b"abcd"[..], Some(3), "size"),
        (&b"abd"[..], Some(3), "SHA-256"),
        (&b"abc"[..], Some(4), "size"),
        (&b"abc"[..], Some(2), "size"),
    ] {
        let root = tempfile::tempdir().unwrap();
        let error = obtain(
            root.path(),
            &job(),
            TEST_PIN,
            || fixture(bytes, length),
            |_| panic!("unverified selection"),
        )
        .unwrap_err();
        assert!(error.contains(reason), "{error}");
        assert!(entries(root.path()).is_empty());
    }
}

struct BrokenReader(bool);
impl Read for BrokenReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.0 {
            return Err(io::Error::other("broken stream"));
        }
        self.0 = true;
        buffer[0] = b'a';
        Ok(1)
    }
}
#[test]
fn stream_failure_removes_partial_file() {
    let root = tempfile::tempdir().unwrap();
    let error = obtain(
        root.path(),
        &job(),
        TEST_PIN,
        || {
            Ok(Download {
                body: Box::new(BrokenReader(false)),
                length: None,
            })
        },
        |_| panic!("selection after failure"),
    )
    .unwrap_err();
    assert!(error.contains("Read engine download"), "{error}");
    assert!(entries(root.path()).is_empty());
}

#[test]
fn valid_cache_is_rehashed_and_selected_without_network() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join(FILE_NAME), b"abc").unwrap();
    let selected = Cell::new(false);
    assert!(
        obtain(
            root.path(),
            &job(),
            TEST_PIN,
            || panic!("network for valid cache"),
            |path| {
                assert_eq!(fs::read(path).unwrap(), b"abc");
                selected.set(true);
                Ok(())
            }
        )
        .unwrap()
    );
    assert!(selected.get());
}

#[test]
fn corrupt_cache_is_repaired_before_selection() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join(FILE_NAME), b"abd").unwrap();
    assert!(
        !obtain(
            root.path(),
            &job(),
            TEST_PIN,
            || fixture(b"abc", Some(3)),
            |path| {
                assert_eq!(fs::read(path).unwrap(), b"abc");
                Ok(())
            }
        )
        .unwrap()
    );
    assert_eq!(fs::read(root.path().join(FILE_NAME)).unwrap(), b"abc");
    assert_eq!(entries(root.path()).len(), 1);
}

#[test]
fn cancellation_before_fetch_never_touches_network_or_creates_partial() {
    let root = tempfile::tempdir().unwrap();
    let download_job = job();
    download_job.state.lock().unwrap().cancel_requested = true;
    let error = obtain(
        root.path(),
        &download_job,
        TEST_PIN,
        || panic!("fetch after cancellation"),
        |_| panic!("selection after cancellation"),
    )
    .unwrap_err();
    assert!(error.contains("cancelled"), "{error}");
    assert!(entries(root.path()).is_empty());
}

struct CancellingReader(std::sync::Arc<Job>);
impl Read for CancellingReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.0.state.lock().unwrap().cancel_requested = true;
        buffer[0] = b'a';
        Ok(1)
    }
}
#[test]
fn cancellation_during_stream_removes_partial_and_never_selects() {
    let root = tempfile::tempdir().unwrap();
    let download_job = std::sync::Arc::new(job());
    let body_job = download_job.clone();
    let error = obtain(
        root.path(),
        &download_job,
        TEST_PIN,
        || {
            Ok(Download {
                body: Box::new(CancellingReader(body_job)),
                length: None,
            })
        },
        |_| panic!("selection after cancellation"),
    )
    .unwrap_err();
    assert!(error.contains("cancelled"), "{error}");
    assert!(entries(root.path()).is_empty());
}

#[test]
fn publication_never_overwrites_a_file_created_during_download() {
    let root = tempfile::tempdir().unwrap();
    let destination = root.path().join(FILE_NAME);
    let error = obtain(
        root.path(),
        &job(),
        TEST_PIN,
        || {
            fs::write(&destination, b"other file").unwrap();
            fixture(b"abc", None)
        },
        |_| panic!("selection after conflicting publish"),
    )
    .unwrap_err();
    assert!(error.contains("Publish"), "{error}");
    assert_eq!(fs::read(&destination).unwrap(), b"other file");
    assert_eq!(entries(root.path()), [destination]);
}

#[cfg(unix)]
#[test]
fn cache_symlinks_are_rejected_without_touching_their_targets() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let target = outside.path().join("unrelated");
    fs::write(&target, b"abc").unwrap();
    symlink(&target, root.path().join(FILE_NAME)).unwrap();
    let error = obtain(
        root.path(),
        &job(),
        TEST_PIN,
        || panic!("fetch for unsafe cache"),
        |_| panic!("select unsafe cache"),
    )
    .unwrap_err();
    assert!(error.contains("regular file"), "{error}");
    assert_eq!(fs::read(target).unwrap(), b"abc");
    let linked_root = root.path().join("linked-directory");
    symlink(outside.path(), &linked_root).unwrap();
    let error = obtain(
        &linked_root,
        &job(),
        TEST_PIN,
        || panic!("fetch through linked root"),
        |_| panic!("select through linked root"),
    )
    .unwrap_err();
    assert!(error.contains("directory"), "{error}");
    assert_eq!(entries(outside.path()).len(), 1);
}

#[test]
fn registry_rejects_duplicates_and_stale_cancel_without_losing_active_job() {
    let registry = Registry::default();
    let first = Arc::new(job());
    registry.register(first.clone()).unwrap();
    let second = Arc::new(Job::new("b".repeat(64), TEST_PIN));
    assert!(registry.register(second.clone()).is_err());
    assert!(registry.cancel(&"b".repeat(64)).is_err());
    assert!(!first.snapshot().unwrap().cancel_requested);
    registry.cancel(&"a".repeat(64)).unwrap();
    assert!(first.snapshot().unwrap().cancel_requested);
    first.finish(Err("cancelled".into()));
    registry.register(second.clone()).unwrap();
    assert!(registry.cancel(&"a".repeat(64)).is_err());
    assert!(!second.snapshot().unwrap().cancel_requested);
}

#[test]
fn final_selection_and_cancellation_have_one_winner() {
    let ready = job();
    ready.select(false, || Ok(())).unwrap();
    assert!(ready.request_cancel().is_err());
    ready.finish(Ok(false));
    let snapshot = ready.snapshot().unwrap();
    assert_eq!(snapshot.phase, "ready");
    assert!(!snapshot.active);
    assert!(!snapshot.cancel_requested);
    let cancelled = job();
    cancelled.request_cancel().unwrap();
    assert!(
        cancelled
            .select(false, || panic!("select after accepted cancellation"))
            .is_err()
    );
    cancelled.finish(Err("cancelled".into()));
    assert_eq!(cancelled.snapshot().unwrap().phase, "cancelled");
}

#[test]
fn selected_archive_does_not_publish_ready_until_worker_cleanup_finishes() {
    let download_job = job();
    download_job.progress("verifying", 3).unwrap();
    download_job.select(false, || Ok(())).unwrap();
    let before_cleanup = download_job.snapshot().unwrap();
    assert_ne!(before_cleanup.phase, "ready");
    assert!(before_cleanup.active);
    assert!(download_job.request_cancel().is_err());
    download_job.finish(Ok(false));
    let finished = download_job.snapshot().unwrap();
    assert_eq!(finished.phase, "ready");
    assert!(!finished.active);
}

#[test]
fn worker_retains_native_guard_until_cleanup_and_terminal_status() {
    struct Guard<'a> {
        root: &'a Path,
        job: &'a Job,
        dropped: &'a Cell<bool>,
    }
    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            assert!(
                entries(self.root).is_empty(),
                "guard released before partial cleanup"
            );
            assert!(
                !self.job.snapshot().unwrap().active,
                "guard released before terminal state"
            );
            self.dropped.set(true);
        }
    }
    let root = tempfile::tempdir().unwrap();
    let download_job = job();
    let dropped = Cell::new(false);
    let guard = Guard {
        root: root.path(),
        job: &download_job,
        dropped: &dropped,
    };
    run_worker(&download_job, guard, || {
        assert!(!dropped.get());
        obtain(
            root.path(),
            &download_job,
            TEST_PIN,
            || {
                Ok(Download {
                    body: Box::new(BrokenReader(false)),
                    length: None,
                })
            },
            |_| panic!("select broken stream"),
        )
    });
    assert!(dropped.get());
    assert_eq!(download_job.snapshot().unwrap().phase, "failed");
}

#[test]
fn worker_bounds_external_error_text_in_snapshot() {
    let download_job = job();
    run_worker(&download_job, (), || Err("bad input ".repeat(10_000)));
    let snapshot = download_job.snapshot().unwrap();
    assert_eq!(snapshot.phase, "failed");
    assert!(snapshot.message.len() <= 8192);
    assert!(!snapshot.active);
}

#[test]
fn redirect_policy_allows_only_bounded_https_release_hosts_without_credentials() {
    for url in [
        DOWNLOAD_URL,
        "https://release-assets.githubusercontent.com/github-production-release-asset/123?sig=value",
    ] {
        assert!(network::allowed_redirect(&url.parse().unwrap(), 1), "{url}");
        assert!(
            !network::allowed_redirect(&url.parse().unwrap(), 5),
            "too many redirects"
        );
    }
    for url in [
        "http://github.com/ventoy",
        "https://github.com.evil.example/file",
        "https://github.com@evil.example/file",
        "https://user:password@github.com/file",
        "https://user@github.com/file",
        "https://release-assets.githubusercontent.com:8443/file",
        "https://127.0.0.1/file",
        "file:///tmp/archive",
    ] {
        assert!(
            !network::allowed_redirect(&url.parse().unwrap(), 1),
            "{url}"
        );
    }
}

#[test]
fn actual_blocking_client_reads_body_without_a_tokio_runtime() {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 4096, "oversized loopback request");
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc")
            .unwrap();
    });
    // Only this test relaxes HTTPS, for its loopback fixture. The production
    // builder and public API expose no URL or transport override.
    let client = network::client_builder().https_only(false).build().unwrap();
    let mut response = client
        .get(format!("http://{address}/archive"))
        .send()
        .unwrap();
    let mut body = Vec::new();
    response.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"abc");
    server.join().unwrap();
}

#[test]
fn restore_revalidates_and_selects_existing_cache_without_creating_missing_directories() {
    let root = tempfile::tempdir().unwrap();
    let absent = root.path().join("absent");
    assert!(!restore_cache(&absent, TEST_PIN, |_| panic!("selection without cache")).unwrap());
    assert!(!absent.exists());
    let path = root.path().join(FILE_NAME);
    fs::write(&path, b"abc").unwrap();
    let selected = Cell::new(false);
    assert!(
        restore_cache(root.path(), TEST_PIN, |path| {
            assert_eq!(fs::read(path).unwrap(), b"abc");
            selected.set(true);
            Ok(())
        })
        .unwrap()
    );
    assert!(selected.get());
    fs::write(&path, b"bad").unwrap();
    assert!(!restore_cache(root.path(), TEST_PIN, |_| panic!("select corrupt cache")).unwrap());
    assert_eq!(fs::read(path).unwrap(), b"bad");
}

#[test]
#[ignore = "downloads the pinned official archive into a disposable cache; requires ISOHOPPER_LIVE_ENGINE_DOWNLOAD=1"]
fn live_official_download() {
    assert_eq!(
        std::env::var("ISOHOPPER_LIVE_ENGINE_DOWNLOAD").as_deref(),
        Ok("1")
    );
    let root = tempfile::tempdir().unwrap();
    let initial = start(
        root.path().to_path_buf(),
        crate::NativeJob::begin().unwrap(),
    )
    .unwrap();
    assert_eq!(initial.job_id.len(), 64);
    assert!(
        initial
            .job_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(240);
    let completed = loop {
        let snapshot = status().unwrap().unwrap();
        if !snapshot.active {
            break snapshot;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "live download did not finish"
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert_eq!(completed.phase, "ready", "{}", completed.message);
    assert!(!completed.cache_hit);
    assert_eq!(completed.completed_bytes, 20_320_548);
    let selected = crate::preparation::inputs::selected_archive()
        .unwrap()
        .unwrap();
    assert_eq!(selected.sha256, ARCHIVE_SHA256);
    assert!(restore(root.path().to_path_buf()).unwrap());
    assert_eq!(entries(root.path()).len(), 1);
}
