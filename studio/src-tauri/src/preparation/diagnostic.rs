// SPDX-License-Identifier: GPL-3.0-or-later
//! Debug-build-only installed-process regression. There is deliberately no
//! SourcesComplete/Confirm path: the real broker must cancel before execution.
use super::{Channel, ClientMessage, ClientSession, Job, Outcome, ServerMessage, remote_handle};
use crate::imports::source_catalog::{PreparedSource, SourceCatalog};
use isohopper_core::engine::archive::{ARCHIVE_BYTES, ARCHIVE_SHA256};
use isohopper_helper::{
    broker_probe::check_studio, windows_pipe::Server, windows_probe::current_peer,
};
use std::{
    fs::File,
    io::{self, BufRead, Read, Write},
};

pub(crate) fn requested() -> bool {
    std::env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--diagnose-empty-preparation"))
}

pub(crate) fn run() -> Result<(), String> {
    if std::env::args_os().count() != 2 {
        return Err("Empty preparation diagnostic takes no arguments".into());
    }
    let local = current_peer().map_err(|e| e.to_string())?;
    check_studio(local.evidence()).map_err(|e| e.to_string())?;
    let server = Server::create().map_err(|e| e.to_string())?;

    // A normal retained Studio file, not a delete-pending tempfile handle. Its
    // synthetic bytes cannot become a boot image: this flow only sends Cancel
    // once the helper confirms receipt, before it opens any target or archive.
    let root = tempfile::tempdir().map_err(|e| e.to_string())?;
    let path = root.path().join("synthetic-engine.tar.gz");
    File::create(&path)
        .and_then(|f| f.set_len(ARCHIVE_BYTES as u64))
        .map_err(|e| e.to_string())?;
    let mut sources = SourceCatalog::default();
    let info = sources
        .insert_batch(vec![PreparedSource::new(
            File::open(&path).map_err(|e| e.to_string())?,
            "synthetic-engine.tar.gz",
        )?])?
        .remove(0);
    let archive = sources.lease(&info.source_id)?;
    println!(
        "{}",
        serde_json::json!({
            "nonce": server.endpoint().nonce(),
            "studio_pid": local.evidence().process_id,
            "studio_created": local.evidence().creation_time,
        })
    );
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut reply = String::new();
    io::stdin()
        .lock()
        .take(32)
        .read_line(&mut reply)
        .map_err(|e| e.to_string())?;
    let text = reply
        .strip_suffix('\n')
        .ok_or("Missing diagnostic parent response")?
        .trim_end_matches('\r');
    let pid: u32 = text.parse().map_err(|_| "Invalid diagnostic helper PID")?;
    if pid == 0 || pid.to_string() != text {
        return Err("Invalid diagnostic helper PID".into());
    }
    let launched = crate::elevation::accept_diagnostic_helper(server, pid)?;
    let mut channel = Channel {
        launched,
        protocol: ClientSession::new(0),
        current: None,
        terminal_received: false,
    };
    let job = Job::new("0".repeat(64));
    let result = (|| {
        channel.receive(&job)?;
        if !matches!(channel.body()?, ServerMessage::Hello) {
            return Err("Diagnostic expected greeting".into());
        }
        channel.reply(
            &job,
            ClientMessage::Begin {
                target_selector: "diagnostic-no-device-selector".into(),
                source_count: 0,
            },
        )?;
        channel.receive(&job)?;
        if !matches!(channel.body()?, ServerMessage::NeedArchive) {
            return Err("Diagnostic expected engine request".into());
        }
        archive.with_verified_source(|file, _| {
            channel.reply(
                &job,
                ClientMessage::Archive {
                    remote_handle: remote_handle(file)?,
                    bytes: ARCHIVE_BYTES as u64,
                    sha256: ARCHIVE_SHA256.into(),
                },
            )?;
            channel.receive(&job)
        })?;
        if !matches!(channel.body()?, ServerMessage::InputsReady) {
            return Err("Diagnostic expected zero-source input acknowledgement".into());
        }
        channel.reply(&job, ClientMessage::Cancel)?;
        channel.receive(&job)?;
        if !matches!(
            channel.body()?,
            ServerMessage::Terminal {
                outcome: Outcome::Cancelled,
                bytes_written: 0,
                bytes_verified: 0,
                target_may_be_incomplete: false,
                ..
            }
        ) {
            return Err("Diagnostic expected cancellation without device writes".into());
        }
        channel.finish_terminal(&job)
    })();
    let cleanup = channel.launched.close_and_wait();
    super::with_cleanup(result, cleanup)?;
    println!("EMPTY_PREPARATION_HANDOFF_OK");
    Ok(())
}

#[cfg(test)]
#[path = "diagnostic_test.rs"]
mod tests;
