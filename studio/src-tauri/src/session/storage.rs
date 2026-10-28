use super::{MAX_STATE_BYTES, STATE_FILE, Saved};
use std::{
    fs::{self, File, Metadata, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

fn no_link(info: &Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        info.file_attributes() & 0x400 == 0
    }
    #[cfg(not(windows))]
    {
        !info.file_type().is_symlink()
    }
}
fn directory(root: &Path, create: bool) -> Result<Option<PathBuf>, String> {
    match fs::symlink_metadata(root) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            if !create {
                return Ok(None);
            }
            fs::create_dir_all(root).map_err(|e| format!("Create saved-session directory: {e}"))?;
        }
        Err(error) => return Err(format!("Inspect saved-session directory: {error}")),
        Ok(_) => (),
    }
    let info = fs::symlink_metadata(root).map_err(|e| e.to_string())?;
    if !info.is_dir() || !no_link(&info) {
        return Err("Saved-session location must be a real directory.".into());
    }
    fs::canonicalize(root)
        .map(Some)
        .map_err(|e| format!("Resolve saved-session directory: {e}"))
}
fn regular(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("Inspect saved session: {error}")),
        Ok(info) if info.is_file() && no_link(&info) => Ok(true),
        Ok(_) => Err("Saved session must be a regular file, not a link or device.".into()),
    }
}
fn open(path: &Path) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(0x0020_0000);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("Open saved session: {e}"))?;
    let info = file.metadata().map_err(|e| e.to_string())?;
    if !info.is_file() || !no_link(&info) || info.len() > MAX_STATE_BYTES {
        return Err("Saved session must be a bounded regular file.".into());
    }
    Ok(file)
}
pub(super) fn read(root: &Path) -> Result<Option<Saved>, String> {
    let Some(root) = directory(root, false)? else {
        return Ok(None);
    };
    let path = root.join(STATE_FILE);
    if !regular(&path)? {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    open(&path)?
        .take(MAX_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("Read saved session: {e}"))?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err("Saved session exceeds the size limit.".into());
    }
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|e| format!("Read saved-session JSON: {e}"))
}
pub(super) fn write(root: &Path, saved: &Saved) -> Result<(), String> {
    let root = directory(root, true)?.ok_or("Saved-session directory is unavailable.")?;
    let path = root.join(STATE_FILE);
    regular(&path)?;
    let identity = same_file::Handle::from_path(&root).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec(saved).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_STATE_BYTES {
        return Err("Saved session exceeds the size limit.".into());
    }
    let mut temporary = tempfile::Builder::new()
        .prefix(".session-")
        .tempfile_in(&root)
        .map_err(|e| format!("Create saved session: {e}"))?;
    temporary
        .write_all(&bytes)
        .map_err(|e| format!("Write saved session: {e}"))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|e| format!("Flush saved session: {e}"))?;
    let checked = directory(&root, false)?.ok_or("Saved-session directory disappeared.")?;
    if same_file::Handle::from_path(checked).map_err(|e| e.to_string())? != identity {
        return Err("Saved-session directory changed.".into());
    }
    regular(&path)?;
    temporary
        .persist(&path)
        .map_err(|e| format!("Publish saved session: {}", e.error))?;
    Ok(())
}
