use same_file::Handle;
use std::{
    fs::{self, File, Metadata, OpenOptions},
    path::{Path, PathBuf},
};

pub(super) struct Directory {
    pub path: PathBuf,
    identity: Handle,
}
impl Directory {
    pub fn open(path: &Path) -> Result<Self, String> {
        match fs::symlink_metadata(path) {
            Ok(info) if !plain_directory(&info) => {
                return Err("Engine cache must be a real directory.".into());
            }
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(path)
                    .map_err(|e| format!("Create engine cache directory: {e}"))?;
            }
            Err(error) => return Err(format!("Inspect engine cache directory: {error}")),
        }
        if !plain_directory(&fs::symlink_metadata(path).map_err(|e| e.to_string())?) {
            return Err("Engine cache must be a real directory.".into());
        }
        let path =
            fs::canonicalize(path).map_err(|e| format!("Resolve engine cache directory: {e}"))?;
        let identity =
            Handle::from_path(&path).map_err(|e| format!("Retain engine cache directory: {e}"))?;
        Ok(Self { path, identity })
    }
    pub fn check(&self) -> Result<(), String> {
        let info = fs::symlink_metadata(&self.path)
            .map_err(|e| format!("Recheck engine cache directory: {e}"))?;
        if !plain_directory(&info)
            || Handle::from_path(&self.path).map_err(|e| e.to_string())? != self.identity
        {
            return Err("Engine cache directory changed during download.".into());
        }
        Ok(())
    }
}
fn no_reparse(info: &Metadata) -> bool {
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
fn plain_directory(info: &Metadata) -> bool {
    info.is_dir() && no_reparse(info)
}
pub(super) fn open_regular(path: &Path) -> Result<File, String> {
    let info = fs::symlink_metadata(path).map_err(|e| format!("Inspect engine cache file: {e}"))?;
    if !info.is_file() || !no_reparse(&info) {
        return Err("Engine cache entry must be a regular file, not a link or device.".into());
    }
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
        options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT
    }
    let file = options
        .open(path)
        .map_err(|e| format!("Open engine cache file: {e}"))?;
    let info = file.metadata().map_err(|e| e.to_string())?;
    if !info.is_file() || !no_reparse(&info) {
        return Err("Engine cache entry must be a regular file.".into());
    }
    Ok(file)
}
pub(super) fn identity(file: &File) -> Result<Handle, String> {
    Handle::from_file(file.try_clone().map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}
pub(super) fn same_file(path: &Path, expected: &Handle) -> Result<(), String> {
    if identity(&open_regular(path)?)? != *expected {
        return Err("Engine cache file changed during download.".into());
    }
    Ok(())
}
