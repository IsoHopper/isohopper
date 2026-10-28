// SPDX-License-Identifier: GPL-3.0-or-later
//! New regular-file GPT images, optionally with FAT32 EFI boot volumes.
//! Every write uses a retained handle to a newly created regular file.
use crate::layout::{self, Layout, LayoutError};
use same_file::Handle;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};
use thiserror::Error;

mod gpt;

type BootImage<'a> = (&'a [crate::fat::Volume; 2], &'a [u8], Option<&'a [u8]>);

#[derive(Debug, Error)]
pub enum VirtualDiskError {
    #[error(transparent)]
    Fat(#[from] crate::fat::FatError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Layout(#[from] LayoutError),
    #[error("invalid GPT image: {0}")]
    Invalid(String),
    #[error("random identifier generation failed: {0}")]
    Entropy(String),
}

/// Create an image with identical x64 EFI applications in both boot slots.
/// The data partition remains unformatted. This does not prove firmware boot.
pub fn create_bootable(
    path: impl AsRef<Path>,
    p: &Layout,
    payload: &[u8],
) -> Result<(), VirtualDiskError> {
    create_bootable_configured(path, p, payload, crate::fat::DEFAULT_POWER_MASK)
}

/// Include the same IHPOWER.CFG in both boot volumes. Bits 0, 1, and 2 enable
/// reboot, shutdown, and firmware setup respectively; all other bits are invalid.
/// These are firmware menu preferences and never execute host power operations.
pub fn create_bootable_configured(
    path: impl AsRef<Path>,
    p: &Layout,
    payload: &[u8],
    power_mask: u8,
) -> Result<(), VirtualDiskError> {
    let volumes = crate::fat::prepare(p, payload, power_mask, None)?;
    create_image(path.as_ref(), p, Some((&volumes, payload, None)))
}

/// Also embed a caller-supplied EFI utility at IHUTIL.EFI in both boot slots.
/// Structural validation is not publisher authentication; firmware controls
/// whether the utility may execute under its Secure Boot policy.
pub fn create_bootable_with_utility(
    path: impl AsRef<Path>,
    p: &Layout,
    payload: &[u8],
    power_mask: u8,
    utility: &[u8],
) -> Result<(), VirtualDiskError> {
    let volumes = crate::fat::prepare(p, payload, power_mask, Some(utility))?;
    create_image(path.as_ref(), p, Some((&volumes, payload, Some(utility))))
}

/// Verify GPT and every initialized FAT32 byte against the expected payload.
pub fn verify_bootable(path: impl AsRef<Path>, payload: &[u8]) -> Result<(), VirtualDiskError> {
    verify_bootable_inner(path.as_ref(), payload, None)
}

/// Verify both boot slots against the exact expected launcher and utility.
pub fn verify_bootable_with_utility(
    path: impl AsRef<Path>,
    payload: &[u8],
    utility: &[u8],
) -> Result<(), VirtualDiskError> {
    verify_bootable_inner(path.as_ref(), payload, Some(utility))
}

fn verify_bootable_inner(
    path: &Path,
    payload: &[u8],
    utility: Option<&[u8]>,
) -> Result<(), VirtualDiskError> {
    crate::fat::validate_efi_x64(payload)?;
    if let Some(utility) = utility {
        crate::fat::validate_efi_x64(utility)?;
    }
    let mut file = open_regular_read(path)?;
    let before = file.metadata()?;
    let identity = Handle::from_file(file.try_clone()?)?;
    check_identity(path, &identity, before.len())?;
    let p = gpt::inspect_reader(&mut file, before.len())?;
    crate::fat::verify_existing(&mut file, &p, payload, utility)?;
    let after = file.metadata()?;
    if after.len() != before.len() || after.modified()? != before.modified()? {
        return Err(invalid("image changed during verification"));
    }
    check_identity(path, &identity, before.len())
}

/// Create exclusively. An error may leave an incomplete image; existing paths
/// are never overwritten. All mutations use the newly created, retained file.
pub fn create(path: impl AsRef<Path>, p: &Layout) -> Result<(), VirtualDiskError> {
    create_image(path.as_ref(), p, None)
}

fn create_image(
    path: &Path,
    p: &Layout,
    boot: Option<BootImage<'_>>,
) -> Result<(), VirtualDiskError> {
    layout::validate(p)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("image must be a regular file"));
    }
    let identity = Handle::from_file(file.try_clone()?)?;
    populate(&mut file, p)?;
    if let Some((volumes, payload, utility)) = boot {
        crate::fat::write_volumes(&mut file, volumes, payload, utility)?;
        file.sync_all()?;
        gpt::verify_reader(&mut file, p.size_bytes)?;
        crate::fat::verify_volumes(&mut file, volumes, payload, utility)?;
    }
    check_identity(path, &identity, p.size_bytes)
}

/// Verify canonical GPT metadata only, not filesystems or bootability.
pub fn verify(path: impl AsRef<Path>) -> Result<(), VirtualDiskError> {
    let path = path.as_ref();
    let mut file = open_regular_read(path)?;
    let before = file.metadata()?;
    let identity = Handle::from_file(file.try_clone()?)?;
    check_identity(path, &identity, before.len())?;
    gpt::verify_reader(&mut file, before.len())?;
    let after = file.metadata()?;
    if after.len() != before.len() || after.modified()? != before.modified()? {
        return Err(invalid("image changed during verification"));
    }
    check_identity(path, &identity, before.len())
}

fn invalid(message: impl Into<String>) -> VirtualDiskError {
    VirtualDiskError::Invalid(message.into())
}

fn open_regular_read(path: &Path) -> Result<File, VirtualDiskError> {
    if !fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(invalid(
            "image must be a regular file, not a symlink or device",
        ));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    // Reject final symlink races and do not block if a path becomes a FIFO.
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
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(invalid("opened image is not a regular file"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(invalid("image is a reparse point"));
        }
    }
    Ok(file)
}

fn check_identity(path: &Path, identity: &Handle, size: u64) -> Result<(), VirtualDiskError> {
    let file = open_regular_read(path)?;
    let observed_size = file.metadata()?.len();
    let current = Handle::from_file(file)?;
    if &current != identity || observed_size != size {
        return Err(invalid("image identity or size changed"));
    }
    Ok(())
}

trait ImageIo: Read + Write + Seek {
    fn make_sparse(&mut self) -> io::Result<()>;
    fn set_len(&mut self, size: u64) -> io::Result<()>;
    fn sync_all(&mut self) -> io::Result<()>;
}
impl ImageIo for File {
    fn make_sparse(&mut self) -> io::Result<()> {
        #[cfg(windows)]
        {
            use std::os::windows::{fs::MetadataExt, io::AsRawHandle};
            use windows_sys::Win32::{
                Storage::FileSystem::FILE_ATTRIBUTE_SPARSE_FILE,
                System::{IO::DeviceIoControl, Ioctl::FSCTL_SET_SPARSE},
            };
            let mut returned = 0;
            // SAFETY: this is the retained, synchronous handle of the newly
            // created regular file. A null input requests SetSparse = TRUE;
            // there is no output buffer and returned remains valid for the call.
            let success = unsafe {
                DeviceIoControl(
                    self.as_raw_handle(),
                    FSCTL_SET_SPARSE,
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    0,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if success == 0 {
                return Err(io::Error::last_os_error());
            }
            if self.metadata()?.file_attributes() & FILE_ATTRIBUTE_SPARSE_FILE == 0 {
                return Err(io::Error::other("Windows did not mark the image sparse"));
            }
        }
        Ok(())
    }
    fn set_len(&mut self, size: u64) -> io::Result<()> {
        File::set_len(self, size)
    }
    fn sync_all(&mut self) -> io::Result<()> {
        File::sync_all(self)
    }
}

fn populate(image: &mut impl ImageIo, p: &Layout) -> Result<(), VirtualDiskError> {
    layout::validate(p)?;
    let writes = gpt::encode(p)?;
    // Windows otherwise allocates real storage for the logical image length.
    // Refuse filesystems that cannot enable sparse files before extending.
    image.make_sparse()?;
    image.set_len(p.size_bytes)?;
    for (offset, data) in writes {
        if offset > p.size_bytes || data.len() as u64 > p.size_bytes - offset {
            return Err(invalid("write exceeds image bounds"));
        }
        image.seek(SeekFrom::Start(offset))?;
        image.write_all(&data)?;
    }
    image.sync_all()?;
    gpt::verify_reader(image, p.size_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FaultFile {
        file: File,
        failure: &'static str,
    }
    impl Read for FaultFile {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            if self.failure == "read" {
                Err(io::Error::other("injected read"))
            } else {
                self.file.read(b)
            }
        }
    }
    impl Write for FaultFile {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            match self.failure {
                "write" => Err(io::Error::other("injected write")),
                "short" => Ok(0),
                _ => self.file.write(b),
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }
    impl Seek for FaultFile {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            if self.failure == "seek" {
                Err(io::Error::other("injected seek"))
            } else {
                self.file.seek(pos)
            }
        }
    }
    impl ImageIo for FaultFile {
        fn make_sparse(&mut self) -> io::Result<()> {
            if self.failure == "sparse" {
                Err(io::Error::other("injected sparse setup"))
            } else {
                self.file.make_sparse()
            }
        }
        fn set_len(&mut self, len: u64) -> io::Result<()> {
            if self.failure == "truncate" {
                Err(io::Error::other("injected truncate"))
            } else {
                self.file.set_len(len)
            }
        }
        fn sync_all(&mut self) -> io::Result<()> {
            if self.failure == "sync" {
                Err(io::Error::other("injected sync"))
            } else {
                self.file.sync_all()
            }
        }
    }

    #[test]
    fn io_failures_never_report_success() {
        let p = layout::plan(256 << 20, 512, false).unwrap();
        for failure in [
            "sparse", "truncate", "seek", "write", "short", "sync", "read",
        ] {
            let mut f = FaultFile {
                file: tempfile::tempfile().unwrap(),
                failure,
            };
            let error = populate(&mut f, &p).unwrap_err();
            if failure == "sparse" {
                assert_eq!(f.file.metadata().unwrap().len(), 0);
            }
            match error {
                VirtualDiskError::Io(e) => assert_eq!(
                    e.kind(),
                    if failure == "short" {
                        io::ErrorKind::WriteZero
                    } else {
                        io::ErrorKind::Other
                    }
                ),
                other => panic!("{failure}: {other}"),
            }
        }
    }

    #[test]
    fn invalid_plan_cannot_truncate_a_file() {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(b"preserve me").unwrap();
        let mut p = layout::plan(256 << 20, 512, false).unwrap();
        p.partitions[0].end_lba += 1;
        assert!(populate(&mut f, &p).is_err());
        f.rewind().unwrap();
        let mut text = String::new();
        f.read_to_string(&mut text).unwrap();
        assert_eq!(text, "preserve me");
    }

    #[test]
    fn replacement_at_same_path_is_not_original_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image");
        let original = File::create(&path).unwrap();
        let identity = Handle::from_file(original).unwrap();
        fs::rename(&path, dir.path().join("original")).unwrap();
        File::create(&path).unwrap();
        assert!(check_identity(&path, &identity, 0).is_err());
    }
}
