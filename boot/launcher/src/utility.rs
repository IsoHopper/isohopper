// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 S33G

use core::mem::MaybeUninit;
use uefi::{
    Status, cstr16,
    proto::device_path::{DevicePath, build},
};

const UTILITY_PATH: &uefi::CStr16 = cstr16!("\\IHUTIL.EFI");

fn utility_path<'a>(
    device: &DevicePath,
    buffer: &'a mut [MaybeUninit<u8>],
) -> Result<&'a DevicePath, Status> {
    if device.instance_iter().count() != 1 || device.node_iter().next().is_none() {
        return Err(Status::UNSUPPORTED);
    }
    let mut builder = build::DevicePathBuilder::with_buf(buffer);
    for node in device.node_iter() {
        builder = builder.push(&node).map_err(|_| Status::BAD_BUFFER_SIZE)?;
    }
    builder
        .push(&build::media::FilePath {
            path_name: UTILITY_PATH,
        })
        .and_then(|builder| builder.finalize())
        .map_err(|_| Status::BAD_BUFFER_SIZE)
}

fn complete_load<T>(status: Status, image: Option<T>, unload: impl FnOnce(T)) -> Result<T, Status> {
    if status == Status::SUCCESS {
        return image.ok_or(Status::LOAD_ERROR);
    }
    // LoadImage may leave an allocated, forbidden image on this error.
    if status == Status::SECURITY_VIOLATION
        && let Some(image) = image
    {
        unload(image);
    }
    Err(status)
}

#[cfg(target_os = "uefi")]
mod firmware {
    use super::*;
    use uefi::{
        Handle, boot,
        proto::{
            loaded_image::LoadedImage,
            media::{
                file::{File, FileAttribute, FileMode},
                fs::SimpleFileSystem,
            },
        },
    };

    fn file_system_handle() -> Result<Handle, Status> {
        let loaded = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
            .map_err(|error| error.status())?;
        let device = loaded.device().ok_or(Status::UNSUPPORTED)?;
        let path =
            boot::open_protocol_exclusive::<DevicePath>(device).map_err(|error| error.status())?;
        boot::locate_device_path::<SimpleFileSystem>(&mut &*path).map_err(|error| error.status())
    }

    fn file_present(handle: Handle) -> Result<bool, Status> {
        let mut fs = boot::open_protocol_exclusive::<SimpleFileSystem>(handle)
            .map_err(|error| error.status())?;
        let mut root = fs.open_volume().map_err(|error| error.status())?;
        let file = match root.open(UTILITY_PATH, FileMode::Read, FileAttribute::empty()) {
            Ok(file) => file,
            Err(error) if error.status() == Status::NOT_FOUND => return Ok(false),
            Err(error) => return Err(error.status()),
        };
        file.is_regular_file().map_err(|error| error.status())
    }

    pub fn available() -> Result<bool, Status> {
        file_present(file_system_handle()?)
    }

    pub fn load() -> Result<Handle, Status> {
        let fs = file_system_handle()?;
        if !file_present(fs)? {
            return Err(Status::NOT_FOUND);
        }
        let mut buffer = [MaybeUninit::uninit(); 4096];
        let path = {
            let device_path =
                boot::open_protocol_exclusive::<DevicePath>(fs).map_err(|error| error.status())?;
            utility_path(&device_path, &mut buffer)?
        };
        // All file/protocol guards are closed before the firmware loads the image.
        load_from_device_path(path)
    }

    fn load_from_device_path(path: &DevicePath) -> Result<Handle, Status> {
        let system = uefi::table::system_table_raw().ok_or(Status::UNSUPPORTED)?;
        // SAFETY: the UEFI entry point installed this table. This launcher has
        // not exited boot services, and no borrowed table data crosses StartImage.
        let services =
            unsafe { system.as_ref().boot_services.as_ref() }.ok_or(Status::UNSUPPORTED)?;
        let mut raw_image = core::ptr::null_mut();
        // SAFETY: path is a complete, live device path; parent is this image;
        // output storage is valid. FALSE is BootPolicy::ExactMatch. A NULL source
        // buffer forces firmware filesystem loading and its normal security policy.
        // The raw call is needed because uefi 0.41's safe wrapper discards the
        // output handle on SECURITY_VIOLATION, preventing required cleanup.
        let status = unsafe {
            (services.load_image)(
                false.into(),
                boot::image_handle().as_ptr(),
                path.as_ffi_ptr().cast(),
                core::ptr::null(),
                0,
                &mut raw_image,
            )
        };
        let image = if status == Status::SUCCESS || status == Status::SECURITY_VIOLATION {
            // SAFETY: only these statuses define the returned image handle.
            unsafe { Handle::from_ptr(raw_image) }
        } else {
            None
        };
        complete_load(status, image, unload_remaining)
    }

    pub fn unload_remaining(image: Handle) {
        // Applications are automatically unloaded on return. A rejected start
        // can leave the handle live; check before unloading that remaining image.
        if boot::open_protocol_exclusive::<LoadedImage>(image).is_ok() {
            if let Err(error) = boot::unload_image(image) {
                uefi::println!("Cannot unload utility: {:?}", error.status());
            }
        }
    }
}

#[cfg(target_os = "uefi")]
pub use firmware::{available, load, unload_remaining};

#[cfg(test)]
mod tests {
    use super::*;
    use uefi::{
        cstr16,
        proto::device_path::{build, media::FilePath},
    };

    #[test]
    fn utility_path_keeps_device_and_appends_only_fixed_filename() {
        let mut source = [MaybeUninit::uninit(); 128];
        let device = build::DevicePathBuilder::with_buf(&mut source)
            .push(&build::hardware::Pci {
                function: 0,
                device: 7,
            })
            .unwrap()
            .finalize()
            .unwrap();
        let mut output = [MaybeUninit::uninit(); 128];
        let path = utility_path(device, &mut output).unwrap();
        let mut nodes = path.node_iter();
        let pci: &uefi::proto::device_path::hardware::Pci =
            nodes.next().unwrap().try_into().unwrap();
        assert_eq!(pci.device(), 7);
        assert_eq!(pci.function(), 0);
        let file: &FilePath = nodes.next().unwrap().try_into().unwrap();
        assert_eq!(
            file.path_name().iter().collect::<std::vec::Vec<_>>(),
            cstr16!("\\IHUTIL.EFI").to_u16_slice_with_nul()
        );
        assert!(nodes.next().is_none());
    }

    #[test]
    fn path_buffer_limit_and_ambiguous_devices_are_rejected() {
        let mut source = [MaybeUninit::uninit(); 128];
        let device = build::DevicePathBuilder::with_buf(&mut source)
            .push(&build::hardware::Pci {
                function: 0,
                device: 7,
            })
            .unwrap()
            .finalize()
            .unwrap();
        let mut too_small = [MaybeUninit::uninit(); 8];
        assert_eq!(
            utility_path(device, &mut too_small).unwrap_err(),
            Status::BAD_BUFFER_SIZE
        );
        let mut source = [MaybeUninit::uninit(); 128];
        let ambiguous = build::DevicePathBuilder::with_buf(&mut source)
            .push(&build::hardware::Pci {
                function: 0,
                device: 7,
            })
            .unwrap()
            .push(&build::end::Instance)
            .unwrap()
            .push(&build::hardware::Pci {
                function: 0,
                device: 8,
            })
            .unwrap()
            .finalize()
            .unwrap();
        let mut output = [MaybeUninit::uninit(); 128];
        assert_eq!(
            utility_path(ambiguous, &mut output).unwrap_err(),
            Status::UNSUPPORTED
        );
    }

    #[test]
    fn security_rejection_unloads_and_never_returns_image() {
        let mut unloaded = None;
        assert_eq!(
            complete_load(Status::SECURITY_VIOLATION, Some(7), |h| unloaded = Some(h)),
            Err(Status::SECURITY_VIOLATION)
        );
        assert_eq!(unloaded, Some(7));
    }

    #[test]
    fn only_success_with_a_handle_can_run() {
        assert_eq!(
            complete_load(Status::SUCCESS, Some(7), |_| panic!(
                "unloaded accepted image"
            )),
            Ok(7)
        );
        assert_eq!(
            complete_load::<usize>(Status::SUCCESS, None, |_| panic!("invalid handle")),
            Err(Status::LOAD_ERROR)
        );
        for status in [
            Status::ACCESS_DENIED,
            Status::LOAD_ERROR,
            Status::WARN_UNKNOWN_GLYPH,
        ] {
            assert_eq!(
                complete_load::<usize>(status, None, |_| panic!("invalid handle")),
                Err(status)
            );
        }
    }
}
