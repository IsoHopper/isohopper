// SPDX-License-Identifier: GPL-3.0-or-later
//! Native staging proof on one newly created disposable VHD, never caller disks.
#[path = "support/lock_image.rs"]
#[allow(dead_code)]
mod lock_image;
#[cfg(windows)]
#[path = "support/windows_vhd.rs"]
#[allow(dead_code)]
mod vhd_support;
#[path = "support/windows_volume.rs"]
#[allow(dead_code)]
mod volume_support;

fn format_completed(output: &[u8]) -> std::io::Result<()> {
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reply {
        return_code: u32,
    }
    if output.len() > 4096 {
        return Err(std::io::Error::other("oversized format reply"));
    }
    let reply: Reply = serde_json::from_slice(output)?;
    if reply.return_code != 0 {
        return Err(std::io::Error::other(format!(
            "MSFT_Volume.Format returned {}",
            reply.return_code
        )));
    }
    Ok(())
}

#[test]
fn format_result_requires_exact_success_and_bounded_typed_output() {
    assert!(format_completed(br#"{"return_code":0}"#).is_ok());
    for output in [
        r#"{"return_code":3}"#,
        r#"{"return_code":43006}"#,
        r#"{"return_code":4096}"#,
        r#"{"return_code":"0"}"#,
        r#"{"return_code":false}"#,
        r#"{"return_code":-1}"#,
        r#"{"return_code":4294967296}"#,
        r#"{}"#,
        r#"{"return_code":0,"extra":true}"#,
        r#"{"return_code":0,"return_code":0}"#,
    ] {
        assert!(format_completed(output.as_bytes()).is_err(), "{output}");
    }
    assert!(format_completed(&vec![b' '; 4097]).is_err());
}

#[test]
fn data_volume_selection_rejects_other_ranges_and_duplicate_extents() {
    let plan = isohopper_core::layout::plan(lock_image::CAPACITY, 512, false).unwrap();
    let ranges: Vec<_> = plan
        .partitions
        .iter()
        .map(|p| (p.start_lba * 512, (p.end_lba - p.start_lba + 1) * 512))
        .collect();
    assert!(!volume_support::has_exact_data_range(&plan, &[]).unwrap());
    assert!(!volume_support::has_exact_data_range(&plan, &ranges[1..]).unwrap());
    assert!(volume_support::has_exact_data_range(&plan, &ranges[..1]).unwrap());
    assert!(volume_support::has_exact_data_range(&plan, &ranges).unwrap());
    assert!(volume_support::has_exact_data_range(&plan, &[ranges[0], ranges[0]]).is_err());
    assert!(
        volume_support::has_exact_data_range(&plan, &[(ranges[0].0 + 512, ranges[0].1)]).is_err()
    );
    assert!(
        volume_support::has_exact_data_range(&plan, &[(ranges[0].0, ranges[0].1 - 512)]).is_err()
    );
    let mut invalid = plan;
    invalid.partitions[0].start_lba += 1;
    assert!(volume_support::has_exact_data_range(&invalid, &ranges).is_err());
}

#[cfg(windows)]
#[test]
#[ignore = "formats only its own new 256 MiB VHDX as exFAT; requires Windows administrator storage privileges; never requests elevation"]
fn windows_exfat_staging_preserves_nested_files_after_reattachment()
-> Result<(), Box<dyn std::error::Error>> {
    native::run()
}

#[cfg(windows)]
mod native {
    use super::{format_completed, lock_image, vhd_support, volume_support};
    use cap_std::fs::Dir;
    use isohopper_core::{layout, virtualdisk};
    use isohopper_helper::writer::{RetainedDevice, write_image};
    use isohopper_media::copy::{CopyEntry, Phase, copy_one, validate_manifest};
    use sha2::{Digest, Sha256};
    use std::{
        ffi::OsString,
        fs::{File, OpenOptions},
        io::{self, Read, Write},
        os::windows::{ffi::OsStringExt, fs::OpenOptionsExt, process::CommandExt},
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::atomic::AtomicBool,
        thread,
        time::{Duration, Instant},
    };
    use volume_support::{Volume, volume_extents, wait_for_data_volume};
    use windows_sys::Win32::{
        Storage::FileSystem::{FILE_SHARE_READ, FILE_SHARE_WRITE},
        System::SystemInformation::GetSystemDirectoryW,
    };

    // Documented, synchronous local provider operation. No caller text forms
    // executable PowerShell. Only this test's canonical GUID and exact owned
    // extent enter through JSON stdin. No Force, disk initialization, drive
    // letter assignment, format retry or production command is exposed.
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/format-msft-volume
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/storage/msft-partitiontovolume
    const FORMAT_SCRIPT: &str = r#"
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$stage = 1
try {
    Import-Module (Join-Path $PSHOME 'Modules\CimCmdlets\CimCmdlets.psd1') -ErrorAction Stop
    $inputText = [Console]::In.ReadToEnd()
    if ($inputText.Length -gt 1024) { throw 'request bound' }
    $request = Microsoft.PowerShell.Utility\ConvertFrom-Json -InputObject $inputText
    if ($request.volume_guid -isnot [string] -or $request.volume_guid.Length -ne 49) { throw 'GUID shape' }
    $guid = [guid]::ParseExact($request.volume_guid.Substring(11, 36), 'D')
    if ($request.volume_guid -cne ('\\?\Volume{' + $guid.ToString('D') + '}\')) { throw 'GUID canonical form' }
    if (($request.disk_number -isnot [int] -and $request.disk_number -isnot [long]) -or $request.disk_number -lt 0 -or $request.disk_number -gt [uint32]::MaxValue -or
        ($request.start -isnot [int] -and $request.start -isnot [long]) -or $request.start -ne 1048576 -or
        ($request.length -isnot [int] -and $request.length -isnot [long]) -or $request.length -le 0 -or
        $request.length -gt 268435456 -or ($request.length % 512) -ne 0) { throw 'extent bounds' }
    $stage = 2
    $count = 0
    $matched = [System.Collections.Generic.List[object]]::new()
    CimCmdlets\Get-CimInstance -Namespace 'Root/Microsoft/Windows/Storage' -ClassName MSFT_Volume | Microsoft.PowerShell.Core\ForEach-Object {
        $count++
        if ($count -gt 1024) { throw 'volume count' }
        if ($_.Path -ieq $request.volume_guid) { $matched.Add($_) }
    }
    if ($matched.Count -ne 1) { throw 'volume match' }
    $volume = $matched[0]
    $stage = 3
    $partitions = [System.Collections.Generic.List[object]]::new()
    CimCmdlets\Get-CimAssociatedInstance -InputObject $volume -Association MSFT_PartitionToVolume -ResultClassName MSFT_Partition | Microsoft.PowerShell.Core\ForEach-Object {
        if ($partitions.Count -ge 2) { throw 'partition count bound' }
        $partitions.Add($_)
    }
    if ($partitions.Count -ne 1) { throw 'partition count' }
    $partition = $partitions[0]
    if ($partition.DiskNumber -isnot [uint32] -or $partition.DiskNumber -ne $request.disk_number -or
        $partition.PartitionNumber -isnot [uint32] -or $partition.PartitionNumber -ne 1 -or
        $partition.Offset -isnot [uint64] -or $partition.Offset -ne $request.start -or
        $partition.Size -isnot [uint64] -or $partition.Size -ne $request.length -or
        $partition.IsSystem -isnot [bool] -or $partition.IsSystem -ne $false -or
        $partition.IsBoot -isnot [bool] -or $partition.IsBoot -ne $false -or
        [guid]$partition.GptType -ne [guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' -or
        ($null -ne $partition.DriveLetter -and [int][char]$partition.DriveLetter -ne 0)) { throw 'partition binding' }
    if (-not [string]::IsNullOrEmpty($volume.FileSystem) -and $volume.FileSystem -ine 'RAW') { throw 'volume already formatted' }
    $stage = 4
    $result = CimCmdlets\Invoke-CimMethod -InputObject $volume -MethodName Format -Arguments @{
        FileSystem = 'ExFAT'; FileSystemLabel = 'IH-TEST'; AllocationUnitSize = [uint32]4096;
        Full = $false; Force = $false
    }
    if ($null -eq $result -or $result.ReturnValue -isnot [uint32]) { throw 'method return code' }
    [Console]::Out.Write((Microsoft.PowerShell.Utility\ConvertTo-Json -Compress -InputObject @{ return_code = $result.ReturnValue }))
} catch {
    [Console]::Error.WriteLine(('owned VHD format failed: stage=' + $stage + '; hresult=' + $_.Exception.HResult))
    exit 1
}
"#;

    // The inventory resolver is deliberately private to its read-only command
    // allowlist. This test uses the same trusted system-directory rule without
    // making a formatting command available through that runtime API.
    fn powershell() -> io::Result<PathBuf> {
        let mut output = [0u16; 32768];
        // SAFETY: fixed live writable buffer with its exact character count.
        let count = unsafe { GetSystemDirectoryW(output.as_mut_ptr(), output.len() as u32) };
        if count == 0 {
            return Err(io::Error::last_os_error());
        }
        if count as usize >= output.len() {
            return Err(io::Error::other("system directory bound"));
        }
        let path = PathBuf::from(OsString::from_wide(&output[..count as usize]));
        if !path.is_absolute() {
            return Err(io::Error::other("system directory is not absolute"));
        }
        Ok(path.join(r"WindowsPowerShell\v1.0\powershell.exe"))
    }

    struct FinishChild(Child);
    impl Drop for FinishChild {
        fn drop(&mut self) {
            // A timeout/pipe error is not cancellation of provider mutation.
            // Wait before the outer VHD owner can detach, including on panic.
            let _ = self.0.wait();
        }
    }

    fn drain(mut input: impl Read) -> io::Result<Vec<u8>> {
        let mut saved = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                return Ok(saved);
            }
            let keep = count.min(4097usize.saturating_sub(saved.len()));
            saved.extend_from_slice(&buffer[..keep]);
            // Continue draining excess output so pipe backpressure cannot
            // leave the provider blocked while cleanup tries to detach it.
        }
    }

    fn format_owned_data(vhd: &vhd_support::TemporaryVhd, volume: &Volume) -> io::Result<()> {
        let (_, number) = vhd.physical_path()?;
        volume_support::verify_no_mount_paths(volume)?;
        assert_eq!(
            volume_extents(&volume.name)?,
            [(number, volume.start, volume.length)]
        );
        let request = serde_json::to_vec(&serde_json::json!({
            "volume_guid": volume.name, "disk_number": number,
            "start": volume.start, "length": volume.length,
        }))?;
        let program = powershell()?;
        let directory = program.parent().expect("absolute system PowerShell");
        let mut child = FinishChild(
            Command::new(&program)
                .args([
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    FORMAT_SCRIPT,
                ])
                .env("PSModulePath", directory.join("Modules"))
                .current_dir(directory)
                .creation_flags(0x0800_0000) // CREATE_NO_WINDOW; no elevation.
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        let output = child.0.stdout.take().expect("piped stdout");
        let errors = child.0.stderr.take().expect("piped stderr");
        let output = thread::spawn(move || drain(output));
        let errors = thread::spawn(move || drain(errors));
        child
            .0
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(&request)?;
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut overdue = false;
        let status = loop {
            if let Some(status) = child.0.try_wait()? {
                break status;
            }
            if !overdue && Instant::now() >= deadline {
                overdue = true;
                eprintln!(
                    "Owned VHD format exceeded 60 seconds; retaining attachment until provider process exits"
                );
            }
            thread::sleep(Duration::from_millis(25));
        };
        let output = output
            .join()
            .map_err(|_| io::Error::other("format stdout reader"))??;
        let errors = errors
            .join()
            .map_err(|_| io::Error::other("format stderr reader"))??;
        // The borrowed, attached owner has stayed alive through process exit.
        let (_, current_number) = vhd.physical_path()?;
        assert_eq!(current_number, number);
        assert_eq!(
            volume_extents(&volume.name)?,
            [(number, volume.start, volume.length)]
        );
        if overdue {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned VHD format exceeded 60 seconds; child has now exited",
            ));
        }
        if output.len() > 4096 || errors.len() > 4096 {
            return Err(io::Error::other("format output exceeded bound"));
        }
        if !status.success() || !errors.is_empty() {
            return Err(io::Error::other(format!(
                "owned VHD format child failed: {}",
                String::from_utf8_lossy(&errors)
            )));
        }
        format_completed(&output)
    }

    fn verify_files(root: &Dir, entries: &[CopyEntry]) -> io::Result<()> {
        for entry in entries {
            let mut file = root.open(&entry.relative_path)?;
            assert_eq!(file.metadata()?.len(), entry.bytes);
            let mut hash = Sha256::new();
            let mut remaining = entry.bytes;
            let mut buffer = [0u8; 65536];
            while remaining != 0 {
                let count = remaining.min(buffer.len() as u64) as usize;
                file.read_exact(&mut buffer[..count])?;
                hash.update(&buffer[..count]);
                remaining -= count as u64;
            }
            assert_eq!(file.read(&mut [0])?, 0);
            assert_eq!(<[u8; 32]>::from(hash.finalize()), entry.sha256);
        }
        Ok(())
    }

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        let _privilege = vhd_support::ManageVolumePrivilege::enable()?;
        let directory = tempfile::tempdir()?;
        let image_path = directory.path().join("seed.img");
        let plan = layout::plan(vhd_support::CAPACITY, 512, false)?;
        virtualdisk::create_bootable(&image_path, &plan, &lock_image::payload())?;
        let mut image = File::open(&image_path)?;
        let digest = vhd_support::hash_exact(&mut image)?;
        let mut vhd = vhd_support::TemporaryVhd::create(directory.path().join("exfat-stage.vhdx"))?;
        vhd.attach(false)?;
        let mut device = vhd.open_raw_device()?;
        let seed_snapshot = device.initial_snapshot().clone();
        assert!(seed_snapshot.device_id.is_some());
        // The only raw write is seeding this newly created blank VHD. Once
        // filesystems exist, this test writes through the bound data filesystem.
        let seeded = write_image(
            &mut device,
            &mut image,
            &seed_snapshot,
            digest,
            &AtomicBool::new(false),
            |_| {},
        )?;
        assert_eq!(seeded.bytes_verified, vhd_support::CAPACITY);
        drop(device);
        vhd.detach()?;
        vhd.attach(false)?;
        let mut device = vhd.open_raw_device()?;
        let expected = device.initial_snapshot().clone();
        assert_eq!(expected.device_id, seed_snapshot.device_id);
        let volume = wait_for_data_volume(expected.device_number, &plan)?;
        assert_eq!(device.snapshot()?, expected);
        format_owned_data(&vhd, &volume)?;
        assert_eq!(device.snapshot()?, expected);
        volume_support::verify_filesystem_kind(&volume, "exFAT")?;

        let names = [
            "Windows/boot.iso",
            "Mac/boot.iso",
            "Linux live/tools/日本語.img",
        ];
        let sizes = [2 * 1024 * 1024 + 37, 1024 * 1024 + 73, 192 * 1024 + 19];
        let mut entries = Vec::new();
        let mut sources = Vec::new();
        for (index, (name, size)) in names.into_iter().zip(sizes).enumerate() {
            let bytes: Vec<_> = (0..size)
                .map(|offset| ((offset + index * 13) % 251) as u8)
                .collect();
            let path = directory.path().join(format!("source-{index}"));
            let mut source = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(path)?;
            source.write_all(&bytes)?;
            source.sync_all()?;
            entries.push(CopyEntry {
                relative_path: name.into(),
                bytes: size as u64,
                sha256: Sha256::digest(&bytes).into(),
            });
            sources.push(source);
        }
        validate_manifest(&entries, volume.length / 2, 4096)?;
        let root = Dir::open_ambient_dir(&volume.name, cap_std::ambient_authority())?;
        for (entry, source) in entries.iter().zip(&mut sources) {
            let mut final_phase = None;
            let report = copy_one(&root, source, entry, &AtomicBool::new(false), |progress| {
                assert!(progress.completed_bytes <= entry.bytes);
                final_phase = Some(progress.phase);
            })?;
            assert_eq!(final_phase, Some(Phase::Complete));
            assert_eq!(report.bytes_written, entry.bytes);
            assert_eq!(report.bytes_verified, entry.bytes);
            assert_eq!(report.sha256, entry.sha256);
        }
        assert!(
            copy_one(
                &root,
                &mut sources[0],
                &entries[0],
                &AtomicBool::new(false),
                |_| {}
            )
            .is_err()
        );
        verify_files(&root, &entries)?;
        assert_eq!(
            volume_extents(&volume.name)?,
            [(expected.device_number, volume.start, volume.length)]
        );
        assert_eq!(device.snapshot()?, expected);
        drop(root);
        drop(device);
        vhd.detach()?;

        // Same retained VHD owner, fresh read-only attachment and fresh volume
        // enumeration. No drive letters, old volume handle or cache-only check.
        vhd.attach(true)?;
        let (physical_path, number) = vhd.physical_path()?;
        let volume = wait_for_data_volume(number, &plan)?;
        assert_eq!(
            volume_extents(&volume.name)?,
            [(number, volume.start, volume.length)]
        );
        volume_support::verify_filesystem_kind(&volume, "exFAT")?;
        let root = Dir::open_ambient_dir(&volume.name, cap_std::ambient_authority())?;
        verify_files(&root, &entries)?;
        drop(root);
        let mut raw = OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE)
            .open(physical_path)?;
        vhd_support::assert_readback_binding(&raw, number)?;
        let persisted_path = directory.path().join("persisted.img");
        let mut persisted = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&persisted_path)?;
        assert_eq!(
            io::copy(
                &mut Read::by_ref(&mut raw).take(vhd_support::CAPACITY),
                &mut persisted
            )?,
            vhd_support::CAPACITY
        );
        persisted.sync_all()?;
        drop(persisted);
        drop(raw);
        vhd.detach()?;
        // Confirms both GPT copies and the two complete FAT boot slots were
        // preserved while formatting and populating only the data partition.
        virtualdisk::verify_bootable(&persisted_path, &lock_image::payload())?;
        println!(
            "Owned VHD exFAT staging: 3 nested files copied and SHA-256 verified after read-only reattachment; GPT and both FAT boot slots preserved; no physical disk or OS boot tested"
        );
        Ok(())
    }
}
