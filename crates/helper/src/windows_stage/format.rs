// SPDX-License-Identifier: GPL-3.0-or-later
//! Private synchronous provider call. Caller retains its owned VHD throughout.
use super::{
    StageError,
    build_policy::{SelectedVolume, format_outcome},
};
use std::{
    ffi::OsString,
    io::{self, Read, Write},
    os::windows::{ffi::OsStringExt, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;
fn err(stage: &'static str, e: impl std::fmt::Display) -> StageError {
    StageError::Io {
        operation: stage,
        source: io::Error::other(e.to_string()),
    }
}
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
        $request.length -gt 70368744177664 -or ($request.length % 512) -ne 0) { throw 'extent bounds' }
    if ($request.allocation_unit -notin @(32768,131072)) { throw 'allocation unit' }
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
        [guid]$partition.Guid -ne [guid]::ParseExact($request.partition_guid, 'D') -or
        [guid]$partition.GptType -ne [guid]'ebd0a0a2-b9e5-4433-87c0-68b6b72699c7' -or
        ($null -ne $partition.DriveLetter -and [int][char]$partition.DriveLetter -ne 0)) { throw 'partition binding' }
    if (-not [string]::IsNullOrEmpty($volume.FileSystem) -and $volume.FileSystem -ine 'RAW') { throw 'volume already formatted' }
    $stage = 4
    $result = CimCmdlets\Invoke-CimMethod -InputObject $volume -MethodName Format -Arguments @{
        FileSystem = 'ExFAT'; FileSystemLabel = 'IsoHopper'; AllocationUnitSize = [uint32]$request.allocation_unit;
        Full = $false; Force = $false
    }
    if ($null -eq $result -or $result.ReturnValue -isnot [uint32]) { throw 'method return code' }
    [Console]::Out.Write((Microsoft.PowerShell.Utility\ConvertTo-Json -Compress -InputObject @{ return_code = $result.ReturnValue }))
} catch {
    [Console]::Error.WriteLine(('owned VHD format failed: stage=' + $stage + '; hresult=' + $_.Exception.HResult))
    exit 1
}
"#;
struct FinishChild {
    child: Child,
    output: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
    errors: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
}
impl FinishChild {
    fn collect(&mut self) -> Result<(Vec<u8>, Vec<u8>), StageError> {
        // Join both before propagating either failure. Each drain owns only its
        // pipe, but neither thread may escape the owned staging operation.
        let output = self.output.take().map(thread::JoinHandle::join);
        let errors = self.errors.take().map(thread::JoinHandle::join);
        let output = output
            .ok_or(StageError::Invalid("formatter stdout worker missing"))?
            .map_err(|_| StageError::Invalid("formatter output worker"))?
            .map_err(|e| err("formatter stdout", e))?;
        let errors = errors
            .ok_or(StageError::Invalid("formatter stderr worker missing"))?
            .map_err(|_| StageError::Invalid("formatter error worker"))?
            .map_err(|e| err("formatter stderr", e))?;
        Ok((output, errors))
    }
}
impl Drop for FinishChild {
    fn drop(&mut self) {
        // A failed request must still deliver EOF before waiting. Never kill
        // the formatter or release its VHD while it or its drain workers run.
        drop(self.child.stdin.take());
        let _ = self.child.wait();
        let _ = self.collect();
    }
}
fn drain(mut input: impl Read) -> io::Result<Vec<u8>> {
    let mut saved = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            return Ok(saved);
        }
        let keep = n.min(4097usize.saturating_sub(saved.len()));
        saved.extend_from_slice(&buffer[..keep]);
    }
}
fn powershell() -> Result<PathBuf, StageError> {
    let mut buffer = [0u16; 32768];
    // SAFETY: fixed writable UTF16 output buffer and exact character count.
    let n = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
    if n == 0 || n >= buffer.len() {
        return Err(err("system PowerShell path", io::Error::last_os_error()));
    }
    let root = PathBuf::from(OsString::from_wide(&buffer[..n]));
    if !root.is_absolute() {
        return Err(StageError::Invalid("system directory is not absolute"));
    }
    Ok(root.join(r"WindowsPowerShell\v1.0\powershell.exe"))
}
pub(super) fn format_owned(v: &SelectedVolume) -> Result<(), StageError> {
    let request=serde_json::to_vec(&serde_json::json!({"volume_guid":v.guid,"disk_number":v.disk_number,"start":v.start,"length":v.length,"partition_guid":v.partition_guid,"allocation_unit":v.allocation_unit})).map_err(|e|err("format request",e))?;
    if request.len() > 1024 {
        return Err(StageError::Invalid("format request exceeds bound"));
    }
    let program = powershell()?;
    let directory = program
        .parent()
        .ok_or(StageError::Invalid("PowerShell parent"))?;
    let mut child = FinishChild {
        child: Command::new(&program)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                FORMAT_SCRIPT,
            ])
            .env("PSModulePath", directory.join("Modules"))
            .current_dir(directory)
            .creation_flags(0x08000000)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| err("start owned-volume formatter", e))?,
        output: None,
        errors: None,
    };
    let output = child
        .child
        .stdout
        .take()
        .ok_or(StageError::Invalid("formatter stdout"))?;
    let errors = child
        .child
        .stderr
        .take()
        .ok_or(StageError::Invalid("formatter stderr"))?;
    child.output = Some(thread::spawn(move || drain(output)));
    child.errors = Some(thread::spawn(move || drain(errors)));
    child
        .child
        .stdin
        .take()
        .ok_or(StageError::Invalid("formatter stdin"))?
        .write_all(&request)
        .map_err(|e| err("formatter request", e))?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut overdue = false;
    let status = loop {
        if let Some(s) = child
            .child
            .try_wait()
            .map_err(|e| err("wait formatter", e))?
        {
            break s;
        }
        overdue |= Instant::now() >= deadline;
        thread::sleep(Duration::from_millis(25));
    };
    let (output, errors) = child.collect()?;
    format_outcome(status.code(), overdue, &output, &errors)
}
