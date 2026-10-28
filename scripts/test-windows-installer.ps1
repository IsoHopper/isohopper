# SPDX-License-Identifier: GPL-3.0-or-later
# Executes real installers only on an explicitly disposable GitHub Windows runner.
param([Parameter(Mandatory = $true)][string]$Installer)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This integration test requires a disposable GitHub Windows runner.'
}
$installation = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'IsoHopper'
if (Test-Path -LiteralPath $installation) { throw 'Refusing a pre-existing runner installation.' }
$Installer = (Resolve-Path -LiteralPath $Installer).Path
$workspace = (Resolve-Path -LiteralPath $env:GITHUB_WORKSPACE).Path.TrimEnd('\') + '\'
if (-not $Installer.StartsWith($workspace, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'The diagnostic installer must be inside the checked-out workspace.'
}
$temporary = Join-Path $env:RUNNER_TEMP ('isohopper-installer-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
$settingsRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'org.isohopper.studio'
if (Test-Path -LiteralPath $settingsRoot) { throw 'Refusing pre-existing Studio user data.' }
New-Item -ItemType Directory -Path $settingsRoot | Out-Null
$settings = Join-Path $settingsRoot 'session.json'
$cache = Join-Path $settingsRoot 'installer-test-cache.bin'
[IO.File]::WriteAllText($settings, '{"schema_version":1,"images":[],"installer_test":"preserve these bytes"}')
[IO.File]::WriteAllBytes($cache, [byte[]](1, 9, 2, 8, 3, 7))
$sentinels = @{}
foreach ($path in @($settings, $cache)) { $sentinels[$path] = (Get-FileHash -LiteralPath $path).Hash }
# Tauri CLI 2.12.4 bundle.rs patches the first marker while packaging NSIS,
# then restores the original build file. Hash the exact packaged bytes.
$studioPath = (Resolve-Path -LiteralPath 'studio/src-tauri/target/debug/isohopper-studio.exe').Path
$studioBytes = [IO.File]::ReadAllBytes($studioPath)
$originalMarker = '__TAURI_BUNDLE_TYPE_VAR_UNK'
$packagedMarker = [Text.Encoding]::ASCII.GetBytes('__TAURI_BUNDLE_TYPE_VAR_NSS')
$markerOffset = [Text.Encoding]::Latin1.GetString($studioBytes).IndexOf($originalMarker, [StringComparison]::Ordinal)
if ($markerOffset -lt 0 -or $originalMarker.Length -ne $packagedMarker.Length) {
    throw 'Missing or incompatible Tauri bundle marker; review the pinned bundler before testing.'
}
[Array]::Copy($packagedMarker, 0, $studioBytes, $markerOffset, $packagedMarker.Length)
$expected = @{
    'isohopper-studio.exe' = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($studioBytes))
    'isohopper-helper.exe' = (Get-FileHash 'target/debug/isohopper-helper.exe').Hash
}
$expectedSizes = @{
    'isohopper-studio.exe' = $studioBytes.Length
    'isohopper-helper.exe' = (Get-Item 'target/debug/isohopper-helper.exe').Length
}
$studioBytes = $null
$registry = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\IsoHopper'
$skipCleanup = $false
$installerInvocation = 0

function Invoke-Installer([string]$Path, [string]$Mode, [int]$ExpectedExit = 0) {
    $script:installerInvocation++
    $label = "#$script:installerInvocation $([IO.Path]::GetFileName($Path)) $Mode"
    $script:lastInstaller = $label
    $stderrPath = Join-Path $temporary ("installer-$script:installerInvocation.stderr.txt")
    Write-Output "Running installer $label; expected exit $ExpectedExit."
    # The parent owns this output file. Elevated setup only receives an inherited
    # standard handle; it never opens a caller-supplied diagnostic file path.
    $process = Start-Process -FilePath $Path -ArgumentList $Mode -RedirectStandardError $stderrPath -PassThru
    if (-not $process.WaitForExit(180000)) {
        $script:skipCleanup = $true
        $process.Kill($true)
        throw "Installer timed out: $label; defer cleanup to runner disposal."
    }
    $process.WaitForExit()
    $reader = [IO.StreamReader]::new($stderrPath, [Text.Encoding]::UTF8)
    try {
        $buffer = [char[]]::new(2400)
        $count = $reader.ReadBlock($buffer, 0, $buffer.Length)
        $diagnostic = [string]::new($buffer, 0, $count)
    } finally { $reader.Dispose() }
    if ($diagnostic) { Write-Output "Installer $label stderr: $diagnostic" }
    if ($process.ExitCode -ne $ExpectedExit) {
        throw "Installer $label returned $($process.ExitCode); expected $ExpectedExit. $diagnostic"
    }
}

function Assert-Settings {
    foreach ($path in $sentinels.Keys) {
        if ((Get-FileHash -LiteralPath $path).Hash -ne $sentinels[$path]) { throw 'Installer modified saved user data.' }
    }
}

function Assert-Installed {
    foreach ($name in $expected.Keys) {
        $path = Join-Path $installation $name
        $hash = (Get-FileHash -LiteralPath $path).Hash
        $size = (Get-Item -LiteralPath $path).Length
        if ($hash -ne $expected[$name] -or $size -ne $expectedSizes[$name]) {
            throw "Installed executable mismatch after $script:lastInstaller`: $name; SHA256=$hash expected=$($expected[$name]); bytes=$size expected=$($expectedSizes[$name])."
        }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $installation 'uninstall.exe') -PathType Leaf)) {
        throw 'Missing installed uninstaller.'
    }
    Assert-Settings
}

function Remove-OwnedInstallation {
    $uninstaller = Join-Path $installation 'uninstall.exe'
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw 'Cannot safely uninstall incomplete test fixture.' }
    # NSIS normally relaunches a temporary child and returns before cleanup.
    # Run our own copy with _?= last to wait for registry/shortcut cleanup too.
    $copy = Join-Path $temporary ('uninstall-' + [Guid]::NewGuid().ToString('N') + '.exe')
    Copy-Item -LiteralPath $uninstaller -Destination $copy
    Invoke-Installer $copy ("/S _?=" + $installation)
    Remove-Item -LiteralPath $copy
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while ((Test-Path -LiteralPath $installation) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 100 }
    if (Test-Path -LiteralPath $installation) { throw 'Uninstall did not remove the owned installation.' }
    Assert-Settings
}

try {
    # Fresh install first, then the actual published previous version -> new build.
    Invoke-Installer $Installer '/S'
    Assert-Installed
    Remove-OwnedInstallation
    $previous = Join-Path $temporary 'previous-setup.exe'
    Invoke-WebRequest -Uri 'https://github.com/IsoHopper/isohopper/releases/download/v0.1.0-experimental.3/IsoHopper-v0.1.0-experimental.3-windows-x64-setup.exe' -OutFile $previous
    if ((Get-Item -LiteralPath $previous).Length -ne 6233561 -or
        (Get-FileHash -LiteralPath $previous -Algorithm SHA256).Hash -ne 'ED2BA85B803F95D6DDCCEB102768600ADE43E943A615845999491A553E19C9F1') {
        throw 'Published previous installer failed its pinned size/SHA-256 check.'
    }
    Invoke-Installer $previous '/S'
    $oldHash = (Get-FileHash -LiteralPath (Join-Path $installation 'isohopper-studio.exe')).Hash
    Invoke-Installer $previous '/S' 3
    Write-Output '::notice title=Installer regression reproduced::Published experimental.3 refuses a repeated installation with exit 3.'
    Invoke-Installer $Installer '/S'
    Assert-Installed
    if ((Get-FileHash -LiteralPath (Join-Path $installation 'isohopper-studio.exe')).Hash -eq $oldHash) {
        throw 'Upgrade did not replace the previous Studio executable.'
    }
    $protection = @{}
    foreach ($name in @('isohopper-studio.exe', 'isohopper-helper.exe', 'uninstall.exe')) {
        $protection[$name] = (Get-Acl -LiteralPath (Join-Path $installation $name)).Sddl
    }
    foreach ($mode in @('/S', '/P')) {
        Invoke-Installer $Installer $mode
        Assert-Installed
        foreach ($name in $protection.Keys) {
            if ((Get-Acl -LiteralPath (Join-Path $installation $name)).Sddl -ne $protection[$name]) {
                throw "Repair changed executable protection: $name"
            }
        }
    }

    # A retained executable models an active app/helper session. No bytes change.
    foreach ($name in @('isohopper-studio.exe', 'isohopper-helper.exe', 'uninstall.exe')) {
        $held = [IO.File]::Open((Join-Path $installation $name), [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try { Invoke-Installer $Installer '/S' 10 } finally { $held.Dispose() }
        Assert-Installed
    }

    # Registry values must never become executable commands or deletion paths.
    $marker = Join-Path $temporary 'old-uninstaller-ran.txt'
    $fakeUninstaller = Join-Path $temporary 'old-uninstaller.cmd'
    [IO.File]::WriteAllText($fakeUninstaller, "@echo off`r`necho unexpected > `"$marker`"`r`nexit /b 0`r`n")
    $outside = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) ('.IsoHopper-test-' + [Guid]::NewGuid().ToString('N') + '.txt')
    [IO.File]::WriteAllText($outside, 'Do not delete through OldMainBinaryName.')
    try {
        Set-ItemProperty -LiteralPath $registry -Name 'UninstallString' -Value ('"' + $fakeUninstaller + '"')
        Set-ItemProperty -LiteralPath $registry -Name 'MainBinaryName' -Value ('..\' + [IO.Path]::GetFileName($outside))
        Set-ItemProperty -LiteralPath $registry -Name 'InstallLocation' -Value $temporary
        Set-Item -LiteralPath 'HKLM:\Software\IsoHopper\IsoHopper' -Value $temporary
        Invoke-Installer $Installer '/P'
        Assert-Installed
        if (Test-Path -LiteralPath $marker) { throw 'Installer executed an old registry-provided uninstaller.' }
        if ([IO.File]::ReadAllText($outside) -ne 'Do not delete through OldMainBinaryName.') { throw 'Installer touched an unrelated file.' }
    } finally { if (Test-Path -LiteralPath $outside) { Remove-Item -LiteralPath $outside } }

    # Recover a partial installation without running a missing/old uninstaller.
    Remove-Item -LiteralPath (Join-Path $installation 'isohopper-helper.exe')
    Remove-Item -LiteralPath (Join-Path $installation 'uninstall.exe')
    Invoke-Installer $Installer '/S'
    Assert-Installed

    # An ordinary empty directory left behind by an earlier attempt is repairable.
    Remove-OwnedInstallation
    New-Item -ItemType Directory -Path $installation | Out-Null
    Invoke-Installer $Installer '/S'
    Assert-Installed

    # Run production retained-handle, owner/ACL and embedded-hash validation.
    & cargo test --manifest-path studio/src-tauri/Cargo.toml --locked native_installed_helper_is_protected_and_matches_build -- --ignored --nocapture *> installed-check.log
    $testExit = $LASTEXITCODE
    Get-Content installed-check.log
    if ($testExit -ne 0) { throw 'Production installed-file protection check failed after upgrades.' }
    Write-Output '::notice title=Windows installer check::Fresh install, published .3 upgrade, silent/passive repair, retained executable busy refusal, registry isolation, partial/empty recovery, user-data preservation and native protected-file checks passed; no physical-device operation or interactive UAC tested.'
} finally {
    if (-not $skipCleanup) {
        if (Test-Path -LiteralPath (Join-Path $installation 'uninstall.exe') -PathType Leaf) { Remove-OwnedInstallation }
        if (Test-Path -LiteralPath $settingsRoot) { Remove-Item -LiteralPath $settingsRoot -Recurse -Force }
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
    }
}
