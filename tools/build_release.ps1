#requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('9.3', '9.4', '9.5')][string]$IdaVersion,
    [Parameter(Mandatory)][string]$IdaSdk,
    [Parameter(Mandatory)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
Set-StrictMode -Version Latest

$sdkCommits = @{
    '9.3' = 'acacbbcc8fa349d919cc185d88b1ab3710ca252d' # v9.3.1-release
    '9.4' = '2348615c25f90e357cd2cc72fcfede1ba14ad41a' # v9.4.0-release
    '9.5' = '04c0a982c80fd08388e7a3c26ff711fc1c38344d' # v9.5.0-release
}
$requiredRust = '1.93.1'
$recipeHash = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash.ToLowerInvariant()
$repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).ProviderPath
$sdk = (Resolve-Path -LiteralPath $IdaSdk).ProviderPath
$output = [IO.Path]::GetFullPath($OutputDirectory)
$suffix = $IdaVersion.Replace('.', '')
$package = Join-Path $output "ntrays-ida$suffix"
$archive = "$package-windows-x64.zip"
$buildLog = Join-Path $output "build-ida$suffix.log"

if (-not $IsWindows) { throw 'The release build requires Windows with MSVC Build Tools.' }
foreach ($path in @($package, $archive, $buildLog)) {
    if (Test-Path -LiteralPath $path) { throw "Output already exists: $path. Choose a new output directory." }
}
$rustVersion = & rustc --version
if ($LASTEXITCODE -ne 0 -or $rustVersion -notmatch "^rustc $([regex]::Escape($requiredRust)) ") {
    throw "Use Rust $requiredRust (rustup toolchain install $requiredRust --profile minimal)."
}
$sdkCommit = & git -C $sdk rev-parse HEAD
if ($LASTEXITCODE -ne 0 -or $sdkCommit -ne $sdkCommits[$IdaVersion]) {
    throw "IDA $IdaVersion requires SDK commit $($sdkCommits[$IdaVersion]); got $sdkCommit."
}
$sdkChanges = & git -C $sdk status --porcelain --untracked-files=no
if ($LASTEXITCODE -ne 0 -or $sdkChanges) { throw 'The SDK checkout has tracked changes.' }
$proHeader = Get-Content -Raw -LiteralPath (Join-Path $sdk 'include/pro.h')
$expectedSdk = [int]($IdaVersion.Replace('.', '') + '0')
if ($proHeader -notmatch "(?m)^#define IDA_SDK_VERSION\s+$expectedSdk\s*$") { throw 'SDK header version does not match the selected IDA.' }

function Get-SourceHashes {
    $files = @(Get-Item -LiteralPath (Join-Path $repo 'Cargo.toml'), (Join-Path $repo 'Cargo.lock'))
    $files += Get-ChildItem -LiteralPath (Join-Path $repo 'core'), (Join-Path $repo 'plugin'), (Join-Path $repo '.cargo') -Recurse -File
    @($files | Sort-Object FullName | ForEach-Object {
        [ordered]@{ path = $_.FullName.Substring($repo.Length + 1).Replace('\', '/'); sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
}

$sourceHashes = Get-SourceHashes
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
$vsInstall = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $vsInstall) { throw 'MSVC x64 Build Tools were not found.' }
$dumpbin = Get-ChildItem -Path (Join-Path $vsInstall 'VC/Tools/MSVC/*/bin/Hostx64/x64/dumpbin.exe') | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
if (-not $dumpbin) { throw 'dumpbin.exe was not found in MSVC Build Tools.' }

New-Item -ItemType Directory -Path $output -Force | Out-Null
$build = Join-Path $output ('.build-ida' + $suffix + '-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $build | Out-Null
$oldSdk = $env:IDASDK
$oldTarget = $env:CARGO_TARGET_DIR
Push-Location -LiteralPath $repo
try {
    $env:IDASDK = $sdk
    $env:CARGO_TARGET_DIR = $build
    & cargo build --release --locked -p ntrays --target x86_64-pc-windows-msvc 2>&1 | Tee-Object -FilePath $buildLog
    if ($LASTEXITCODE -ne 0) { throw "Build failed; see $buildLog." }
    $afterHashes = Get-SourceHashes
    if (($sourceHashes | ConvertTo-Json -Depth 3 -Compress) -ne ($afterHashes | ConvertTo-Json -Depth 3 -Compress)) {
        throw 'Source files changed during the build. Run again from a stable checkout.'
    }
    $dll = Join-Path $build 'x86_64-pc-windows-msvc/release/ntrays.dll'
    $peCheck = @(& $dumpbin /EXPORTS /DEPENDENTS $dll | ForEach-Object {
        if ($_ -match '^Dump of file ') { 'Dump of file ntrays.dll' } else { $_ }
    })
    if ($LASTEXITCODE -ne 0 -or ($peCheck -join "`n") -notmatch '\bPLUGIN\b' -or ($peCheck -join "`n") -notmatch '(?im)^\s+ida\.dll\s*$') {
        throw 'DLL is missing PLUGIN or its IDA 9 import.'
    }
    if (($peCheck -join "`n") -match '(?im)^\s+(ida64|vcruntime[^\s]*|msvcp[^\s]*)\.dll\s*$') {
        throw 'Unexpected IDA 8 or dynamic MSVC runtime dependency.'
    }
    New-Item -ItemType Directory -Path $package | Out-Null
    Copy-Item -LiteralPath $dll -Destination (Join-Path $package 'ntrays.dll')
    Copy-Item -LiteralPath (Join-Path $repo 'LICENSE') -Destination (Join-Path $package 'LICENSE')
    Copy-Item -LiteralPath (Join-Path $repo 'NOTICE') -Destination (Join-Path $package 'NOTICE')
    $notices = Join-Path $package 'licenses'
    New-Item -ItemType Directory -Path $notices | Out-Null
    Copy-Item -LiteralPath (Join-Path $sdk '../LICENSE') -Destination (Join-Path $notices 'IDA-SDK-LICENSE')
    Copy-Item -LiteralPath (Join-Path $repo 'data/syscall-presets-NOTICE.txt') -Destination $notices
    $metadataJson = & cargo metadata --locked --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read dependency notices.' }
    foreach ($dependency in ($metadataJson | ConvertFrom-Json).packages | Where-Object source) {
        $licenseFiles = @(Get-ChildItem -LiteralPath (Split-Path -Parent $dependency.manifest_path) -File | Where-Object Name -Match '^(LICEN[CS]E|COPYING|COPYRIGHT|UNLICENSE|NOTICE)')
        if (-not $licenseFiles) { throw "Missing license notice for $($dependency.name)." }
        foreach ($notice in $licenseFiles) {
            Copy-Item -LiteralPath $notice.FullName -Destination (Join-Path $notices ($dependency.name + '-' + $dependency.version + '-' + $notice.Name))
        }
    }
    $rustRoot = & rustc --print sysroot
    if ($LASTEXITCODE -ne 0) { throw 'Cannot locate Rust library notices.' }
    $rustNotices = Join-Path $notices 'rust'
    New-Item -ItemType Directory -Path $rustNotices | Out-Null
    Copy-Item -LiteralPath (Join-Path $rustRoot 'share/doc/rust/COPYRIGHT-library.html') -Destination $rustNotices
    Copy-Item -LiteralPath (Join-Path $rustRoot 'share/doc/rust/licenses') -Destination (Join-Path $rustNotices 'licenses') -Recurse
    $peCheck | Set-Content -LiteralPath (Join-Path $package 'pe-check.txt') -Encoding utf8
    $revision = & git -C $repo rev-parse HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Cannot read source revision.' }
    $manifest = [ordered]@{
        ida = $IdaVersion; target = 'x86_64-pc-windows-msvc'; rust = $rustVersion; sdk_commit = $sdkCommit
        source_revision = $revision; source_files = $sourceHashes; build_script_sha256 = $recipeHash
        dll_sha256 = (Get-FileHash -LiteralPath (Join-Path $package 'ntrays.dll') -Algorithm SHA256).Hash.ToLowerInvariant()
        validation = 'Compiled; PLUGIN export, ida.dll import and static MSVC runtime checked. Runtime IDA/Hex-Rays validation is separate.'
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $package 'manifest.json') -Encoding utf8
    @"
NtRays for IDA Pro $IdaVersion on Windows x64

Close IDA, then copy ntrays.dll to %APPDATA%\Hex-Rays\IDA Pro\plugins.
Install one matching NtRays DLL; keep older/upstream DLL copies outside IDA's plugin search paths.
The x64 Hex-Rays decompiler is required. Reopen IDA and the database.
This package is built for IDA $IdaVersion only. See manifest.json and pe-check.txt for build checks.
License: BSD-3-Clause, original NtRays Copyright (c) 2021 Can Bölük; see LICENSE.
Third-party notices for the linked SDK/Rust code are in licenses/.
"@ | Set-Content -LiteralPath (Join-Path $package 'INSTALL.txt') -Encoding utf8
    Compress-Archive -Path (Join-Path $package '*') -DestinationPath $archive
    $zipHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    "$zipHash  $([IO.Path]::GetFileName($archive))" | Set-Content -LiteralPath "$archive.sha256" -Encoding ascii
    Write-Output "Built $archive"
}
finally {
    $env:IDASDK = $oldSdk
    $env:CARGO_TARGET_DIR = $oldTarget
    Pop-Location
    # This directory was created by this invocation. Keep package/logs, remove only its regular build files.
    $resolvedBuild = (Resolve-Path -LiteralPath $build).ProviderPath
    $resolvedOutput = (Resolve-Path -LiteralPath $output).ProviderPath.TrimEnd('\')
    if (-not $resolvedBuild.StartsWith($resolvedOutput + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid temporary build path.' }
    Get-ChildItem -LiteralPath $resolvedBuild -Recurse -File -Force | ForEach-Object {
        $filePath = (Resolve-Path -LiteralPath $_.FullName).ProviderPath
        if (-not $filePath.StartsWith($resolvedBuild + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Invalid build artifact path.' }
        Remove-Item -LiteralPath $filePath -ErrorAction Stop
    }
    Get-ChildItem -LiteralPath $resolvedBuild -Recurse -Directory | Sort-Object FullName -Descending | ForEach-Object {
        if (-not (Get-ChildItem -LiteralPath $_.FullName -Force)) { Remove-Item -LiteralPath $_.FullName -ErrorAction Stop }
    }
    Remove-Item -LiteralPath $resolvedBuild -ErrorAction Stop
}
