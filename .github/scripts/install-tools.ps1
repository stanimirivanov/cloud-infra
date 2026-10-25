# Reviewed release archives only; no downloaded installer scripts or PATH tool reuse.
[CmdletBinding()]
param(
    [ValidateSet('uv', 'pulumi', 'gitleaks')][string[]]$Tool = @('uv', 'pulumi', 'gitleaks'),
    [string]$Archive
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') {
    throw 'Only reviewed x64 tool archives are supported'
}
$platform = if ($IsWindows) { 'windows-x64' } elseif ($IsLinux) { 'linux-x64' } else { throw 'Unsupported OS' }
$pins = Get-Content (Join-Path $repo 'config/toolchain.json') -Raw | ConvertFrom-Json -AsHashtable
if ($Archive -and $Tool.Count -ne 1) { throw 'A local archive requires exactly one tool' }
foreach ($name in $Tool) {
    $asset = $pins.tools[$name].assets[$platform]
    $stage = Join-Path $repo ('.infra/tools/' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $package = if ($Archive) { (Resolve-Path -LiteralPath $Archive).Path } else {
        $download = Join-Path $stage ([uri]$asset.url).Segments[-1]
        Invoke-WebRequest -Uri $asset.url -OutFile $download -TimeoutSec 180
        $download
    }
    if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant() -ne $asset.sha256) {
        throw "TOOL001: $name archive checksum mismatch; nothing extracted or executed"
    }
    $unpacked = Join-Path $stage 'unpacked'
    New-Item -ItemType Directory -Path $unpacked | Out-Null
    if ($asset.url.EndsWith('.zip')) {
        Expand-Archive -LiteralPath $package -DestinationPath $unpacked
    } else {
        & tar -xzf $package -C $unpacked
        if ($LASTEXITCODE -ne 0) { throw "TOOL001: $name extraction failed" }
    }
    $binary = Join-Path $unpacked $asset.binary
    if (-not (Test-Path -LiteralPath $binary -PathType Leaf)) { throw "TOOL001: missing $name binary" }
    if ($name -eq 'gitleaks') {
        if ((Get-FileHash -LiteralPath $binary -Algorithm SHA256).Hash.ToLowerInvariant() -ne $asset.binary_sha256) {
            throw 'TOOL001: scanner binary checksum mismatch'
        }
        $scannerDir = Join-Path $repo '.infra/tools/gitleaks'
        New-Item -ItemType Directory -Path $scannerDir -Force | Out-Null
        Copy-Item -LiteralPath $binary -Destination $scannerDir -Force
        $binary = Join-Path $scannerDir (Split-Path $binary -Leaf)
    }
    if (-not $IsWindows) {
        & chmod 0755 $binary
        if ($LASTEXITCODE -ne 0) { throw "TOOL001: cannot mark $name executable" }
    }
    $binDir = Split-Path $binary -Parent
    $env:PATH = $binDir + [IO.Path]::PathSeparator + $env:PATH
    if ($env:GITHUB_PATH) { $binDir | Out-File -LiteralPath $env:GITHUB_PATH -Append -Encoding utf8 }
    Write-Host "Verified $name $($pins.tools[$name].version) for $platform"
}
