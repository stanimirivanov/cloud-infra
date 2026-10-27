# Preparation only: no credentials, plugin execution, PATH or implicit Pulumi home.
[CmdletBinding()]
param(
    [ValidateSet('oci', 'cloudflare', 'terraform-provider')][string[]]$Provider = @('oci', 'cloudflare', 'terraform-provider'),
    [string]$HomeDirectory = '.infra/provider-home',
    [string]$Archive
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne 'X64') { throw 'PROVIDER001: x64 required' }
$platform = if ($IsWindows) { 'windows-x64' } elseif ($IsLinux) { 'linux-x64' } else { throw 'PROVIDER001: unsupported OS' }
$pins = Get-Content (Join-Path $repo 'config/provider-toolchain.json') -Raw | ConvertFrom-Json -AsHashtable
if ($Archive -and $Provider.Count -ne 1) { throw 'PROVIDER001: local archive requires one provider' }
foreach ($name in $Provider) {
    $asset = $pins.providers[$name].assets[$platform]
    $version = $pins.providers[$name].version
    $system = $platform.Split('-')[0]
    $expectedUrl = "https://github.com/pulumi/pulumi-$name/releases/download/v$version/pulumi-resource-$name-v$version-$system-amd64.tar.gz"
    if ($version -notmatch '^\d+\.\d+\.\d+$' -or $asset.url -cne $expectedUrl -or $asset.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'PROVIDER001: invalid release pin' }
    foreach ($parent in @('.infra', '.infra/provider-downloads')) {
        $candidate = Join-Path $repo $parent
        if ((Test-Path -LiteralPath $candidate) -and ((Get-Item -LiteralPath $candidate -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'PROVIDER001: linked download path' }
    }
    $stage = Join-Path $repo ('.infra/provider-downloads/' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    $package = if ($Archive) { (Resolve-Path -LiteralPath $Archive).Path } else {
        $download = Join-Path $stage 'provider.tar.gz'
        Invoke-WebRequest -Uri $asset.url -OutFile $download -TimeoutSec 180
        $download
    }
    if ((Get-FileHash -LiteralPath $package -Algorithm SHA256).Hash.ToLowerInvariant() -ne $asset.sha256) {
        [Console]::Error.WriteLine('PROVIDER001: archive checksum mismatch; nothing extracted or executed')
        exit 1
    }
    & uv run --locked python -m infra_core.provider_tools --root $repo --home (Join-Path $repo $HomeDirectory) --provider $name --archive $package
    if ($LASTEXITCODE -ne 0) { throw 'PROVIDER001: installation failed' }
}
