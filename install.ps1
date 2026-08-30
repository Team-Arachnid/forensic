<#
.SYNOPSIS
    Arachnid Forensic — installer for Windows.

.DESCRIPTION
    You are encouraged to read this before running it. That is not a formality:
    this suite asks SOCs to allowlist a binary that does forensic things to a
    host, and a project making that request should not also ask you to pipe an
    unread script into a shell.

        irm https://raw.githubusercontent.com/ArachnidGs/forensic/main/install.ps1 -OutFile install.ps1
        .\install.ps1

    Reading it first is encouraged but is your call, not a step you have to get
    past: `notepad install.ps1` before that second line.

    What it does, in order:
      1. works out this machine's architecture
      2. downloads the matching release binary, its SHA256SUMS, and the
         detached signature over SHA256SUMS
      3. verifies the signature against a key pinned in this file, then the
         binary's digest against the signed SHA256SUMS. It stops on either
         failure and installs nothing
      4. installs under %LOCALAPPDATA%, adds it to the PowerShell profile's
         PATH only if it is missing, and prints the exact line it added

    What it does not do: no telemetry, no analytics, no phone-home beyond the
    downloads above. It never installs Npcap for you — that driver's trust
    chain should stay with its vendor — and it never elevates privileges.

    Uninstall with:  arachnid-cli self uninstall

.PARAMETER Version
    Install a specific release tag instead of the latest, e.g. -Version v0.1.0.

.PARAMETER InstallDir
    Override the install directory.
#>

[CmdletBinding()]
param(
    [string]$Version,
    [string]$InstallDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Repo   = 'ArachnidGs/forensic'
$Bin    = 'arachnid-cli'
$Marker = '# added by arachnid-cli installer'

# Minisign public key for release artifacts. This is the trust anchor: the whole
# verification chain reduces to whether this line is the project's real key.
#
# The installer fails closed if this is ever emptied, rather than falling back to
# "checksum only" — a checksum fetched over the same channel as the artifact
# proves the download was not corrupted and nothing at all about where it came
# from. Rotating it is a release, not a patch; see release/README.md.
$PubKey = if ($env:ARACHNID_PUBKEY) { $env:ARACHNID_PUBKEY } else { "RWT8KhRGhzRZ4gmiGJHOgKJOfZCY6dxDG/SIew+5RDH0LOkPXHFJENGh" }

function Write-Step { param([string]$m) Write-Host "==> $m" }
function Write-Detail { param([string]$m) Write-Host "    $m" }
function Fail { param([string]$m) Write-Error $m; exit 1 }

# --------------------------------------------------------------------------
# Platform
# --------------------------------------------------------------------------

function Get-Target {
    $arch = $env:PROCESSOR_ARCHITECTURE
    switch ($arch) {
        'AMD64' { return 'x86_64-pc-windows-msvc' }
        'ARM64' {
            # No aarch64 Windows build is published yet. The x64 binary runs
            # under emulation on ARM64 Windows, so say that plainly rather than
            # refusing to install anything.
            Write-Detail 'ARM64 host: installing the x64 build, which runs under emulation.'
            return 'x86_64-pc-windows-msvc'
        }
        default { Fail "unsupported architecture: $arch" }
    }
}

# --------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------

function Assert-Signature {
    param([string]$File, [string]$SigFile, [string]$KeyFile)

    if (-not $PubKey) {
        Fail @"
this installer has no release key pinned, so a download cannot be verified and
will not be installed. See release/README.md, or build from source:
  cargo install --git https://github.com/$Repo arachnid-cli
"@
    }

    $minisign = Get-Command minisign -ErrorAction SilentlyContinue
    if (-not $minisign) {
        Fail @"
minisign was not found, and this installer will not skip the signature check.

Install it, then re-run:
  winget install jedisct1.minisign
  scoop install minisign

Or download the release, its SHA256SUMS and SHA256SUMS.minisig by hand from
https://github.com/$Repo/releases and verify them yourself.
"@
    }

    Set-Content -Path $KeyFile -Value $PubKey -Encoding ascii
    & $minisign.Source -Vm $File -x $SigFile -p $KeyFile | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Fail @"
signature verification FAILED. The download does not come from the release key
pinned in this installer. Nothing has been installed. Do not run the downloaded
file; report this.
"@
    }
    Write-Detail 'signature: verified with minisign'
}

function Assert-Digest {
    param([string]$File, [string]$ChecksumFile, [string]$Name)

    $line = Select-String -Path $ChecksumFile -Pattern "[ *]$([regex]::Escape($Name))$" |
            Select-Object -First 1
    if (-not $line) { Fail "$Name is not listed in SHA256SUMS; refusing to install it." }

    $want = ($line.Line -split '\s+')[0].ToLower()
    $got  = (Get-FileHash -Path $File -Algorithm SHA256).Hash.ToLower()
    if ($want -ne $got) {
        Fail @"
checksum MISMATCH for $Name.
  expected $want
  got      $got
Nothing has been installed. Do not run the downloaded file; report this.
"@
    }
    Write-Detail "sha256:    $got"
}

# --------------------------------------------------------------------------
# PATH
# --------------------------------------------------------------------------

function Set-ProfilePath {
    param([string]$Dir)

    $current = $env:Path -split ';'
    if ($current -contains $Dir) {
        return "$Dir was already on PATH; nothing was changed."
    }

    $profilePath = $PROFILE.CurrentUserCurrentHost
    if (Test-Path $profilePath) {
        if (Select-String -Path $profilePath -Pattern ([regex]::Escape($Marker)) -Quiet) {
            return "$profilePath already carries the installer's PATH line; nothing was changed."
        }
    } else {
        New-Item -ItemType File -Path $profilePath -Force | Out-Null
    }

    $line = "`$env:Path = `"$Dir;`$env:Path`""
    Add-Content -Path $profilePath -Value "`n$Marker`n$line"
    return @"
added to $profilePath
      $line
    Open a new PowerShell session for that to take effect.

    That line applies to PowerShell only. To make it available to cmd.exe and
    Explorer as well, run this once — the installer does not do it for you,
    because a machine-wide PATH edit is not something to make on your behalf:
      [Environment]::SetEnvironmentVariable('Path', "`$Dir;" + [Environment]::GetEnvironmentVariable('Path','User'), 'User')
"@
}

# --------------------------------------------------------------------------
# Runtime dependencies
# --------------------------------------------------------------------------

function Test-Npcap {
    $installed = (Test-Path "$env:SystemRoot\System32\Npcap\wpcap.dll") -or
                 (Test-Path "$env:SystemRoot\System32\wpcap.dll")
    if ($installed) {
        Write-Detail 'npcap:     found'
        return
    }
    Write-Host ''
    Write-Warning @"
Npcap was not found. Live packet capture will not work until it is installed:

  https://npcap.com/#download

Arachnid does not bundle or silently install it. It is third-party driver
software, and your trust chain for a kernel driver should stay with its vendor.

Everything else — collect, parse-pcap, verify, report, recover, sanitize —
works without it.
"@
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

$target = Get-Target
if (-not $InstallDir) { $InstallDir = Join-Path $env:LOCALAPPDATA 'arachnid-forensic\bin' }

Write-Step 'Arachnid Forensic installer'
Write-Detail "target:    $target"

if (-not $Version) {
    try {
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
                                     -UserAgent "arachnid-cli-installer" -TimeoutSec 30
        $Version = $release.tag_name
    } catch {
        # A 404 here means "no releases published", which is a different problem
        # from "the network is down" and deserves a different answer.
        $status = $null
        if ($_.Exception.Response) { $status = [int]$_.Exception.Response.StatusCode }
        switch ($status) {
            404 {
                Fail @"
this repository has no published releases yet, so there is nothing to install.

Build it from source in the meantime:
  git clone https://github.com/$Repo.git
  cd forensic; cargo install --path crates/arachnid-cli

Or watch https://github.com/$Repo/releases for the first one.
"@
            }
            { $_ -in 403, 429 } {
                Fail @"
GitHub rate-limited this request (HTTP $status). Wait a few minutes, or install
a specific version:  .\install.ps1 -Version v0.1.0
"@
            }
            default {
                Fail @"
could not read the release list$(if ($status) { " (HTTP $status)" }). Check network
access to github.com and any proxy, or install a specific version:
  .\install.ps1 -Version v0.1.0
"@
            }
        }
    }
}
$plain = $Version.TrimStart('v')
Write-Detail "release:   $Version"

# Idempotency: if the installed copy is already this version, stop before
# downloading anything at all.
$exePath = Join-Path $InstallDir "$Bin.exe"
if (Test-Path $exePath) {
    $current = ''
    try { $current = (& $exePath version | Select-Object -First 1).Split(' ')[1] } catch { }
    if ($current -eq $plain) {
        Write-Step "$Bin $plain is already installed at $exePath"
        Write-Detail "Nothing to do. Run '$Bin doctor' to check the installation."
        exit 0
    }
    if ($current) { Write-Detail "upgrading: $current -> $plain" }
}

$asset = "$Bin-$target.exe"
$base  = "https://github.com/$Repo/releases/download/$Version"
$tmp   = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    Write-Step 'Downloading'
    $ua = 'arachnid-cli-installer'
    Invoke-WebRequest -Uri "$base/$asset"             -OutFile "$tmp\$asset"          -UserAgent $ua
    Invoke-WebRequest -Uri "$base/SHA256SUMS"         -OutFile "$tmp\SHA256SUMS"      -UserAgent $ua
    Invoke-WebRequest -Uri "$base/SHA256SUMS.minisig" -OutFile "$tmp\SHA256SUMS.minisig" -UserAgent $ua

    Write-Step 'Verifying'
    # Signature first: SHA256SUMS is only worth reading once it is known to be ours.
    Assert-Signature -File "$tmp\SHA256SUMS" -SigFile "$tmp\SHA256SUMS.minisig" -KeyFile "$tmp\minisign.pub"
    Assert-Digest -File "$tmp\$asset" -ChecksumFile "$tmp\SHA256SUMS" -Name $asset

    Write-Step "Installing to $InstallDir"
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    # Move into place in one step, so an interrupted install never leaves a
    # half-written binary where a working one used to be.
    Move-Item -Path "$tmp\$asset" -Destination $exePath -Force

    $pathNote = Set-ProfilePath -Dir $InstallDir
    Test-Npcap

    Write-Host ''
    Write-Step 'Installed'
    Write-Detail "version:   $plain"
    Write-Detail "path:      $exePath"
    Write-Detail "PATH:      $pathNote"
    Write-Host ''
    Write-Host "Check it over with:   $Bin doctor"
    Write-Host "Remove it later with: $Bin self uninstall"
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
