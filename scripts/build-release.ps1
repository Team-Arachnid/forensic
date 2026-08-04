# Windows release build + Authenticode signature.
#
# Requires: Rust MSVC toolchain, the Npcap SDK, and signtool.exe from the
# Windows SDK. Npcap itself is a kernel driver installed on the examined host;
# only its import library is needed here.

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Target = "x86_64-pc-windows-msvc",
    [string]$NpcapSdk = $env:NPCAP_SDK,
    # Authenticode signing certificate thumbprint from the local certificate store.
    [string]$CertThumbprint = $env:ARACHNID_CERT_THUMBPRINT,
    [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

if (-not $NpcapSdk) { throw "Set NPCAP_SDK to the Npcap SDK root (npcap-sdk-*/)." }
$libDir = Join-Path $NpcapSdk (if ($Target -like "aarch64*") { "Lib\ARM64" } else { "Lib\x64" })
if (-not (Test-Path $libDir)) { throw "Npcap import libraries not found at $libDir" }

Write-Host "==> building arachnid-core for $Target"
rustup target add $Target 2>$null | Out-Null

# Static CRT comes from .cargo/config.toml. wpcap.dll stays a runtime import:
# it is the user-mode half of the Npcap driver and cannot be statically linked.
$env:LIB = "$libDir;$env:LIB"
$env:SOURCE_DATE_EPOCH = (git log -1 --pretty=%ct)
$env:RUSTFLAGS = "--remap-path-prefix=$PWD=/build"

cargo build --release --locked --target $Target -p arachnid-core-cli
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$version = (cargo metadata --no-deps --format-version 1 | ConvertFrom-Json).packages[0].version
$dist = Join-Path $PWD "dist"
New-Item -ItemType Directory -Force -Path $dist | Out-Null
$out = Join-Path $dist "arachnid-core-$version-$Target.exe"
Copy-Item "target\$Target\release\arachnid-core.exe" $out -Force

Write-Host "==> verifying the binary is inspectable"
$strings = & cmd /c "findstr /C:parse-pcap `"$out`"" 2>$null
if (-not $strings) { throw "'parse-pcap' not visible in the binary; the pipeline is obscuring it" }

if ($CertThumbprint) {
    Write-Host "==> Authenticode signing"
    & signtool sign /sha1 $CertThumbprint /fd SHA256 /tr $TimestampUrl /td SHA256 /v $out
    if ($LASTEXITCODE -ne 0) { throw "signtool failed" }
    & signtool verify /pa /v $out
    if ($LASTEXITCODE -ne 0) { throw "signature verification failed" }
} else {
    Write-Host "==> ARACHNID_CERT_THUMBPRINT not set; skipping signing (release builds MUST set it)"
}

$hash = (Get-FileHash -Algorithm SHA256 $out).Hash.ToLower()
"$hash  $(Split-Path -Leaf $out)" | Out-File -Encoding ascii "$out.sha256"
Write-Host "==> SHA-256: $hash"
Write-Host ""
Write-Host "Add this hash to docs/SOC-ALLOWLISTING.md before publishing."
