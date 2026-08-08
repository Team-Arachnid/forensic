# Arachnid Core

**Live triage and network forensics for the Arachnid Forensic suite.**

Arachnid Core collects volatile system state and network evidence from a running
host into a tamper-evident, cryptographically signed evidence container. It is
read-only against the target: the only writes go to the container directory you
name.

For use by authorized analysts on systems they have permission to examine.

```
arachnid-core collect     -o ./ev-host01              # volatile state
arachnid-core capture     -o ./ev-net -d eth0 --duration 300 -f "not port 22"
arachnid-core parse-pcap  suspicious.pcap -o ./ev-pcap
arachnid-core verify      ./ev-host01                 # exit 0 = intact, 3 = tampered
arachnid-core report      ./ev-host01 --format html -o triage.html
```

---

## Contents

- [Design stance](#design-stance)
- [Install and build](#install-and-build)
- [Usage](#usage)
- [The evidence container](#the-evidence-container)
- [Threat model](#threat-model)
- [SOC allowlisting](#soc-allowlisting)
- [Output schema](#output-schema)
- [Development](#development)
- [Known limitations](#known-limitations)

---

## Design stance

A triage tool runs with high privilege on a host that may already be
compromised, and it does things that resemble reconnaissance. Two consequences
shape everything here.

**1. Be inspectable, not evasive.** There is no packing, no obfuscation, no
anti-debugging, and no attempt to hide from AV or EDR. The release build
*fails* if the subcommand names are not visible to `strings`. Defenders are
asked to pre-approve the tool via [the allowlisting
guide](docs/SOC-ALLOWLISTING.md) — the alternative, a tool that hides from
defenders, is indistinguishable from malware and deserves to be treated as such.

**2. Never write to the target.** Collectors read `/proc`, `/sys`, the registry
(`KEY_READ` only), and config paths. Persistence entries are *enumerated*, never
modified. `--dry-run` performs every collection and every hash while writing
nothing at all, so you can validate an EDR rule before a real engagement.

Explicitly out of scope, and flagged rather than implemented if a future feature
would need them: anti-EDR/anti-AV/anti-debugging, packing or runtime
obfuscation, exploit or privilege-escalation code, process injection, dynamic
code loading, self-persistence, packet injection or interception.

---

## Install and build

### Requirements

| | Linux | Windows |
|---|---|---|
| Toolchain | Rust stable ≥ 1.82 | Rust stable ≥ 1.82, MSVC |
| Capture library | `libpcap-dev` / `libpcap-devel` | [Npcap](https://npcap.com/) + Npcap SDK |
| Capture privilege | root, or `CAP_NET_RAW` | Npcap driver access |

Collection works unprivileged; it just collects less, and says so in
`warnings`. Only `capture` requires the capture library at runtime.

### Development build

```bash
cargo build --release
cargo test --workspace
```

### Release build

```bash
# Linux: static musl binary, reproducible, GPG-signed
GPG_KEY=<your-key-id> ./scripts/build-release.sh

# Windows: static CRT, Authenticode-signed
$env:NPCAP_SDK = "C:\npcap-sdk-1.13"
$env:ARACHNID_CERT_THUMBPRINT = "<thumbprint>"
.\scripts\build-release.ps1
```

Both scripts emit the binary, a `.sha256`, and a signature into `dist/`, and
both refuse to produce a binary whose subcommands are invisible to `strings`.

**What "statically linked" covers, precisely.** On Linux the release script
builds libpcap from source against musl and links it statically, so the output
is a genuine single file with no dynamic dependencies — the script verifies this
with `ldd` and fails if anything is left. On Windows the CRT is static, but
`wpcap.dll` remains an import: it is the user-mode half of the Npcap kernel
driver and cannot be statically linked by anyone. Npcap must be installed on the
examined host for `capture` to work; every other subcommand runs without it.

Builds are reproducible. `SOURCE_DATE_EPOCH` and `--remap-path-prefix` are set,
so rebuilding a tagged commit reproduces the published hash — which is how a SOC
confirms the binary it allowlisted matches the source it reviewed.

---

