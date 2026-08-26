---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 1 · Getting Started

[← Home](Home.md) · [Next: Core Concepts →](02-Concepts.md)

---

## Contents

- [Install](#install)
- [Requirements](#requirements)
- [Development build](#development-build)
- [Checking the installation](#checking-the-installation)
- [Updates](#updates)
- [Release build](#release-build)
- [What "statically linked" covers](#what-statically-linked-covers-precisely)
- [Reproducible builds](#reproducible-builds)
- [Verifying a release binary](#verifying-a-release-binary)
- [Your first container](#your-first-container-five-minutes)
- [Running the TUI](#running-the-tui)
- [Where to go next](#where-to-go-next)

---

## Install

```bash
# macOS, Linux — read it first, then run it
curl -fsSL https://install.arachnid-forensic.dev/install.sh -o install.sh
less install.sh
sh install.sh
```

```powershell
# Windows
irm https://install.arachnid-forensic.dev/install.ps1 -OutFile install.ps1
notepad install.ps1
.\install.ps1
```

The one-line piped forms (`… | sh`, `… | iex`) are the same thing without the
reading step. They are documented second on purpose: a project that asks you to
allowlist a forensic binary should not also ask you to pipe an unread script
into a shell. Both scripts are checked into the repository, so the signing key
they pin is reviewable in version control rather than only at the URL.

The installer verifies a signature over the digest file, then the digest of the
binary, and aborts on either failure having installed nothing. It installs to a
per-user directory, never elevates on its own, and never installs Npcap for you.

> **No release signing key has been generated for this project yet.** Both
> installers stop and say so rather than installing something they cannot
> verify, which is the intended behaviour rather than a bug. Until a key exists,
> build from source as below. The one-time setup is in `release/README.md`.

Full detail on what it downloads, verifies, writes and reverts:
[THREAT_MODEL.md](../../THREAT_MODEL.md).

---

## Requirements

| | Linux | Windows |
|---|---|---|
| Toolchain | Rust stable ≥ **1.82** | Rust stable ≥ **1.82**, MSVC |
| Toolchain (TUI and Sanitize) | Rust stable ≥ **1.88** | Rust stable ≥ **1.88**, MSVC |
| Capture library | `libpcap-dev` / `libpcap-devel` | [Npcap](https://npcap.com/) + the Npcap SDK |
| Capture privilege | root, or `CAP_NET_RAW` | Npcap driver access |

Three crates sit above the workspace floor: `arachnid-core-tui` (ratatui 0.30
needs 1.88) and the two Sanitize crates (raw-device I/O on Windows pulls in the
same `windows` crate). The Core engine crates and the triage CLI stay buildable
on 1.82, so a locked-down build host with an older toolchain can still produce
`arachnid-core`.

**Only `capture` and `parse-pcap` need the capture library at runtime.**
`collect`, `verify` and `report` do not — and on Windows they run on a host with
no Npcap installed at all, because `wpcap.dll` is delay-loaded. See
[Network Forensics § Windows and Npcap](07-Network-Forensics.md#windows-and-npcap).

Collection works unprivileged. It just collects less, and says so in `warnings`
and via [exit code 4](02-Concepts.md#exit-codes).

Installing the capture library:

```bash
sudo apt install libpcap-dev          # Debian / Ubuntu
sudo dnf install libpcap-devel        # Fedora / RHEL
sudo pacman -S libpcap                # Arch
```

---

## Development build

```bash
git clone https://github.com/ArachnidGs/forensic.git
cd forensic
cargo build --release
cargo test --workspace
```

### Put it on your PATH

`cargo build` leaves the binaries in `target/release/`; it does **not** install
them. Installing is the step that makes the command work from anywhere:

```bash
cargo install --path crates/arachnid-cli
arachnid-cli --version
```

That is the only one you need. **`arachnid-cli` is the single entry point** —
bare it opens the terminal UI, and it takes every command below through a
module group:

```bash
arachnid-cli                                 # the TUI, covering every module
arachnid-cli core collect -o ./ev-host01     # triage
arachnid-cli recover scan -i disk.img -o ./rec
arachnid-cli sanitize list-devices           # DESTROYS DATA
arachnid-cli doctor                          # why isn't it working?
arachnid-cli --help
```

The five `core` commands also work without the prefix — `arachnid-cli collect
-o ./ev` — which is the form older scripts and docs use, and which keeps
working.

> Note the binary names are not the crate names. `arachnid-core-cli` is a
> *crate*; typing it gets you `command not found`.

Four binaries land in `target/release/`:

| Binary | Crate | What it is |
|---|---|---|
| `arachnid-cli` | `arachnid-cli` | **the entry point.** TUI bare, every command with a subcommand |
| `arachnid-core` | `arachnid-core-cli` | the triage CLI on its own |
| `arachnid-tui` | `arachnid-core-tui` | the terminal UI on its own |
| `arachnid-sanitize` | `arachnid-sanitize-cli` | **destructive.** Secure erasure — see [Secure Erasure](14-Secure-Erasure.md) |

The last three are what SOAR playbooks and the release scripts name, and their
exit codes are a documented contract, so they still ship. If you are typing
commands yourself, you only need the first.

Build just one:

```bash
cargo build --release -p arachnid-core-cli
cargo build --release -p arachnid-core-tui
cargo build --release -p arachnid-sanitize-cli
```

The release profile is tuned for a small single binary — `opt-level = "z"`,
LTO, one codegen unit, `panic = "abort"`, symbols stripped.

---

## Release build

Release builds are reproducible, statically linked, and signed. The scripts do
all three and refuse to emit a binary that fails any of the checks.

### Linux — static musl, GPG-signed

```bash
GPG_KEY=<your-key-id> ./scripts/build-release.sh
```

What it does, in order:

1. **Builds libpcap from source against musl.** No distribution ships a musl
   static libpcap, and without one you get a working binary with a dynamic
   libpcap dependency — fine for a lab, wrong for a locked-down host.
2. **Builds `arachnid-core`** with `SOURCE_DATE_EPOCH` and
   `--remap-path-prefix` set, for reproducibility.
3. **Proves the binary is static** with `ldd`, and fails if anything is left.
4. **Proves the binary is inspectable** — `strings` must find `collect`,
   `capture`, `parse-pcap`, `verify`, `report` and `Arachnid Core`. If it
   cannot, something in the pipeline is hiding the binary from the analysts you
   are asking to allowlist it, and the build fails.
5. **Emits** the binary, a `.sha256`, and a detached armoured GPG signature into
   `dist/`.

Tunable via environment: `TARGET`, `PCAP_VERSION`, `PCAP_SHA256`, `BUILD_DIR`,
`DIST`, `SOURCE_DATE_EPOCH`.

### Windows — static CRT, Authenticode-signed

```powershell
$env:NPCAP_SDK = "C:\npcap-sdk-1.13"
$env:ARACHNID_CERT_THUMBPRINT = "<thumbprint>"
.\scripts\build-release.ps1
```

Same shape: build, prove inspectable, sign with `signtool` (SHA-256, RFC 3161
timestamped), emit hash. Only the Npcap *import library* is needed at build
time; Npcap itself is a kernel driver installed on the examined host.

---

## What "statically linked" covers, precisely

**Linux:** genuinely a single file. libpcap is built from source against musl and
linked statically; the script verifies with `ldd` and fails if any dynamic
dependency remains.

**Windows:** the CRT is static — no vcruntime redistributable needed on the
examined host — but `wpcap.dll` remains an import. It is the user-mode half of
the Npcap kernel driver and cannot be statically linked by anyone. It is
**delay-loaded**, so:

- the binary starts on a host with no packet driver;
- `collect`, `verify` and `report` work there normally;
- `capture` and `parse-pcap` report a readable error instead of failing to
  start with `STATUS_DLL_NOT_FOUND`.

---

## Reproducible builds

`SOURCE_DATE_EPOCH` and `--remap-path-prefix` are set, so rebuilding a tagged
commit reproduces the published hash. That is how a SOC confirms the binary it
allowlisted matches the source it reviewed — the strongest check available, and
the one the [allowlisting guide](../SOC-ALLOWLISTING.md) recommends.

```bash
git checkout v0.1.0
GPG_KEY=<key> ./scripts/build-release.sh
sha256sum dist/arachnid-core-0.1.0-x86_64-unknown-linux-musl
# compare against the published .sha256
```

---

## Verifying a release binary

Do this **before** running it on an evidence-bearing system.

```bash
sha256sum -c arachnid-core-0.1.0-x86_64-unknown-linux-musl.sha256
gpg --verify arachnid-core-0.1.0-x86_64-unknown-linux-musl.asc \
             arachnid-core-0.1.0-x86_64-unknown-linux-musl
```

Windows:

```powershell
Get-FileHash -Algorithm SHA256 arachnid-core.exe
signtool verify /pa /v arachnid-core.exe
```

---

## Checking the installation

```bash
arachnid-cli doctor
```

It reports the version and build hash, whether the binary on PATH is *this*
binary, whether the capture library loaded, and what the process is actually
permitted to do — read from its own credentials rather than by opening a raw
socket, because on a monitored host a diagnostic that opens a raw socket is a
diagnostic that trips an EDR rule.

Every failing line carries the fix for **this** machine: the package manager you
actually have, the stale copy that is actually shadowing the binary.

```
  [!!] PATH                   `arachnid-cli` resolves to /usr/local/bin/arachnid-cli,
                              not to /home/analyst/.local/bin/arachnid-cli
       An older copy is earlier in PATH. Remove it, or put
       /home/analyst/.local/bin first.
```

`--json` gives the same report machine-readably. The exit code is 1 if anything
failed, so a provisioning script can gate on it.

---

## Updates

`arachnid-cli` checks once a day, **on an interactive terminal only**, whether a
newer release exists, and prints one line to stderr if so. Scripted and
scheduled runs make no network call at all.

It never installs anything by itself. Silently replacing a forensic tool's
binary would break the "the same binary processed this evidence" claim that
chain-of-custody rests on.

```bash
arachnid-cli self update --dry-run    # download, verify, install nothing
arachnid-cli self update              # download, verify, install
arachnid-cli self uninstall           # shows what it would do; --yes does it
```

Switch the check off with `--no-update-check`, or permanently with
`ARACHNID_NO_UPDATE_CHECK=1`. Both are honoured silently. The full behaviour,
including exactly what is sent, is in [THREAT_MODEL.md](../../THREAT_MODEL.md)
and [SOC allowlisting §5a](../SOC-ALLOWLISTING.md).

---

## Your first container (five minutes)

### 1 · Collect

```bash
arachnid-core collect -o ./ev-demo --operator "analyst-7"
```

It prints the report to stdout and ends with:

```
---

Evidence container: ./ev-demo
Signing key fingerprint: 0f78aa46c953c7fda9f39a829e729b656061299a35fb1c337e960695e867ffdc
Record this fingerprint out-of-band; `verify` can only prove origin against it.
Verify with: arachnid-core verify ./ev-demo
```

### 2 · Look at what it made

```bash
find ./ev-demo -type f | sort
```

```
./ev-demo/artifacts/connections.json
./ev-demo/artifacts/kernel_modules.json
./ev-demo/artifacts/persistence.json
./ev-demo/artifacts/processes.json
./ev-demo/artifacts/report.html
./ev-demo/artifacts/report.json
./ev-demo/artifacts/report.md
./ev-demo/artifacts/sessions.json
./ev-demo/custody.log
./ev-demo/manifest.json
```

```bash
cat ./ev-demo/manifest.json
```

```json
{
  "schema_version": "1.0.0",
  "tool": "arachnid-core",
  "tool_version": "0.1.0",
  "container_id": "848b9f935ffcfb4e757c80712b3c61a3",
  "created_utc": "2026-08-28T16:19:01.581759466Z",
  "operator": "analyst-7",
  "host": "arch",
  "platform": "linux/x86_64",
  "public_key": "4d321e81c9f87371a7cc5d5087ebe6c283d6acfc0806a76c10bef23abeb35bde"
}
```

### 3 · Verify it

```bash
arachnid-core verify ./ev-demo; echo "exit=$?"
```

```
container:        ./ev-demo
schema:           1.0.0
signing key:      4d321e81c9f87371a7cc5d5087ebe6c283d6acfc0806a76c10bef23abeb35bde
key fingerprint:  0f78aa46c953c7fda9f39a829e729b656061299a35fb1c337e960695e867ffdc
custody records:  11
artifacts hashed: 8

VERIFIED: every artifact matches the signed custody log.
This confirms the container is internally consistent. It is only proof of
origin if the key fingerprint above matches the one recorded at collection.
exit=0
```

### 4 · Break it, and watch verification catch it

```bash
echo '[]' > ./ev-demo/artifacts/sessions.json
arachnid-core verify ./ev-demo; echo "exit=$?"
```

```
FAILED: 2 problem(s).
  - artifact sessions.json: content modified since collection
  - artifact sessions.json: size differs from record
exit=3
```

That is the whole point of the container. See
[The Evidence Container](05-Evidence-Container.md) for how it works.

### 5 · Render a human report

```bash
arachnid-core report ./ev-demo --format html -o triage.html
```

A single self-contained HTML file with no external assets — it renders on an
air-gapped workstation.

---

## Running the TUI

```bash
arachnid-tui
# or, from the repository:
cargo run -p arachnid-core-tui
```

It shows the wordmark while it probes the host (privilege, capture
availability), then drops into the dashboard. Press `?` for every binding,
`1`–`7` to jump between screens, `q` to quit.

Full guide: [Terminal UI](04-TUI-Guide.md).

---

## Where to go next

- Understand what a container *is* → [Core Concepts](02-Concepts.md)
- Look up a flag → [CLI Reference](03-CLI-Reference.md)
- Do a real engagement → [Workflows](09-Workflows.md)
- Wipe a drive for disposal → [Secure Erasure](14-Secure-Erasure.md)

[← Home](Home.md) · [Next: Core Concepts →](02-Concepts.md)
