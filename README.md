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

arachnid-tui                                          # the same engine, driven from a TUI
```

---

## Contents

- [Design stance](#design-stance)
- [Install and build](#install-and-build)
- [Usage](#usage)
- [Terminal UI](#terminal-ui)
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
| Toolchain (TUI only) | Rust stable ≥ 1.88 | Rust stable ≥ 1.88, MSVC |
| Capture library | `libpcap-dev` / `libpcap-devel` | [Npcap](https://npcap.com/) + Npcap SDK |
| Capture privilege | root, or `CAP_NET_RAW` | Npcap driver access |

Collection works unprivileged; it just collects less, and says so in
`warnings`. Only `capture` requires the capture library at runtime.

`arachnid-core-tui` is the one crate above the workspace floor — ratatui 0.30
needs 1.88. The engine crates and the CLI stay buildable on 1.82.

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

## Usage

### `collect` — volatile system state

```bash
arachnid-core collect -o ./ev-host01 \
    --operator "analyst-7" \
    --signing-key ~/.arachnid/analyst-7.key
```

Collects processes (with argv, parent PID, loaded modules, and SHA-256 of the
on-disk image), network connections mapped to owning processes, login sessions,
loaded kernel modules, and persistence locations.

Optional memory acquisition wraps an external, vetted tool rather than shipping
a kernel driver of its own:

```bash
arachnid-core collect -o ./ev-host01 \
    --memory-tool /opt/avml --memory-tool-sha256 <hex>
```

The tool's hash is verified **before** execution. A mismatch aborts the run —
on a host that may be compromised, an unverified acquisition binary does not get
to run just because it had the right filename.

### `capture` — live packet capture

```bash
arachnid-core capture --list-devices
arachnid-core capture -o ./ev-net -d eth0 -f "tcp port 443" --duration 300
```

BPF filters are applied in the kernel, so filtered traffic is never copied into
userspace. Promiscuous mode is **off by default** because enabling it changes
the interface's receive mode, which is an observable change to the host. Ctrl-C
stops cleanly: the savefile is flushed and hashed rather than lost.

Kernel/interface packet drops are recorded and surfaced prominently. A capture
with drops has gaps, and gaps in evidence must be visible.

### `parse-pcap` — offline analysis

```bash
arachnid-core parse-pcap capture.pcap -o ./ev-pcap -f "not port 53"
```

Builds a flow table, reassembles TCP streams, and extracts indicators: IPs, DNS
queries and answers, TLS SNI, HTTP hosts, URIs, and User-Agents. The source
file's SHA-256 is recorded, binding the analysis to the exact bytes analysed.

Nothing is resolved or enriched against any remote service. A triage tool that
phones out about the indicators it just found leaks the investigation.

### `verify` — independent integrity check

```bash
arachnid-core verify ./ev-host01        # exit 0 intact, 3 tampered
arachnid-core --json verify ./ev-host01
```

Re-hashes every artifact, re-checks every signature, and walks the custody hash
chain. Deliberately implemented independently of the collection path, so a bug
in collection cannot make a broken container verify clean.

### Exit codes

Stable across releases, for SOAR playbooks and IR scripts:

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Runtime error — I/O, permission, missing device, unusable input |
| 2 | Usage error (clap) |
| 3 | Integrity failure — `verify` found a problem |
| 4 | Completed, but a collector was degraded; see `warnings` in the report |

Code 4 is the one worth special handling: you *have* evidence, but it is
incomplete, and the report says exactly which collectors fell short.

### Logging

The operational log (`tracing`) is strictly separate from the evidence log. It
goes to stderr, or to `--log <path>`. Verbosity comes from `--log-level`, which
takes precedence over the `ARACHNID_LOG` environment variable.

---

## Terminal UI

`arachnid-tui` is the second front end over the same engine. It drives the
library crates directly — it never shells out to `arachnid-core`, and it can do
nothing the CLI cannot. A container written by the TUI verifies with the CLI and
validates against the same published schemas.

```bash
cargo run -p arachnid-core-tui     # or: arachnid-tui
```

On launch it shows the wordmark while it probes the host — effective privilege,
whether a capture device is reachable — then drops into the dashboard. Failed
probes become a warning banner, never a refusal to start: an unprivileged
operator can still verify and report on a container collected elsewhere.

```
                       /\   /\
                      (  o.o  )
                        > ^ <
               _.-'~~~~~~~~~~~~~~~'-._
               .'                   '.
               |      ARACHNID       |
               |  F O R E N S I C S  |
               '.___________________.'

                  ⠋ checking host…
              authorized DFIR use only
```

```
 arachnid  1:Dashboard  2:Collect  3:Capture  4:Parse PCAP  5:Verify  6:Report
╭ privilege ─────────────╮╭ packet capture ────────╮╭ evidence session ──────╮
│root                    ││2 device(s)             ││./ev-host01             │
│full collection availab.││eth0, lo                ││operator analyst-7@linux│
│                        ││                        ││verified 8 artifacts    │
╰────────────────────────╯╰────────────────────────╯╰────────────────────────╯
 go to
 > Collect     collect volatile system state
   Capture     capture live network traffic
   Parse PCAP  analyse an existing PCAP
   Verify      verify an evidence container
   Report      render a container's report
 no startup warnings; every check passed
 ? this help  ·  j/k move  ·  Enter open  ·  Tab next screen  ·  1-6 jump …
```

### Screens

| # | Screen | What it does |
|---|--------|--------------|
| 1 | Dashboard | privilege, capture availability, current session, quick launch |
| 2 | Collect | live per-collector checklist, then artifact counts and the key fingerprint |
| 3 | Capture | device and BPF filter, running counters, post-capture flow breakdown |
| 4 | Parse PCAP | read-only analysis first, export to a container second |
| 5 | Verify | per-artifact hash status, overall verdict, collection vs. verify time |
| 6 | Report | container contents by type, and export as JSON / Markdown / HTML |

Verify and Report both open the **chain-of-custody** view (`c`): every record in
order, with the selected one shown in full — complete digest, not a prefix.
Nothing on that screen is summarized away.

### Keys

`?` lists every binding, generated from the same keymap table that dispatches
them. Globally: `Tab`/`Shift-Tab` or `1`-`6` to move between screens, `Ctrl-L`
for the operational log pane, `Esc` to back out, `q` to quit. Within a screen,
`j`/`k` move, `Enter` edits a field or drills in.

Fields have an explicit edit mode so a path containing `q` can be typed: `Enter`
enters the field, `Esc` or `Enter` leaves it.

Anything that starts, replaces or stops evidence collection asks first — quitting
during a capture included, and confirming there sets the stop flag so the
savefile is flushed and sealed rather than lost.

### Behaviour worth knowing

- **Capture keeps running while you navigate.** It is a background thread; the
  header shows `[capturing]` from every screen.
- **Live capture figures are counters only.** Decoding frames to fill a packet
  table would put per-frame work in the capture loop, which is how a capture
  falls behind the link and drops evidence. The flow and protocol breakdown come
  from a read-only re-read of the savefile once it is closed and sealed.
- **`NO_COLOR` is respected**, and every verdict is stated in text as well as
  colour, so nothing is lost in a monochrome terminal.
- **Layout degrades rather than breaks** down to 32x8: the tab strip collapses
  to a position indicator, cards lose their borders, tables truncate with a
  `… n more` marker.
- A panic hook restores the terminal — raw mode off, alternate screen left —
  before the panic prints, so a crash cannot leave the shell unusable.

The TUI remembers the operator name and recent paths in
`$XDG_STATE_HOME/arachnid/tui-state.json` (`%APPDATA%` on Windows). That file is
a convenience, never evidence; deleting it costs two retyped paths.

---

## The evidence container

```
ev-host01/
├── manifest.json          run metadata + Ed25519 public key
├── custody.log            append-only signed hash chain, one record per line
└── artifacts/
    ├── processes.json     connections.json     sessions.json
    ├── kernel_modules.json    persistence.json
    ├── memory.raw         (if acquired)
    ├── capture.pcap       (capture runs)
    ├── pcap_analysis.json (parse-pcap runs)
    └── report.json  report.md  report.html
```

Each `custody.log` line is `<ed25519-signature-hex> <record-json>`. Three
properties combine to make the container tamper-evident:

| Tampering | Detected by |
|---|---|
| Editing an artifact | recorded SHA-256 no longer matches |
| Editing a log record | that line's signature no longer verifies |
| Deleting or reordering records | `prev` hash chain breaks |
| Adding an unlogged artifact | file present on disk with no custody record |

Signing is over the exact bytes following the first space on the line. Nothing
is re-serialized during verification, so JSON canonicalization is never a
correctness question.

Every record carries both a UTC wall-clock timestamp and a monotonic offset from
container creation. Wall clock is what an analyst reads; the monotonic clock is
what preserves ordering when the examined host's clock steps mid-collection.

---

## Threat model

### What Arachnid Core defends against

**Post-collection tampering.** Anyone who modifies an artifact, edits a custody
record, removes a record, or plants an unlogged file is detected by `verify`.
This is the property the container exists to provide.

**A swapped acquisition tool.** The memory acquisition binary is hash-pinned and
verified before execution, so a replaced `avml` on a compromised host is caught
before it runs rather than recorded after.

**Silent partial collection.** Every collector that fails records why, in
`warnings`, in the custody log, at the top of the report, and in exit code 4. An
empty result set is never allowed to look like a clean host.

**Capture gaps.** Kernel and interface drop counters are recorded and surfaced.

### What it does *not* defend against

These are limitations of live triage itself, not gaps to be patched. State them
in your notes.

**A compromised kernel lies.** Every collector reads through OS APIs. A rootkit
that hooks those APIs — a malicious LKM, an SSDT hook, a hypervisor-level
implant — can hide processes, sockets, and files from us as easily as from
`ps`. Memory acquisition and offline analysis are the countermeasure, which is
why `collect` supports acquiring an image. Correlate; do not trust live
enumeration alone against a kernel-level adversary.

**Ephemeral-key containers prove integrity, not origin.** Without
`--signing-key`, a key is generated per run. Anyone who can rewrite the whole
container can also swap the key and re-sign everything. `verify` then proves
only that the container is self-consistent. It proves *origin* only when the key
fingerprint matches one recorded out-of-band. **For chain of custody that must
survive challenge in a proceeding, issue each responder a persistent key and
always pass `--signing-key`.** The fingerprint is printed at the end of every
run precisely so it can be recorded.

**Collection is not atomic.** The host keeps running while collectors execute. A
process can exit between the process table read and the connection table read.
Timestamps in the custody log let you reconstruct the order; they cannot give
you a consistent snapshot. Only a memory image can.

**The operator's privilege is the ceiling.** Arachnid never escalates. Running
as a normal user yields materially less evidence, and says so.

**Collected content is hostile input.** Process command lines, DNS names, HTTP
headers, and persistence values are all attacker-controllable. They are stored
verbatim, and escaped on output — the HTML report escapes every field, and there
is a test asserting a `<script>` tag in a hostname cannot break out. Anything
downstream that renders this data must escape it too.

**Anti-forensics that predates collection.** A cleared utmp, a deleted unit
file, or a task registered only in the registry store is already gone before
Arachnid runs. Arachnid records what is present; it does not recover what was
removed. That is the Arachnid Recover module's job.

---

## SOC allowlisting

Full disclosure of every path, registry key, API, and network behaviour is in
**[docs/SOC-ALLOWLISTING.md](docs/SOC-ALLOWLISTING.md)** — written so a SOC can
pre-approve the binary with a narrow rule instead of a broad one.

Summary: no child processes except the acquisition tool you name; no writes
outside your `-o` directory; no outbound network connections of any kind; no
listening sockets; read-only registry access; no self-persistence.

---

## Output schema

The JSON report is the contract, and it is versioned:

- [`schema/report.schema.json`](schema/report.schema.json) — the full report
- [`schema/custody.schema.json`](schema/custody.schema.json) — one custody record

Consumers must reject a major version they do not implement. The Markdown and
HTML renderings carry no information the JSON lacks, and can be regenerated at
any time with `arachnid-core report`.

The container format is shared with the Arachnid Recover module, which consumes
these containers directly.

---

## Development

```bash
cargo test --workspace              # unit + integration tests
cargo clippy --workspace --all-targets
cargo deny check                    # advisories, bans, licenses, sources
cargo audit                         # RustSec advisories (same DB as deny)

# Lint the Windows collectors from a Linux host — no linker required.
# Use clippy, not check: lints on cfg(windows) code are invisible otherwise.
rustup target add x86_64-pc-windows-msvc
cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc
```

The workspace is six crates, and `arachnid-evidence` is the foundation every
other one depends on:

| Crate | Responsibility |
|---|---|
| `arachnid-evidence` | Hashing, Ed25519 custody chain, container creation, verification |
| `arachnid-collect` | Read-only volatile collectors; external memory acquisition |
| `arachnid-netcap` | Live capture, PCAP parsing, TCP reassembly, indicators |
| `arachnid-report` | Schema-versioned JSON, Markdown and HTML summaries |
| `arachnid-core-cli` | Argument parsing, orchestration, exit codes |
| `arachnid-core-tui` | Terminal UI over the same library calls the CLI makes |

The TUI is a view/controller layer with no engine logic of its own. Its own
tests render every screen at every supported terminal size, so a layout that
would panic and take the terminal with it fails in CI instead.

Tests run unprivileged. Anything needing root — live capture, memory
acquisition — is exercised on its refusal path in CI and belongs to a
disposable-VM suite otherwise.

Dependencies are kept few and are audited in CI; `deny.toml` bans outbound-HTTP
and dynamic-loading crates outright, so an accidental dependency that could
phone home fails the build rather than shipping.

---

## Known limitations

- **macOS** is a stretch goal. `sysinfo` and `netstat2` already yield processes
  and connections there; sessions, kernel modules, and persistence report an
  explicit gap rather than an empty list.
- **Windows scheduled tasks** are read from the on-disk `System32\Tasks` store
  rather than through the Task Scheduler COM API. This misses a task registered
  only in the registry `TaskCache` with no matching file — a known
  anti-forensics technique. The limitation and the way to close it are
  documented on `scheduled_tasks` in `crates/arachnid-collect/src/windows.rs`.
- **TCP reassembly** assumes a stream window under 2 GiB, the standard TCP
  assumption. Per-flow reassembly is capped (8 MiB by default) and a flow that
  hits the cap is flagged `truncated`, never silently shortened.
- **Encrypted ClientHello** yields no SNI. Arachnid reads the plaintext
  handshake and does not attempt to decrypt anything.
- **Windows without Npcap**: `capture` and `parse-pcap` need `wpcap.dll` and
  report a readable error when it is absent. `collect`, `verify` and `report`
  work without it — `wpcap.dll` is delay-loaded, so the binary starts on a host
  that has no packet driver. Npcap installs to `System32\Npcap`, which is not
  on the default DLL search path; Arachnid adds it before the first pcap call.
- **`paste`**, reached via `netstat2`, carries an unmaintained advisory
  (RUSTSEC-2024-0436). It is a compile-time proc-macro contributing no code to
  the binary; the exception and its review date are documented in `deny.toml`.

---

## License

MIT. See [LICENSE](LICENSE).
