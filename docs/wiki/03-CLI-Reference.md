---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 3 · CLI Reference

[← Core Concepts](02-Concepts.md) · [Home](Home.md) · [Next: Terminal UI →](04-TUI-Guide.md)

Complete reference for `arachnid-core` 0.1.0. Every flag, every default, with
worked examples and real output.

> This page covers the **triage** CLI. For `arachnid-sanitize`, the suite's
> destructive erasure CLI, see [Secure Erasure](14-Secure-Erasure.md#cli-reference).

---

## Contents

- [Synopsis](#synopsis)
- [Global options](#global-options)
- [Shared container options](#shared-container-options)
- [`collect`](#collect)
- [`capture`](#capture)
- [`parse-pcap`](#parse-pcap)
- [`verify`](#verify)
- [`report`](#report)
- [Exit codes](#exit-codes)
- [Environment variables](#environment-variables)

---

## Synopsis

```
arachnid-core [OPTIONS] <COMMAND>

Commands:
  collect     Collect volatile system state into a new evidence container
  capture     Capture live network traffic to a PCAP file inside an evidence container
  parse-pcap  Parse an existing PCAP/PCAPNG: flows, TCP streams, indicators
  verify      Re-hash a container's artifacts and check them against its signed log
  report      Re-render the human-readable summary from a container's JSON report
  help        Print this message or the help of the given subcommand(s)
```

`arachnid-core --help` prints the exit-code table too. `arachnid-core <cmd>
--help` prints the flags for one subcommand.

This page documents `arachnid-core` only. The other two modules have their own
CLIs, each fully documented on its own page rather than duplicated here:

| Binary | Commands | Page |
|---|---|---|
| `arachnid-recover` | `scan` · `carve` · `list-results` · `export` | [File Recovery](15-File-Recovery.md#cli-reference) |
| `arachnid-sanitize` | `list-devices` · `wipe` · `verify-wipe` · `cert` | [Secure Erasure](14-Secure-Erasure.md#cli-reference) |

`arachnid-cli` is the single entry point over all three: bare it opens the TUI,
and `arachnid-cli <command>` runs any command above directly. It dispatches
in-process, so exit codes are the ones the underlying command returns.

---

## Global options

Available on every subcommand, before or after it.

| Flag | Default | Meaning |
|---|---|---|
| `--log <PATH>` | stderr | operational log destination. Appended to, with ANSI colour off. Parent directories are created. **Never** the evidence log |
| `--log-level <LEVEL>` | `info` | operational log verbosity. **Overrides** `ARACHNID_LOG` |
| `--json` | off | emit machine-readable JSON on stdout instead of the human summary |
| `-h, --help` | | print help |
| `-V, --version` | | print version |

`--log-level` takes [`tracing` filter
syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html):
a bare level (`warn`, `debug`, `trace`) or per-target directives
(`arachnid_netcap=trace,warn`).

```bash
arachnid-core --log ./run.log --log-level debug collect -o ./ev
arachnid-core --json verify ./ev | jq '.problems'
```

---

## Shared container options

`collect`, `capture` and `parse-pcap` all create a container and all accept
these.

| Flag | Default | Meaning |
|---|---|---|
| `--operator <NAME>` | `<user>@<os>` | identity recorded in **every** custody record. Self-asserted; attributable only through the signing key |
| `--signing-key <PATH>` | ephemeral | Ed25519 key file: a 32-byte seed, raw **or** hex. Without it a key is generated for this run alone |
| `--dry-run` | off | run every collector and every hash, write nothing at all |

The default operator comes from `$USER`, then `$USERNAME`, then `unknown`,
suffixed with the OS: `analyst@linux`. The TUI uses the same rule, so a
container from either front end records the operator identically.

Every container run also writes a `note` record holding the full invocation, so
the log states what was asked for as well as what came back.

See [Concepts § Signing keys](02-Concepts.md#signing-keys-and-what-verification-proves)
for why `--signing-key` matters.

---

## `collect`

Collect volatile system state into a new evidence container.

```
arachnid-core collect [OPTIONS] --output <DIR>
```

| Flag | Default | Meaning |
|---|---|---|
| `-o, --output <DIR>` | *required* | directory to create for this run's container |
| `--no-hash-binaries` | off | skip hashing on-disk process images. Faster; loses image integrity data |
| `--memory-tool <PATH>` | none | external acquisition tool. **Requires** `--memory-tool-sha256` |
| `--memory-tool-sha256 <HEX>` | | expected SHA-256 of that tool |
| `--memory-arg <ARG>...` | none | extra arguments for the tool, inserted **before** the output path |

Plus the [shared container options](#shared-container-options).

### What it collects

Five collectors, in this order — the same order the TUI's checklist shows:

| Collector | Artifact | Contents |
|---|---|---|
| `processes` | `processes.json` | PID, PPID, name, full argv, exe path, exe SHA-256, user, start time, cwd, loaded modules |
| `connections` | `connections.json` | TCP/UDP over IPv4/IPv6, local and remote endpoints, state, owning PIDs, resolved process name |
| `sessions` | `sessions.json` | logged-in users: user, terminal, remote host, login time, session id, state |
| `kernel_modules` | `kernel_modules.json` | name, size, path, SHA-256, dependents |
| `persistence` | `persistence.json` | enumerated persistence locations — never modified |

Full detail per platform: [Collectors](06-Collectors.md).

### Example — routine triage

```bash
arachnid-core collect -o ./ev-host01 --operator "analyst-7"
```

```
# Arachnid Forensic — Core Triage Report

| | |
|---|---|
| Container | `848b9f935ffcfb4e757c80712b3c61a3` |
| Collected | 2026-08-28T16:19:01.581759466Z |
| Host | arch (linux/x86_64) |
| Operator | analyst-7 |
| Tool | arachnid-core 0.1.0 |
| Signing key | `4d321e81c9f87371a7cc5d5087ebe6c283d6acfc0806a76c10bef23abeb35bde` |
| Report schema | 1.0.0 |

## Summary

- Processes: **989**
- Network connections: **26**
- Listening sockets: **8**
- Connections to routable addresses: **7**
- Active sessions: **1**
- Kernel modules: **198**
- Persistence entries: **765**
…
---

Evidence container: ./ev-host01
Signing key fingerprint: 0f78aa46c953c7fda9f39a829e729b656061299a35fb1c337e960695e867ffdc
Record this fingerprint out-of-band; `verify` can only prove origin against it.
Verify with: arachnid-core verify ./ev-host01
```

### Example — attributable collection

```bash
arachnid-core collect -o ./ev-host01 \
    --operator "analyst-7" \
    --signing-key ~/.arachnid/analyst-7.key
```

### Example — fast collection

```bash
arachnid-core collect -o ./ev-host01 --no-hash-binaries
```

Hashing distinct process images is the expensive part of a collection — each
image is hashed once and cached, but on a host with thousands of processes it
still dominates. Skipping it costs you the ability to say *this `sshd` is not
the distribution's `sshd`*. Note the choice in your log.

### Example — with memory acquisition

Arachnid ships **no kernel-mode memory driver of its own**. A custom driver
would be new kernel attack surface on the very host under investigation, and it
would carry none of the review history AVML and WinPmem already have. So it
wraps an external tool — and refuses to execute one it cannot verify.

```bash
sha256sum /opt/avml
# 3f6a…c21b  /opt/avml

arachnid-core collect -o ./ev-host01 \
    --memory-tool /opt/avml \
    --memory-tool-sha256 3f6a…c21b
```

The tool is hashed **before** execution. On mismatch, the run aborts:

```
error: acquisition tool hash mismatch for /opt/avml: expected 3f6a…c21b,
       found 91d0…4e77. Refusing to execute an unverified tool.
```

On a host that may already be compromised, an acquisition binary does not get
to run just because it had the right filename.

Invocation shape is `<tool> [--memory-arg …] <output-path>`, which AVML and
WinPmem share:

```bash
arachnid-core collect -o ./ev-host01 \
    --memory-tool /opt/avml --memory-tool-sha256 3f6a…c21b \
    --memory-arg --compress
# runs: /opt/avml --compress ./ev-host01/artifacts/memory.raw
```

The image lands at `artifacts/memory.raw`, is streamed-hashed (so a
multi-gigabyte image never lands in RAM), and is sealed into the custody log.
The tool path, its verified hash, the arguments, the time window, exit code and
the last 20 lines of stderr are all recorded in the report under `memory`.

`--memory-tool` without `--memory-tool-sha256` is a **usage error** (exit 2) —
`clap` refuses it before anything runs.

### Example — dry run

```bash
arachnid-core collect -o ./ev-test --dry-run
```

Every collector runs, every hash is computed, the custody chain advances in
memory — and nothing reaches disk, including the container directory. Use it to
validate an EDR rule before a real engagement.

### Exit codes

`0` clean · `4` at least one collector was degraded · `1` the run failed
outright · `2` bad flags.

---

## `capture`

Capture live network traffic to a PCAP file inside an evidence container.

```
arachnid-core capture [OPTIONS]
```

| Flag | Default | Meaning |
|---|---|---|
| `--list-devices` | | list capture devices and exit. Conflicts with `--device` and `--output` |
| `-o, --output <DIR>` | *required unless `--list-devices`* | container directory |
| `-d, --device <NAME>` | | interface to capture on |
| `-f, --filter <BPF>` | none | BPF filter, applied **in the kernel** |
| `--duration <SECS>` | unlimited | stop after this many seconds |
| `--count <N>` | unlimited | stop after this many packets |
| `--promiscuous` | **off** | capture frames not addressed to this host |
| `--snaplen <BYTES>` | `65535` | bytes captured per frame |

Plus the [shared container options](#shared-container-options).

Requires root or `CAP_NET_RAW` on Linux, Npcap driver access on Windows.

### `--list-devices`

```bash
arachnid-core capture --list-devices
```

```
wlo1                 10.12.134.45, fe80::cb52:f967:e79:ce7
CloudflareWARP       172.16.0.2, 2606:4700:110:8fff:fd8d:78a4:ab35:4140
any
                     Pseudo-device that captures on all interfaces
lo                   127.0.0.1, ::1  [loopback]
eno1
bluetooth-monitor
                     Bluetooth Linux Monitor
nflog
                     Linux netfilter log (NFLOG) interface
```

With `--json`, an array of `{name, description, addresses, loopback}`:

```bash
arachnid-core --json capture --list-devices \
  | jq -r '.[] | select(.loopback | not) | .name'
```

If nothing is visible you get a readable explanation rather than an empty list:

```
No capture devices visible. Capture needs root/CAP_NET_RAW on Linux, Npcap on Windows.
```

### Example — bounded capture with a filter

```bash
sudo arachnid-core capture -o ./ev-net \
    --operator "analyst-7" \
    -d eth0 \
    -f "tcp port 443 and not host 10.0.0.1" \
    --duration 300
```

The filter is compiled and applied **in the kernel**, so excluded traffic is
never copied into userspace: not in the savefile, not in RAM, not in scope.
That matters when the exclusion is legally required rather than merely
convenient.

Stop conditions are checked every loop iteration and reported in
`stop_reason`: `duration elapsed`, `packet limit reached`, or
`interrupted by operator`.

### Example — capture until interrupted

```bash
sudo arachnid-core capture -o ./ev-net -d eth0
# WARN no --duration or --count: capture runs until interrupted with Ctrl-C
```

`Ctrl-C` **stops cleanly**: the handler sets a flag rather than killing the
process, so the savefile is flushed, hashed and written into the custody log.
Losing a capture to an abrupt exit would be losing evidence.

### Promiscuous mode

**Off by default**, deliberately. Enabling it changes the interface's receive
mode, which is an observable change to the host under examination. `--promiscuous`
is opt-in and recorded in the report.

### Reading the output

```
## Live capture

- Device: `eth0` (Linktype(1))
- Filter: `tcp port 443 and not host 10.0.0.1`
- Promiscuous: false
- Packets: **48210** (39847113 bytes)
- Window: 2026-08-28T16:41:02Z → 2026-08-28T16:46:02Z
- Stopped: duration elapsed
- ⚠ **Dropped 1204 (kernel) / 0 (interface) — this capture has gaps.**
```

Drops set **exit code 4** and add a custody note. A capture with drops has holes
in it, and holes in evidence must be visible. Remedies: tighten the BPF filter,
lower `--snaplen`, capture to faster storage.

`capture` writes `artifacts/capture.pcap` and does **not** analyse it. Run
`parse-pcap` on that file when you want flows and indicators.

### Exit codes

`0` clean · `4` packets were dropped · `1` device not found, no permission, no
capture library.

---

## `parse-pcap`

Parse an existing PCAP or PCAPNG: flows, TCP streams, indicators.

```
arachnid-core parse-pcap [OPTIONS] --output <DIR> <PCAP>
```

| Argument / Flag | Default | Meaning |
|---|---|---|
| `<PCAP>` | *required* | file to analyse. Opened **read-only**; never modified or copied |
| `-o, --output <DIR>` | *required* | container directory for the analysis |
| `-f, --filter <BPF>` | none | BPF filter applied while reading the savefile |
| `--max-stream-bytes <BYTES>` | `8388608` (8 MiB) | per-flow TCP reassembly ceiling |

Plus the [shared container options](#shared-container-options).

### What it extracts

- A **flow table** keyed by the 5-tuple as first observed, with packet and byte
  counts and a first/last-seen window.
- **Reassembled TCP streams**, keyed by sequence offset so retransmissions
  collapse and gaps stay visible.
- **Indicators**: `ipv4`, `ipv6`, `dns_query`, `dns_answer`, `tls_sni`,
  `http_host`, `http_uri`, `http_user_agent`.

**Nothing is resolved or enriched against any remote service.** A triage tool
that phones out about the indicators it just found leaks the investigation.

Full detail: [Network Forensics](07-Network-Forensics.md).

### Example

```bash
arachnid-core parse-pcap sample.pcap -o ./ev-pcap --operator analyst-7
```

```
## PCAP analysis

- Source: `sample.pcap`
- Source SHA-256: `ce51b95bad82ae3fa035ff637cd43145df75a9fd2ce82037a6e0d4754a7f6e02`
- Packets: **3** (382 bytes), 3 flows
- Window: 2026-01-01T00:00:00Z → 2026-01-01T00:00:02Z

### Indicators

| Kind | Value | Count |
|---|---|---|
| dns_query | cdn.update-delivery.example | 1 |
| http_host | c2.example.net | 1 |
| http_uri | /beacon?id=7f3a | 1 |
| http_user_agent | Mozilla/5.0 (compatible; Updater/1.2) | 1 |
| tls_sni | api.telemetry.example | 1 |

### Top flows by volume

| Proto | Source | Destination | Packets | Bytes |
|---|---|---|---|---|
| tcp | 192.168.1.50:44102 | 93.184.216.34:80 | 1 | 159 |
| tcp | 192.168.1.50:44100 | 93.184.216.34:443 | 1 | 136 |
| udp | 192.168.1.50:51314 | 192.168.1.1:53 | 1 | 87 |
```

The **source file's SHA-256 is recorded in the custody log**, binding the
analysis to the exact bytes analysed. The PCAP stays where it is; it is not
copied into the container.

### Example — pulling indicators out

```bash
jq -r '.indicators[]
       | select(.kind == "tls_sni" or .kind == "dns_query")
       | .value' \
   ./ev-pcap/artifacts/pcap_analysis.json | sort -u
```

```
api.telemetry.example
cdn.update-delivery.example
```

Each indicator carries a context naming the flow it came from:

```json
{
  "kind": "http_host",
  "value": "c2.example.net",
  "count": 1,
  "first_seen_utc": "2026-01-01T00:00:02Z",
  "last_seen_utc": "2026-01-01T00:00:02Z",
  "context": "192.168.1.50:44102 -> 93.184.216.34:80"
}
```

### Example — a very large capture

```bash
arachnid-core parse-pcap big.pcap -o ./ev-big \
    -f "not port 445" \
    --max-stream-bytes 2097152

jq '[.flows[] | select(.truncated)] | length' ./ev-big/artifacts/pcap_analysis.json
```

A flow that hits the ceiling is flagged `"truncated": true`, **never silently
shortened**. Indicators live in the first few KiB of a stream, so a lower cap
rarely costs you one.

### Decode errors

`decode_errors` counts frames the decoder could not parse: malformed,
truncated by `snaplen`, or a link type this build does not handle. A non-zero
count sets **exit code 4** and appears in the report. Non-IP frames (ARP, LLDP)
are *not* errors — they simply are not flows and are counted as neither.

### Exit codes

`0` clean · `4` frames failed to decode · `1` unreadable file, bad BPF filter,
no capture library.

---

## `verify`

Re-hash a container's artifacts and check them against its signed log.

```
arachnid-core verify [--json] <CONTAINER>
```

| Argument | Meaning |
|---|---|
| `<CONTAINER>` | evidence container **directory** to verify |

Implemented **independently of the collection path**: it re-reads and re-hashes
from disk rather than sharing any writer state, so a bug in collection cannot
make a broken container verify clean. A second implementation of verification is
exactly what a forensic tool must not have — and exactly what it must have for
the two paths that matter.

### Example — intact

```bash
arachnid-core verify ./ev-host01; echo "exit=$?"
```

```
container:        ./ev-host01
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

### Example — tampered

```bash
arachnid-core verify ./ev-host01; echo "exit=$?"
```

```
FAILED: 2 problem(s).
  - artifact sessions.json: content modified since collection
  - artifact sessions.json: size differs from record
exit=3
```

### Example — machine-readable

```bash
arachnid-core --json verify ./ev-host01
```

```json
{
  "container": "./ev-host01",
  "schema_version": "1.0.0",
  "public_key": "4d321e81c9f87371a7cc5d5087ebe6c283d6acfc0806a76c10bef23abeb35bde",
  "key_fingerprint": "0f78aa46c953c7fda9f39a829e729b656061299a35fb1c337e960695e867ffdc",
  "records": 11,
  "artifacts_checked": 8,
  "artifacts": [
    {
      "name": "processes.json",
      "sha256": "db2a865115beb1ec6a7cf9bd70b55d37735a6b09f241a5ecc6fe2ea22b0b36e2",
      "size": 2807935,
      "logged_utc": "2026-08-28T16:19:13.782656747Z",
      "ok": true,
      "note": null
    },
    {
      "name": "sessions.json",
      "sha256": "80303b515fcf0e01d738150c96dc819e36f175a02a6b2af9536b66307a6c347c",
      "size": 177,
      "logged_utc": "2026-08-28T16:19:13.782888613Z",
      "ok": false,
      "note": "size differs from record (170 on disk)"
    }
  ],
  "problems": [
    "artifact sessions.json: content modified since collection",
    "artifact sessions.json: size differs from record"
  ]
}
```

`artifacts[]` is one row per artifact in custody-log order, then anything on disk
the log does not account for — so a dashboard can show which file failed without
re-hashing the container itself.

### What it checks

In order, per line of `custody.log`:

1. the line has a signature separator;
2. the Ed25519 signature verifies over the bytes after the first space;
3. the record parses as JSON;
4. `seq` increments by exactly one;
5. `prev` matches the SHA-256 of the previous line's exact bytes;
6. for `artifact` records: the file exists, its SHA-256 matches, its size
   matches.

Then, across `artifacts/`: any file present on disk with no custody record is a
problem in its own right.

A manifest that parses but carries an unusable public key is reported as an
**integrity problem (exit 3)**, not a runtime error — and verification continues
without signature checks, because the hash chain and the artifact digests still
have something to say about what was changed.

Full walkthrough: [The Evidence Container § Verification](05-Evidence-Container.md#verification-step-by-step).

### Exit codes

`0` intact · `3` one or more problems · `1` the container could not be read at
all (missing `manifest.json` or `custody.log`).

---

## `report`

Re-render the human-readable summary from a container's JSON report.

```
arachnid-core report [OPTIONS] <CONTAINER>
```

| Argument / Flag | Default | Meaning |
|---|---|---|
| `<CONTAINER>` | *required* | container directory holding `artifacts/report.json` |
| `--format <FORMAT>` | `markdown` | `markdown`, `html`, or `json` |
| `-o, --output <PATH>` | stdout | write to this file instead |

```bash
arachnid-core report ./ev-host01                                # markdown to stdout
arachnid-core report ./ev-host01 --format html -o triage.html   # self-contained HTML
arachnid-core report ./ev-host01 --format json | jq .manifest   # the contract
```

`report` reads **only** `artifacts/report.json`. It never re-collects and never
touches the host. All three renderings carry the same information; nothing
exists in the Markdown or HTML that the JSON lacks, which is why they can be
regenerated at any time.

It refuses a report whose schema major version this build does not implement:

```
error: report schema 2.0.0 is not supported by this build (expected 1.x)
```

The HTML is a single self-contained file with no external assets, so it renders
on an air-gapped analysis workstation. Every field is HTML-escaped — process
command lines and hostnames are attacker-controlled input, and there is a test
asserting a `<script>` tag in a hostname cannot break out of the page.

### Exit codes

`0` rendered · `1` not a container, unreadable `report.json`, unsupported
schema major version.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | runtime error — I/O, permission, missing device, unusable input |
| `2` | usage error (bad flags) |
| `3` | integrity failure — `verify` found a problem |
| `4` | completed, but a collector was degraded, packets were dropped, or frames failed to decode |

Stable across releases. See
[Workflows § SOAR](09-Workflows.md#workflow-5--soar-and-scripted-response) for a scripted
example.

---

## Environment variables

| Variable | Read by | Effect |
|---|---|---|
| `ARACHNID_LOG` | CLI, TUI | operational log filter. **Overridden** by `--log-level` |
| `NO_COLOR` | TUI | set and non-empty ⇒ monochrome rendering |
| `XDG_STATE_HOME` | TUI | base for `arachnid/tui-state.json` |
| `APPDATA` | TUI (Windows) | base for `arachnid\tui-state.json` |
| `HOME` | TUI | fallback base: `~/.local/state/arachnid/` |
| `USER` / `USERNAME` | both | default operator identity |
| `HOSTNAME` / `COMPUTERNAME` | both | manifest `host` (falls back to `/proc/sys/kernel/hostname`) |
| `SystemRoot` | Windows | locating `System32\Npcap` for the delay-load search path |

Build-time only: `TARGET`, `PCAP_VERSION`, `PCAP_SHA256`, `BUILD_DIR`, `DIST`,
`GPG_KEY`, `SOURCE_DATE_EPOCH`, `NPCAP_SDK`, `ARACHNID_CERT_THUMBPRINT`.

---

[← Core Concepts](02-Concepts.md) · [Home](Home.md) · [Next: Terminal UI →](04-TUI-Guide.md)
