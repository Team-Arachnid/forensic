# Arachnid Forensic — Usage Guide

How to actually drive the tools. Every command and every block of output on this
page was produced by the binary in this repository at version **0.1.0**; where a
value would differ on your host (hashes, PIDs, timestamps) it is real output from
a real run, not an illustration.

For the reference-grade documentation — container format, schemas, threat model,
internals — see the [wiki](docs/wiki/Home.md).

**Shipping today:** Arachnid Core (`arachnid-core`, `arachnid-tui`) and
Arachnid Sanitize (`arachnid-sanitize`, plus screen 7 of the TUI). Recover is
not built yet; see [Planned modules](#planned-modules).

> Core is read-only against its target. **Sanitize is not** — it destroys data,
> and a wipe cannot be undone. See [Arachnid Sanitize](#arachnid-sanitize).

> Everything here assumes an authorized analyst working on a system they have
> explicit permission to examine. The tool does not enforce authorization scope.
> That is a process control, not a software one.

---

## Contents

- [Install](#install)
- [The 60-second version](#the-60-second-version)
- [`collect` — volatile system state](#collect--volatile-system-state)
- [`capture` — live packet capture](#capture--live-packet-capture)
- [`parse-pcap` — offline analysis](#parse-pcap--offline-analysis)
- [`verify` — integrity check](#verify--integrity-check)
- [`report` — re-render a summary](#report--re-render-a-summary)
- [Arachnid Sanitize](#arachnid-sanitize)
- [The terminal UI](#the-terminal-ui)
- [Signing keys](#signing-keys)
- [Exit codes and automation](#exit-codes-and-automation)
- [Logging](#logging)
- [Planned modules](#planned-modules)

---

## Install

### Build from source

```bash
git clone https://github.com/arachnid-forensic/arachnid-core.git
cd arachnid-core
cargo build --release
```

Two binaries land in `target/release/`:

| Binary | What it is |
|---|---|
| `arachnid-cli` | **the entry point.** The TUI bare; every command below with a subcommand |
| `arachnid-core` | the triage CLI on its own — collect, capture, parse-pcap, verify, report |
| `arachnid-sanitize` | **destructive.** Secure erasure on its own — see [Arachnid Sanitize](#arachnid-sanitize) |
| `arachnid-tui` | the terminal UI on its own |

`cargo build` leaves these in `target/release/`; it does **not** install them.
Put the entry point on your PATH with:

```bash
cargo install --path crates/arachnid-cli
```

Then `arachnid-cli` is the only name you need — every command in this guide also
works as `arachnid-cli <command>`. The standalone binaries stay for scripts that
name them.

> The binary names are not the crate names. `arachnid-core-cli` is a *crate*;
> typing it gets you `command not found`.

Requirements:

| | Linux | Windows |
|---|---|---|
| Toolchain | Rust stable ≥ 1.82 | Rust stable ≥ 1.82, MSVC |
| Toolchain (TUI and Sanitize) | Rust stable ≥ 1.88 | Rust stable ≥ 1.88, MSVC |
| For `capture` / `parse-pcap` | `libpcap-dev` / `libpcap-devel` | [Npcap](https://npcap.com/) + the Npcap SDK |
| Capture privilege | root, or `CAP_NET_RAW` | Npcap driver access |

`collect`, `verify` and `report` need none of that. They run unprivileged (they
just collect less, and say so), and on Windows they run with no Npcap installed
at all — `wpcap.dll` is delay-loaded.

### Verify a release binary before you run it on evidence

```bash
sha256sum -c arachnid-core-0.1.0-x86_64-unknown-linux-musl.sha256
gpg --verify arachnid-core-0.1.0-x86_64-unknown-linux-musl.asc \
             arachnid-core-0.1.0-x86_64-unknown-linux-musl
```

On Windows the release is Authenticode-signed; check it with
`signtool verify /pa arachnid-core.exe` or `Get-AuthenticodeSignature`.

---

## The 60-second version

```bash
arachnid-core collect    -o ./ev-host01 --operator "analyst-7"    # volatile state
arachnid-core capture    -o ./ev-net -d eth0 --duration 300       # live traffic
arachnid-core parse-pcap suspicious.pcap -o ./ev-pcap             # offline analysis
arachnid-core verify     ./ev-host01                              # 0 intact, 3 tampered
arachnid-core report     ./ev-host01 --format html -o triage.html # human summary

arachnid-tui                                                      # the same engine, driven from a TUI

arachnid-sanitize list-devices                                    # DESTRUCTIVE module
arachnid-sanitize wipe /dev/sdb --method dod3 --confirm-serial <S> --dry-run
```

Each of the first three creates a **new evidence container**: a directory holding
the artifacts, a manifest, and an append-only Ed25519-signed custody log. It is
read-only against the target — the only writes go to the directory you named
with `-o`.

---

## `collect` — volatile system state

```
arachnid-core collect [OPTIONS] --output <DIR>
```

| Flag | Meaning |
|---|---|
| `-o, --output <DIR>` | directory to create for this run's container (required) |
| `--operator <NAME>` | identity recorded in every custody entry. Defaults to `<user>@<os>` |
| `--signing-key <PATH>` | Ed25519 key file (32-byte seed, raw or hex). Without it, a key is generated for this run alone |
| `--dry-run` | run every collector and every hash, write nothing at all |
| `--no-hash-binaries` | skip hashing on-disk process images. Much faster; loses image integrity data |
| `--memory-tool <PATH>` | external acquisition tool — AVML on Linux, WinPmem on Windows |
| `--memory-tool-sha256 <HEX>` | expected SHA-256 of that tool. **Required** with `--memory-tool` |
| `--memory-arg <ARG>...` | extra arguments for the tool, placed before the output path |

### Example: a routine triage collection

```bash
arachnid-core collect -o ./ev-host01 --operator "analyst-7"
```

Collects, in this order: **processes** (argv, parent PID, loaded modules, SHA-256
of the on-disk image), **connections** (mapped to owning processes), **sessions**,
**kernel modules**, **persistence entries**. It prints the Markdown report to
stdout as it finishes:

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

## Active sessions

| User | Terminal | Remote host | Login |
|---|---|---|---|
| ch0udharyji | tty1 | - | 2026-08-28T21:40:20Z |

## Connections to routable addresses

| Proto | Local | Remote | State | PID | Process |
|---|---|---|---|---|---|
| tcp | 172.16.0.2:43290 | 160.79.104.10:443 | ESTABLISHED | 11519 | sshd |
| tcp | 172.16.0.2:48526 | 20.207.73.82:443 | TIME_WAIT | - | - |

…

---

Evidence container: ./ev-host01
Signing key fingerprint: 0f78aa46c953c7fda9f39a829e729b656061299a35fb1c337e960695e867ffdc
Record this fingerprint out-of-band; `verify` can only prove origin against it.
Verify with: arachnid-core verify ./ev-host01
```

What lands on disk:

```
ev-host01/
├── manifest.json            run metadata + the Ed25519 public key
├── custody.log              signed hash chain, one record per line
└── artifacts/
    ├── processes.json       connections.json    sessions.json
    ├── kernel_modules.json  persistence.json
    └── report.json  report.md  report.html
```

**Record that fingerprint.** Write it into your case notes, the ticket, a
radio call — anywhere outside the container. Without it, `verify` can prove
the container is internally consistent but not that it came from you.

### Example: validating an EDR rule before a real engagement

`--dry-run` runs every collector and computes every hash, and writes nothing —
not even the container directory:

```bash
arachnid-core collect -o ./ev-test --dry-run
ls ./ev-test
# ls: cannot access './ev-test': No such file or directory
```

Same syscalls, same file reads, same process enumeration. It is the rehearsal
you give the SOC so they can watch what the tool touches without producing
evidence you then have to account for.

### Example: acquiring memory alongside the volatile state

Arachnid ships no kernel driver of its own. It wraps an external, vetted tool —
and it will not execute one it cannot verify:

```bash
sha256sum /opt/avml
# 3f6a…c21b  /opt/avml

arachnid-core collect -o ./ev-host01 \
    --operator "analyst-7" \
    --signing-key ~/.arachnid/analyst-7.key \
    --memory-tool /opt/avml \
    --memory-tool-sha256 3f6a…c21b
```

The tool is hashed **before** it runs. A mismatch aborts the run:

```
error: acquisition tool hash mismatch for /opt/avml: expected 3f6a…c21b,
       found 91d0…4e77. Refusing to execute an unverified tool.
```

On a host that may already be compromised, a binary does not get to run just
because it had the right filename. The image lands at
`artifacts/memory.raw` and is hashed into the custody log like any other
artifact.

`--memory-arg` inserts extra arguments before the output path, for tools that
need them:

```bash
arachnid-core collect -o ./ev-host01 \
    --memory-tool /opt/avml --memory-tool-sha256 3f6a…c21b \
    --memory-arg --compress
# runs: /opt/avml --compress ./ev-host01/artifacts/memory.raw
```

### Example: a fast collection on a large host

Hashing every distinct process image is the expensive part of a collection.
On a host with thousands of processes, or when you are racing an attacker:

```bash
arachnid-core collect -o ./ev-host01 --no-hash-binaries
```

You lose the ability to say *this `sshd` is not the distribution's `sshd`*.
Use it when time matters more than image integrity, and note it in your log.

---

## `capture` — live packet capture

```
arachnid-core capture [OPTIONS]
```

| Flag | Meaning |
|---|---|
| `--list-devices` | list capture devices and exit |
| `-o, --output <DIR>` | container directory (required unless `--list-devices`) |
| `-d, --device <NAME>` | interface to capture on |
| `-f, --filter <BPF>` | BPF filter, applied **in the kernel** |
| `--duration <SECS>` | stop after this many seconds |
| `--count <N>` | stop after this many packets |
| `--promiscuous` | capture frames not addressed to this host. **Off by default** |
| `--snaplen <BYTES>` | bytes captured per frame (default `65535`) |

Plus the shared container flags: `--operator`, `--signing-key`, `--dry-run`.

Needs root or `CAP_NET_RAW` on Linux, Npcap driver access on Windows.

### Example: find an interface

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
```

Machine-readable, for a playbook that has to pick one:

```bash
arachnid-core --json capture --list-devices | jq -r '.[] | select(.loopback|not) | .name'
```

### Example: a bounded capture with a filter

```bash
sudo arachnid-core capture -o ./ev-net \
    --operator "analyst-7" \
    -d eth0 \
    -f "tcp port 443 and not host 10.0.0.1" \
    --duration 300
```

The filter is compiled and applied in the kernel, so traffic you excluded is
never copied into userspace — it is not in the savefile, not in RAM, and not
in scope. That matters when the exclusion is legally required rather than
merely convenient.

**Promiscuous mode is off by default.** Enabling it changes the interface's
receive mode, which is an observable change to the host under examination.
`--promiscuous` is opt-in, deliberately.

### Example: capture until you stop it

With neither `--duration` nor `--count`, the capture runs until interrupted,
and warns you that it will:

```bash
sudo arachnid-core capture -o ./ev-net -d eth0
# WARN no --duration or --count: capture runs until interrupted with Ctrl-C
```

`Ctrl-C` stops it **cleanly**: the interrupt sets a flag rather than killing the
process, so the savefile is flushed, hashed, and written into the custody log.
An abrupt exit would be losing evidence.

### Reading the result

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

Drops are surfaced prominently and set exit code **4**. A capture with drops has
holes in it, and holes in evidence must be visible, not buried. If you see them:
tighten the BPF filter, lower `--snaplen`, or capture to faster storage.

`capture` writes `artifacts/capture.pcap` and does **not** analyse it. Run
`parse-pcap` on the container's savefile when you want flows and indicators.

---

## `parse-pcap` — offline analysis

```
arachnid-core parse-pcap [OPTIONS] --output <DIR> <PCAP>
```

| Flag | Meaning |
|---|---|
| `<PCAP>` | PCAP or PCAPNG file to analyse. Opened read-only |
| `-o, --output <DIR>` | container directory for the analysis (required) |
| `-f, --filter <BPF>` | BPF filter applied while reading the savefile |
| `--max-stream-bytes <BYTES>` | per-flow TCP reassembly ceiling (default `8388608`) |

Plus `--operator`, `--signing-key`, `--dry-run`.

Builds a flow table, reassembles TCP streams, and extracts indicators: IPv4/IPv6
addresses, DNS queries and answers, TLS SNI, HTTP hosts, URIs and User-Agents.
**Nothing is resolved or enriched against any remote service.** A triage tool
that phones out about the indicators it just found leaks the investigation.

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
analysis to the exact bytes analysed. The PCAP itself stays where it is; it is
not copied into the container.

### Example: pull the indicators out for a pivot

The full analysis is in `artifacts/pcap_analysis.json`:

```bash
jq -r '.indicators[] | select(.kind=="tls_sni" or .kind=="dns_query") | .value' \
    ./ev-pcap/artifacts/pcap_analysis.json | sort -u
```

```
api.telemetry.example
cdn.update-delivery.example
```

Each indicator carries `count`, `first_seen_utc`, `last_seen_utc` and a
`context` naming the flow it came from:

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

### Example: analysing a huge capture

Reassembly is capped per flow so a multi-gigabyte download does not land in RAM.
A flow that hits the cap is flagged `"truncated": true` — never silently
shortened:

```bash
arachnid-core parse-pcap big.pcap -o ./ev-big \
    -f "not port 445" \
    --max-stream-bytes 2097152      # 2 MiB per flow

jq '[.flows[] | select(.truncated)] | length' ./ev-big/artifacts/pcap_analysis.json
```

Indicators live in the first few KiB of a stream, so a lower cap rarely costs
you one. Raise it when you need more of a payload reconstructed.

---

## `verify` — integrity check

```
arachnid-core verify [--json] <CONTAINER>
```

Re-hashes every artifact, re-checks every Ed25519 signature, and walks the
custody hash chain. It is implemented **independently of the collection path**,
so a bug in collection cannot make a broken container verify clean.

### Example: an intact container

```bash
arachnid-core verify ./ev-host01
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
```

Exit code **0**.

### Example: a tampered container

Someone edited one field in `sessions.json`:

```bash
arachnid-core verify ./ev-host01
```

```
container:        ./ev-host01
schema:           1.0.0
signing key:      4d321e81c9f87371a7cc5d5087ebe6c283d6acfc0806a76c10bef23abeb35bde
key fingerprint:  0f78aa46c953c7fda9f39a829e729b656061299a35fb1c337e960695e867ffdc
custody records:  11
artifacts hashed: 8

FAILED: 2 problem(s).
  - artifact sessions.json: content modified since collection
  - artifact sessions.json: size differs from record
```

Exit code **3**.

Four kinds of tampering, four independent detections:

| What was done | Caught by |
|---|---|
| An artifact was edited | its recorded SHA-256 no longer matches |
| A custody record was edited | that line's Ed25519 signature no longer verifies |
| A record was deleted or reordered | the `prev` hash chain breaks |
| A file was planted in `artifacts/` | present on disk with no custody record |

### Example: verification in a script

```bash
arachnid-core --json verify ./ev-host01 > verify.json
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

`artifacts[]` gives you a row per file, so a dashboard can show which one failed
without re-hashing the container itself.

**The limitation, stated plainly:** without `--signing-key`, the key is generated
per run. Anyone who can rewrite the whole container can also swap the key and
re-sign everything, and `verify` will then say VERIFIED. It proves *integrity*
always, and *origin* only when the key fingerprint matches one you recorded
out-of-band. For chain of custody that must survive challenge, use a persistent
key — see [Signing keys](#signing-keys).

---

## `report` — re-render a summary

```
arachnid-core report [--format markdown|html|json] [-o <PATH>] <CONTAINER>
```

Re-renders `artifacts/report.json` — the contract — into a human format. All
three renderings carry the same information; nothing exists in the Markdown or
HTML that is not in the JSON.

```bash
arachnid-core report ./ev-host01                                # markdown to stdout
arachnid-core report ./ev-host01 --format html -o triage.html   # self-contained HTML
arachnid-core report ./ev-host01 --format json | jq .manifest   # the raw contract
```

The HTML is a single self-contained file with no external assets, so it renders
on an air-gapped analysis workstation. Every field in it is HTML-escaped —
process command lines and hostnames are attacker-controlled input, and there is
a test asserting a `<script>` tag in a hostname cannot break out of the page.

`report` reads only `artifacts/report.json`; it never re-collects. It refuses a
report whose schema major version this build does not implement.

---

## Arachnid Sanitize

> **This tool destroys data.** Every other command in this guide is read-only
> against its target. `arachnid-sanitize` exists to make a device unreadable, and
> a wipe cannot be undone. Use `--dry-run` first, every time.

Full reference, including the compliance mapping and every safety rail:
[the wiki's Secure Erasure chapter](docs/wiki/14-Secure-Erasure.md).

### Quick reference

| Command | Purpose |
|---|---|
| `arachnid-sanitize list-devices` | enumerate attached storage, flagging any that host the running OS |
| `arachnid-sanitize wipe` | irreversibly erase **one** device |
| `arachnid-sanitize verify-wipe` | re-read a device and check it against an expected pattern |
| `arachnid-sanitize cert` | print or verify erasure certificates |

Requires Administrator / root for raw device access. Enumeration degrades
gracefully without it.

### Two caveats you must read before claiming compliance

**This build issues no hardware sanitize command.** `--method nist-purge` probes
the device, reports which command *would* apply, then runs a 3-pass software
overwrite — and the certificate says so, so the claim cannot be read as
Purge-grade. Assess it against NIST 800-88 **Clear**.

**Crypto-erase is refused on every device**, because confirming a working
self-encrypting drive needs the same pass-through I/O this build does not
implement. Claiming an unverifiable crypto-erase is the most dangerous false
statement the tool could make.

Also: on SSDs, wear levelling means an overwrite cannot guarantee every physical
cell is reached. That is a property of the media. For flash leaving your
organization, physical destruction or the vendor's own utility remains the
defensible path.

### Example: see what is attached

```bash
arachnid-sanitize list-devices
```

```
PATH                   MODEL                      SERIAL                     SIZE  BUS      FLAGS
/dev/nvme0n1           SAMSUNG MZVL41T0HBLB-00BH1 S6B7NX0X602424        953.9 GiB  NVMe
/dev/sda               Elements SE SSD            23315C401334          931.5 GiB  USB      SYSTEM
                       └─ backs a filesystem the running OS has mounted

Devices flagged SYSTEM host the running operating system and are refused by
`wipe` unless --force-system-volume is passed.
```

The `SERIAL` column is what `--confirm-serial` must match, character for
character.

### Example: the dry run (writes nothing)

```bash
arachnid-sanitize wipe /dev/sdb \
    --method dod3 \
    --confirm-serial S4EVNF0M123456 \
    --dry-run
```

Every safety rail runs, the method is resolved, the estimate is produced, and
**zero bytes are written**. This is the rehearsal that catches a wrong serial or
a wrong path before it costs you a drive.

### Example: a safety rail refusing

A mistyped serial, which is the mistake the rail exists for:

```bash
arachnid-sanitize wipe /dev/nvme0n1 \
    --method nist-clear \
    --confirm-serial DEFINITELY-NOT-THE-SERIAL \
    --dry-run
```

```
REFUSED: serial confirmation failed: you typed "DEFINITELY-NOT-THE-SERIAL",
the selected device reports "S6B7NX0X602424". Nothing was written.
```

Exit code **3** — refused by a rail, nothing written. Serial matching is
**case-sensitive**: folding case would let `abc123` confirm a wipe of the drive
labelled `ABC123`, and hosts exist with both.

The other rails, all of which refuse before a byte is written:

| Rail | Refuses when |
|---|---|
| System-volume block | the device backs the running OS. Override: `--force-system-volume`, and it is recorded on the certificate |
| No serial, no wipe | the device reports no serial at all — common on USB bridges |
| Re-enumeration | the device at that path is no longer the one selected |
| No bulk select | there is no verb that takes more than one device |
| Cooldown | a 3-second countdown precedes the first write |

### Example: the real thing

```bash
sudo arachnid-sanitize wipe /dev/sdb \
    --method dod3 \
    --confirm-serial S4EVNF0M123456 \
    --operator "tech-4" \
    --signing-key ~/.arachnid/tech-4.key \
    --cert-dir /srv/disposal/certs
```

Methods: `nist-clear` (1 pass), `nist-purge` (3, software), `dod3` (3), `dod7`
(7), `crypto-erase` (refused). **There is no default** — the choice changes what
standard the certificate can claim, so it must be explicit.

`Ctrl-C` cancels, leaving the device partially overwritten and **uncertified**.

### Example: reading the exit code as a disposition

| Exit | Means | Do |
|---|---|---|
| `0` | erased, verified, certified | release the drive |
| `3` | refused by a rail — **nothing written** | resolve and retry |
| `4` | wipe ran, **verification failed** | data may survive — destroy physically |
| `5` | completed with **unwritable regions** | drive is failing — destroy physically |

Codes 4 and 5 are not successes. Neither should let a drive into the resale pile.

### Example: certificates

Issued only for a wipe that **completed and verified** — a dry run, a cancelled
wipe, an unwritable region or a failed verification all block issuance.

```bash
arachnid-sanitize cert --cert-dir /srv/disposal/certs --verify
```

```
3 certificate(s) in /srv/disposal/certs/certificates.log
  ccf8c85e…  /dev/sdb  signature ok  chain ok
  a1f09b22…  /dev/sdc  signature ok  chain ok
  7e3d0c41…  /dev/sdd  signature ok  chain ok

VERIFIED: every certificate is intact and correctly chained.
```

Render one for the file:

```bash
arachnid-sanitize cert --id ccf8c85e… --format html -o cert.html
```

Two fields an auditor should read first:

- **`method_detail`** — plainly states whether a hardware purge ran or a software
  overwrite stood in for one.
- **`forced_system_volume`** — whether the system-volume block was overridden.

The register is a hash chain using the same construction as the evidence
container's custody log: removing a certificate breaks the chain, editing one
breaks its signature. The same `--signing-key` caveat applies — without a
persistent key it proves integrity, not origin.

### A note for your SOC

At the syscall level `arachnid-sanitize` is deliberately indistinguishable from
disk-wiping wiper malware, because it is doing the same thing for an authorized
reason. **Treat it as a separate allowlisting decision from `arachnid-core`.**
Many sites will want it allowed on dedicated disposal workstations only — or not
at all, preferring to alert on it and confirm out of band. See
[`docs/SOC-ALLOWLISTING.md` §4a](docs/SOC-ALLOWLISTING.md).

---

## The terminal UI

```bash
arachnid-tui           # or: cargo run -p arachnid-core-tui
```

The TUI drives the same library crates the CLI does. It never shells out to
`arachnid-core`, and it can do nothing the CLI cannot: a container written by
the TUI verifies with the CLI and validates against the same schemas.

On launch it shows the wordmark while it probes the host — effective privilege,
whether a capture device is reachable — then drops into the dashboard. A failed
probe becomes a warning banner, never a refusal to start: an unprivileged
operator can still verify and report on a container collected elsewhere.

```
 arachnid  1:Dashboard  2:Collect  3:Capture  4:Parse PCAP  5:Verify  6:Report  7:Sanitize
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
   Sanitize    securely erase a device — destroys data
 no startup warnings; every check passed
 ? this help  ·  j/k move  ·  Enter open  ·  Tab next screen  ·  1-7 jump …
```

### Keys

Global, from anywhere:

| Key | Does |
|---|---|
| `Tab` / `Shift-Tab` | next / previous screen |
| `1`–`7` | jump straight to a screen |
| `?` | list every binding |
| `Ctrl-L` | toggle the operational log pane |
| `Esc` | back out / dismiss |
| `q` | quit |

Per screen:

| Screen | Keys |
|---|---|
| **1 Dashboard** | `j`/`k` move · `Enter` open |
| **2 Collect** | `j`/`k` field · `Enter` edit / toggle · `r` run collection |
| **3 Capture** | `j`/`k` field · `h`/`l` device · `Enter` edit / toggle · `s` start / stop |
| **4 Parse PCAP** | `j`/`k` field or row · `Enter` edit / analyse · `h`/`l` flows ↔ indicators · `e` export to container |
| **5 Verify** | `j`/`k` row · `h`/`l` recent container · `Enter` edit path · `v` verify · `c` chain of custody |
| **6 Report** | `j`/`k` field · `Enter` edit / cycle format · `o` open container · `x` export · `c` chain of custody |
| **7 Sanitize** | `j`/`k` select · `Enter` next step · `Esc` back a step · `r` re-enumerate · `f` allow system disk · `d` dry run · `x` cancel job · **`Shift-W` commit the wipe** |
| **Chain of custody** | `j`/`k` record · `g`/`G` first / last · `Esc` back |

`?` is generated from the same keymap table that dispatches the keys, so a
binding cannot appear in the help without working, or work without appearing.

### Editing fields

Fields have an **explicit edit mode**, so a path containing `q` can actually be
typed: `Enter` enters the field, `Esc` or `Enter` leaves it. While editing,
global bindings stand down. `Ctrl-U` clears the field.

### Behaviour worth knowing

- **Capture keeps running while you navigate.** It is a background thread; the
  header shows `[capturing]` from every screen.
- **Live capture figures are counters only** — packets and bytes. Decoding
  frames to fill a table would put per-frame work in the capture loop, which is
  how a capture falls behind the link and drops evidence. The flow and protocol
  breakdown come from a read-only re-read of the savefile once it is sealed.
- **Anything that starts, replaces or stops evidence collection asks first** —
  quitting mid-capture included. Confirming there sets the stop flag, so the
  savefile is flushed and sealed rather than lost.
- **One job at a time.** Starting a second collection while one runs is refused
  with a toast; two concurrent runs would mean two containers with interleaved
  custody timestamps.
- **The Sanitize screen's commit key is `Shift-W`**, deliberately not `Enter`
  and not `y` — a wipe must not be clearable by the reflex that clears an
  ordinary confirmation. It is *rejected*, not ignored, until the 3-second
  cooldown elapses.
- **`NO_COLOR` is respected**, and every verdict is stated in text as well as
  colour, so nothing is lost in a monochrome terminal.
- **Layout degrades rather than breaks** down to 32×8: the tab strip collapses
  to a position indicator, cards lose their borders, tables truncate with a
  `… n more` marker. Below that it says `terminal too small / needs 32x8`.
- **A panic hook restores the terminal** — raw mode off, alternate screen left —
  before the panic prints, so a crash cannot leave your shell unusable.

### What the TUI does not expose

The TUI covers the common path. These CLI options have no field on any screen —
use `arachnid-core` for them:

`--memory-tool` / `--memory-tool-sha256` / `--memory-arg` · `--dry-run`
(Core; the Sanitize screen has its own `d` toggle) · `--no-hash-binaries` ·
`--duration` · `--count` · `--snaplen` · `--max-stream-bytes` ·
`--log` / `--log-level` · every `arachnid-sanitize` flag outside the wipe flow
(`verify-wipe`, `cert`, `--quick-verify`, `--no-countdown`, `--cert-dir`)

### Remembered state

The TUI remembers the operator name and recent paths in
`$XDG_STATE_HOME/arachnid/tui-state.json` (`%APPDATA%\arachnid\tui-state.json`
on Windows; `~/.local/state/arachnid/` if `XDG_STATE_HOME` is unset). That file
is a convenience, never evidence. Deleting it costs two retyped paths.

---

## Signing keys

Without `--signing-key`, every run generates a throwaway key. That is fine for a
lab and wrong for anything that has to hold up later.

### Issue a responder a persistent key

The key file is a 32-byte Ed25519 seed, **raw or hex** — both are accepted:

```bash
mkdir -p ~/.arachnid && chmod 700 ~/.arachnid
head -c 32 /dev/urandom > ~/.arachnid/analyst-7.key
chmod 600 ~/.arachnid/analyst-7.key
```

Windows PowerShell:

```powershell
$b = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
[IO.File]::WriteAllBytes("$env:USERPROFILE\.arachnid\analyst-7.key", $b)
```

### Record the fingerprint once

```bash
arachnid-core collect -o /tmp/keycheck --signing-key ~/.arachnid/analyst-7.key | tail -3
# Signing key fingerprint: 6e5cbdeecd531dc9b69681ac71b890c6e5338b0dd9664823626c6f9c03d827c7
```

The fingerprint is stable across every run with that key. Put it in the case
management system, the responder's badge record, a signed team roster — anywhere
an adversary who rewrites a container cannot also rewrite. From then on:

```bash
arachnid-core collect -o ./ev-host01 --signing-key ~/.arachnid/analyst-7.key
```

and a later `verify` that prints that same fingerprint is evidence of **origin**,
not just of integrity.

Treat the key file like any other credential: it is the whole of the attribution
claim. Do not ship it to the host you are examining if you can avoid it, and
rotate it if a responder's kit is lost.

---

## Exit codes and automation

Stable across releases, for SOAR playbooks and IR scripts:

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | runtime error — I/O, permission, missing device, unusable input |
| `2` | usage error (bad flags) |
| `3` | integrity failure — `verify` found a problem |
| `4` | completed, but a collector was degraded; see `warnings` in the report |

**Code 4 is the interesting one.** You *have* evidence, and it is incomplete.
The report says exactly which collectors fell short and why. Never treat it as
success and never treat it as failure:

```bash
#!/usr/bin/env bash
set -uo pipefail

arachnid-core --json collect -o "$OUT" \
    --operator "$RESPONDER" --signing-key "$KEYFILE" > collect.json
case $? in
  0) echo "collection complete" ;;
  4) echo "PARTIAL — gaps recorded:"
     jq -r '.collection.warnings[]' collect.json ;;
  *) echo "collection failed"; exit 1 ;;
esac

arachnid-core verify "$OUT"
[ $? -eq 3 ] && { echo "INTEGRITY FAILURE — do not use this container"; exit 3; }
```

`--json` turns stdout into machine-readable output for `collect`, `capture`,
`parse-pcap` and `verify`. (`report` picks its own rendering with
`--format json`; `--json` does nothing there.) The Markdown summary goes to
stdout only in human mode, and the operational log goes to stderr or `--log`, so
the two never interleave.

---

## Logging

The operational log (`tracing`) is strictly separate from the evidence log. The
evidence log lives in the container and is signed; the operational log is a
debugging aid and is never written there.

```bash
arachnid-core --log ./run.log --log-level debug collect -o ./ev-host01
```

- Default destination is **stderr**; `--log <path>` appends to a file instead
  (with ANSI colour off).
- Verbosity comes from `--log-level`, which **takes precedence** over the
  `ARACHNID_LOG` environment variable. Both take
  [`tracing` filter syntax](https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html):
  `info`, `debug`, `arachnid_netcap=trace,warn`.
- Default level is `info`.

In the TUI, `ARACHNID_LOG` sets the level and the log goes to the in-app pane
(`Ctrl-L`), capped at the last 1000 lines.

---

## Planned modules

The suite is specified with more modules than are built. To keep this document
honest, they are listed rather than illustrated:

| Module | Status |
|---|---|
| **Arachnid Core** | shipping — `arachnid-core`, `arachnid-tui` |
| **Arachnid Sanitize** | shipping — `arachnid-sanitize`, and screen 7 of the TUI |
| **Arachnid Recover** | not built. Consumes Core's evidence containers directly; recovers what anti-forensics removed before collection |

Recover has no binary yet. When it lands, its usage goes here with real output,
the same as everything above.

---

## Where to go next

| You want | Read |
|---|---|
| Full reference documentation | [the wiki](docs/wiki/Home.md) |
| The container format, byte by byte | [Evidence Container](docs/wiki/05-Evidence-Container.md) |
| What Arachnid does and does not defend against | [Threat Model](docs/wiki/10-Security-and-Threat-Model.md) |
| To pre-approve the binary in your EDR | [SOC Allowlisting](docs/SOC-ALLOWLISTING.md) |
| To consume the output from another tool | [Reports and Schemas](docs/wiki/08-Reports-and-Schemas.md) |
| To securely erase a drive | [Secure Erasure](docs/wiki/14-Secure-Erasure.md) |
| Something went wrong | [Troubleshooting](docs/wiki/12-Troubleshooting.md) |

---

## Notes for maintainers

- Drift between this document and real `--help` output is a **bug**. Every
  example here was run against the binary; re-run them when flags change.
- Do not document a module that does not exist, and do not leave a shipped one
  undocumented. An earlier revision of this file documented `arachnid-sanitize`
  subcommands, `--interface`/`--input` flags and `.arc` container *files* that
  were never real; the revision after it claimed Sanitize did not exist while it
  was shipping. Both cost a responder more than a missing page does.
- For Sanitize specifically: never soften the two caveats. This build issues no
  hardware sanitize command and refuses crypto-erase outright, and a reader who
  misses that may file a Clear-grade wipe as a Purge.
