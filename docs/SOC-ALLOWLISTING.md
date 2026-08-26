---
# Empty on purpose: Jekyll only renders a file that carries a front-matter
# block, and the layout comes from the defaults in _config.yml.
---
# SOC Allowlisting Guide — Arachnid Core

**Audience:** the SOC, detection engineering, or EDR administration team being
asked to allow this binary to run on managed endpoints.

Arachnid Core is a DFIR triage tool. It runs with high privilege on hosts that
may be actively compromised, and it does things that look like reconnaissance —
enumerating processes, reading persistence locations, capturing packets. That
resemblance is real, and the honest answer to it is disclosure, not evasion.

This document tells you exactly what the binary touches so you can write a
narrow allow rule instead of a broad one. Nothing here is marketing: if a
behaviour is not on this page, it is a bug, and we want the report.

> **Three binaries, two decisions.** `arachnid-core`, `arachnid-recover` and
> `arachnid-tui` are read-only against the target — `arachnid-recover` opens raw
> devices, but read-only, and cannot write to one (see
> [§4b](#4b-arachnid-recover-raw-device-reads)). `arachnid-sanitize` **destroys
> data on raw block devices** and should be assessed separately — see
> [§4a](#4a-arachnid-sanitize-raw-device-writes). Allowlisting the read-only
> tools does not imply allowlisting the destructive one, and for most sites it
> should not.

---

## 1. Identity

Verify before allowlisting. Do not allowlist by filename or path.

| Field | Value |
|---|---|
| Product | Arachnid Core (Arachnid Forensic suite) |
| Binary | `arachnid-core` / `arachnid-core.exe` |
| Version | 0.1.0 |
| Linux signature | detached GPG, `.asc` alongside the binary |
| Windows signature | Authenticode, SHA-256, RFC 3161 timestamped |

**Release hashes** are published in `dist/*.sha256` with each release and
mirrored here at tag time. Prefer allowlisting by **code-signing certificate**
(Windows) or **GPG key** (Linux) over by hash, so patch releases do not require
a new rule. Allowlist by hash only if your tooling cannot do publisher rules.

```
# 0.1.0 — fill in at release tag time from dist/*.sha256
x86_64-unknown-linux-musl   <sha256>
x86_64-pc-windows-msvc      <sha256>
```

Builds are reproducible: `SOURCE_DATE_EPOCH` and `--remap-path-prefix` are set
in `scripts/build-release.sh`, so you can rebuild from the tagged commit and
confirm the hash matches the source you reviewed. That is the strongest check
available and we encourage it.

---

## 2. What it is not

These are hard design constraints, enforced in review and in `deny.toml`.
Arachnid Core contains **no**:

- anti-EDR, anti-AV, anti-debugging, or sandbox-detection logic
- packing, binary encryption, or runtime obfuscation
- dynamic code loading, self-modification, or reflective loading. `libloading`
  and `dlopen` are denied at the dependency level; the two build scripts that
  use `libloading` (bindgen's libclang probe, and pcap's `wpcap.dll` probe) run
  on the build host only and are explicitly whitelisted as build-time in
  `deny.toml`. On Windows, `wpcap.dll` is a normal import-library link, not a
  runtime `LoadLibrary` of attacker-reachable code
- process injection, hooking, or memory writes into other processes
- exploit or privilege-escalation code — it uses the privilege it was given
- persistence for itself: it installs no service, task, key, or unit
- telemetry, analytics, usage reporting, crash reporting, or any endpoint that
  receives data from you. There is nowhere for such data to go: this project
  operates no server
- packet injection or interception — capture is receive-only

`arachnid-core`, `arachnid-recover` and `arachnid-sanitize` additionally make
**no outbound network connections of any kind**. `arachnid-cli` makes exactly
one — a daily version check, on interactive terminals only, which installs
nothing and is disabled by a flag or an environment variable. It is specified in
full in [§5a](#5a-the-update-check-arachnid-cli-only). `reqwest` and `hyper`
remain denied at the dependency level.

The binary is deliberately inspectable: `strings`, `sigcheck`, and a
disassembler all work on it, and the release script **fails the build** if the
subcommand names are not visible to `strings`. If your analysts want to read it
before approving it, that is the intended workflow.

If a future feature would require any of the above, the design is out of scope
and gets flagged rather than implemented.

---

## 3. Process behaviour

| Behaviour | Detail |
|---|---|
| Child processes | **None**, except the memory acquisition tool *you* specify via `--memory-tool`. Arachnid verifies that tool's SHA-256 against a hash you supply and refuses to execute it on mismatch. |
| Process access | `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION \| PROCESS_VM_READ` for module enumeration (Windows). Read-only. Failures are tolerated, not retried with escalated rights. |
| Memory writes | None into any other process, ever. |
| Threads | Single-threaded collection. No remote thread creation. |
| Privilege | Uses the token it is launched with. Never adjusts, impersonates, or escalates. Capture needs root/`CAP_NET_RAW` (Linux) or Npcap driver access (Windows); everything else degrades gracefully without it. |

Expected parent process is a shell, an EDR live-response session, or a SOAR
runner. `arachnid-core` spawning anything other than your named acquisition
tool is worth an alert.

---

## 4. Filesystem behaviour

### Writes

**Only inside the evidence container directory given by `-o/--output`**, plus
the operational log path if you pass `--log`. There are no temp files, no
scratch directories, no config files, and no writes to any system location.

```
<container>/manifest.json
<container>/custody.log
<container>/artifacts/*
```

`--dry-run` performs every collection and every hash but writes nothing at all,
including not creating the container directory. Use it to validate a rule.

> **`arachnid-sanitize` is the exception, and it is a large one.** Everything
> above describes `arachnid-core`. The suite's erasure module writes directly
> to raw block devices and is covered in [§4a](#4a-arachnid-sanitize-raw-device-writes)
> below. If you are allowlisting the suite, read that section — a rule scoped to
> `arachnid-core` does not describe it.
>
> `arachnid-recover` also touches raw devices, but only to **read** them, and it
> writes far more output than `arachnid-core` does. See
> [§4b](#4b-arachnid-recover-raw-device-reads).

---

## 4a. `arachnid-sanitize`: raw device writes

`arachnid-sanitize` destroys data by design. Its behaviour is deliberately
indistinguishable, at the syscall level, from a disk-wiping wiper-malware
sample, because it is doing the same thing for an authorized reason.

**Treat it as a separate allowlisting decision from `arachnid-core`.** Many
sites will want it allowlisted on dedicated disposal workstations only, or not
at all.

### What it does that will trip EDR

| Behaviour | Detail |
|---|---|
| Raw device handles | Opens `\\.\PhysicalDriveN` / `/dev/sdX` for **write**, with `FILE_FLAG_WRITE_THROUGH` / `O_SYNC`. |
| Bulk sequential overwrite | 4 MiB chunks, whole-device, 1–7 passes depending on method. |
| Device enumeration | `IOCTL_STORAGE_QUERY_PROPERTY`, `IOCTL_DISK_GET_LENGTH_INFO`, `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` per drive letter (Windows); `/sys/block/**`, `/proc/mounts` (Linux). All read-only. |
| Requires elevation | Administrator / root. Enumeration alone degrades gracefully without it. |

### What it does not do

- No network access of any kind — no remote trigger, no reporting home.
- No scheduling, no persistence, no service installation. Every wipe is
  operator-initiated and confirmed in the same session.
- No self-deletion, no log clearing, no attempt to hide the operation.
- No writes outside the named device and the certificate directory.

### File writes

```
<cert-dir>/certificates.log            append-only, Ed25519-signed register
<cert-dir>/erasure-<id>.{md,html}      only on explicit export
```

### Detection guidance

Rather than allowlisting broadly, prefer **alerting on it and confirming out of
band**. A genuine `arachnid-sanitize` run is a planned, ticketed event; an
unplanned one is exactly the incident you want the alert for. The binary is
code-signed and its subcommand names are visible to `strings` (the release
build fails otherwise), so identity is checkable.

`--dry-run` exercises enumeration, method selection and every safety rail while
writing **zero bytes** to the device. Use it to validate a rule without
destroying media; it is asserted by test, not by inspection.

The `--log` operational log records the device path, serial, method, pass count
and outcome of every run, and the certificate register is an independent,
tamper-evident record of every *completed* wipe. Between them, "what did this
tool erase and when" is answerable after the fact.

---

### Reads

Linux:

```
/proc/<pid>/{stat,cmdline,exe,cwd,maps,status}   process state
/proc/net/{tcp,tcp6,udp,udp6}, /proc/<pid>/fd/   sockets to owning PID
/proc/modules, /proc/sys/kernel/osrelease        loaded kernel modules
/lib/modules/<release>/**                        module images, for hashing
/var/run/utmp, /run/utmp                         login sessions
/etc/systemd/system, /run/systemd/system,
  /usr/lib/systemd/system, /lib/systemd/system,
  /etc/systemd/user, /usr/lib/systemd/user       unit files
/etc/crontab, /etc/cron.d, /etc/cron.{hourly,
  daily,weekly,monthly}, /var/spool/cron[/crontabs]
/etc/xdg/autostart, /home/*/.config/autostart,
  /root/.config/autostart                        desktop autostart
/etc/rc.local, /etc/rc.d/rc.local
<any process exe path>                           binary hashing (--no-hash-binaries disables)
```

Windows:

```
HKLM\ and HKCU\ Software\Microsoft\Windows\CurrentVersion\Run
  ...\RunOnce, ...\RunServices, ...\RunServicesOnce
  ...\Policies\Explorer\Run
HKLM\...\Windows NT\CurrentVersion\Winlogon
HKLM\Software\Wow6432Node\...\Run
%SystemRoot%\System32\Tasks\**                   scheduled task XML
%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp\*
%SystemDrive%\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*
%SystemRoot%\System32\drivers\*.sys              driver images, for hashing
<any process image path>                         binary hashing
```

**All registry access is `KEY_READ`.** No key or value is created, modified, or
deleted. No scheduled task is registered or removed. No unit is enabled or
disabled. Arachnid enumerates persistence; it never touches it.

---

## 4b. `arachnid-recover`: raw device reads

`arachnid-recover` recovers deleted files from a disk image or an attached
device. It is **read-only against its source**, and unlike Sanitize that is a
property of the code rather than a policy: the trait every parser and the carver
read through has no write method, and device handles are opened `.read(true)`
and never `.write(true)`. The kernel refuses a write even if one were issued.

It is nevertheless worth a rule of its own, because two of its behaviours look
unusual on an endpoint.

### What it does that may trip EDR

| Behaviour | Detail |
|---|---|
| Raw device open, read-only | `\\.\PhysicalDriveN` / `/dev/sdX` opened for reading. Needs Administrator or root. No `IOCTL_DISK_*` write ioctl is ever issued |
| Bulk sequential reads | 4 MiB chunks, potentially across the whole device, during a carving pass. Sustained full-device read is the signature; it resembles a backup agent or a disk imager, because that is what it is doing |
| Device enumeration | the same read-only enumeration `arachnid-sanitize list-devices` performs, and the same code |
| High-volume file creation | an export writes one file per recovered result into the output directory, plus a `custody.log` it appends to and `fsync`s after every record |

### What it does not do

No writes to the source device, at any point, by any code path. No network. No
process spawning. No registry writes. No decryption, key recovery, password
guessing or brute force — encrypted files are reported as encrypted and left
alone. No persistence, no privilege escalation, no code loading.

### File writes

All under the `--output` directory the operator names: `results.json`,
`summary.txt`, and — on export — an evidence container in exactly the format
[§4](#4-filesystem-behaviour) describes, with `manifest.json`, an append-only
`custody.log`, and the recovered files under `artifacts/`.

Filenames under `artifacts/recovered/` derive from the **filesystem under
examination**, which on a compromised host is attacker-controlled. Every path
component is reduced before it becomes a path — `..`, absolute roots, drive
prefixes, NUL bytes, control characters and reserved device names are all
neutralized — so a recovered file cannot be written outside the output
directory. Expect ordinary-looking user filenames there; expect them to be
sanitized, not trusted.

### Detection guidance

A sustained full-device read plus a burst of file creation is the shape. Scope a
rule to that pair rather than to the device open alone, which by itself is
indistinguishable from any backup or imaging tool.

Recover **refuses to write its output onto the device it is reading** — on Linux
this is proven from `/proc/mounts` and refused outright, elsewhere it warns.
That refusal is worth surfacing if you log the tool's stderr: it means an
operator pointed the output at the wrong volume.

The `--log` operational log records the source, the passes run and the outcome
of every scan, and an export's custody log is an independent tamper-evident
record of every file written. "What did this tool read and what did it produce"
is answerable after the fact.

Scanning an **image file** rather than a device needs no elevation and opens no
raw device at all. That is the common case and the recommended one: work from an
acquisition, not the live disk.

---

## 5. Network behaviour

| Behaviour | Detail |
|---|---|
| Outbound connections | **One, from `arachnid-cli` only, and only on an interactive terminal.** A daily version check against `api.github.com`. See [§5a](#5a-the-update-check) — this paragraph used to read "none", and changed when `arachnid-cli` gained `self update`. |
| Telemetry / analytics | **None.** No usage counters, no machine identifiers, no install ping, no crash reporting. |
| Indicator lookup | **None.** A domain or address found in captured traffic is never resolved, queried or submitted anywhere. |
| Listening sockets | None. |
| Packet capture | Only under `capture`, only on the interface you name with `--device`. Uses libpcap (Linux) / Npcap (Windows). |
| Promiscuous mode | **Off by default.** `--promiscuous` is opt-in because it changes interface receive mode, which is an observable host change. |
| Transmission | None. The send path of the capture library is never called. |
| BPF filters | Applied in the kernel, so filtered traffic is never copied into userspace. |

Expected EDR observations during `capture`: `AF_PACKET` socket creation and
`SO_ATTACH_FILTER` (Linux), or a handle to `\Device\NPCAP\<iface>` (Windows).
Both are inherent to packet capture and are the reason capture is a separate
subcommand you can decline to allow.

`arachnid-core`, `arachnid-recover` and `arachnid-sanitize` — the standalone
binaries — make **no outbound connection at all**. The paragraph below applies
solely to the `arachnid-cli` front end.

---

## 5a. The update check (`arachnid-cli` only)

`arachnid-cli` performs one version check. It is the only unprompted outbound
request anywhere in the suite, so here is the whole of it.

| | |
|---|---|
| Request | `GET https://api.github.com/repos/ArachnidGs/forensic/releases/latest` |
| Sends | the URL and `User-Agent: arachnid-cli/<version>`. Nothing else |
| When | on launch, **only if stderr is a terminal**, at most once per 24 hours |
| Timeout | 500 ms, hard |
| On failure | silent. No message, no delay past the cap, no change to the exit code |
| Effect | at most one line on **stderr**, then the operator's command runs normally |
| Installs anything | **No.** Never, under any circumstance. `self update` is a separate command the operator runs |

### What this means for a monitored estate

**Scripted and scheduled runs make no network call at all.** The TTY condition
is the load-bearing part: a SOAR playbook, a cron job, a CI pipeline and any
piped invocation all skip the check entirely. If your endpoints run this
non-interactively, the observable network behaviour is unchanged from the
paragraph this section replaced.

An interactive analyst session will show at most one TLS connection to
`api.github.com` per day per user.

### Suppressing it

Either of these removes the request completely, and both are honoured silently:

```
ARACHNID_NO_UPDATE_CHECK=1          # environment, estate-wide if you set it there
arachnid-cli --no-update-check …    # per invocation
```

Blocking `api.github.com` at the egress point has the same effect from the
tool's side: the check fails silently within its timeout and nothing else
changes.

`arachnid-cli doctor` states which mode it is in, so an operator can confirm the
suppression rather than assume it.

### What it is not

It is not telemetry. Nothing is reported to us — the request is a read of a
public API endpoint, and the response is a version string. There is no endpoint
anywhere in this project that receives data.

`arachnid-cli self update` and the installers make further requests, but only
because the operator ran them. Both are documented byte for byte in
[THREAT_MODEL.md](../THREAT_MODEL.md).

---

## 6. Suggested rules

**Windows Defender ASR / AppLocker / WDAC** — prefer a publisher rule on the
Authenticode certificate. If you must use a path rule, scope it to a
SOC-controlled directory that responders cannot write to arbitrarily.

**CrowdStrike / SentinelOne / Defender for Endpoint** — allowlist by
certificate, then add an exclusion for the evidence container path so the
collected artifacts (which will contain malware paths and, if you acquire
memory, malware *code*) are not quarantined mid-collection.

> Put the evidence container on a dedicated collection volume or share, and
> exclude that path from real-time scanning. A memory image of an infected host
> **will** trigger signature hits. That is the image working correctly.

**Linux (SELinux/AppArmor/auditd)** — the read set in §4 is the complete list.
Expect `ptrace`-free process enumeration; Arachnid does not attach to processes.

---

## 7. Verifying a container you receive

Anyone can re-check an evidence container without trusting the collecting host:

```bash
arachnid-core verify /path/to/container      # exit 0 = intact, 3 = tampered
arachnid-core --json verify /path/to/container
```

This re-hashes every artifact, re-checks every Ed25519 signature, and walks the
custody hash chain. It runs independently of the collection code path.

**Important limitation, stated plainly:** without `--signing-key`, Arachnid
generates a signing key per run. That makes the container tamper-*evident*
against modification after collection, but anyone who can rewrite the whole
container can also swap the key and re-sign it. `verify` therefore proves
*integrity*, not *origin*, unless the key fingerprint it prints matches one you
recorded out-of-band at collection time. For chain-of-custody that must survive
challenge, issue each responder a persistent key and pass `--signing-key`.

---

## 8. Reporting

If Arachnid Core does something not described here, that is a defect we want to
know about. Open an issue with the operational log (`--log`) and the custody
log; between them they record every action the tool took.
