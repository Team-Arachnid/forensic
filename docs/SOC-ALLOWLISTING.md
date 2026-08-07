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
- outbound network connections of any kind (`reqwest` and `hyper` are denied
  at the dependency level; there is no update check and no telemetry)
- packet injection or interception — capture is receive-only

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

## 5. Network behaviour

| Behaviour | Detail |
|---|---|
| Outbound connections | **None.** No telemetry, no update check, no indicator lookup, no DNS resolution of collected indicators. |
| Listening sockets | None. |
| Packet capture | Only under `capture`, only on the interface you name with `--device`. Uses libpcap (Linux) / Npcap (Windows). |
| Promiscuous mode | **Off by default.** `--promiscuous` is opt-in because it changes interface receive mode, which is an observable host change. |
| Transmission | None. The send path of the capture library is never called. |
| BPF filters | Applied in the kernel, so filtered traffic is never copied into userspace. |

Expected EDR observations during `capture`: `AF_PACKET` socket creation and
`SO_ATTACH_FILTER` (Linux), or a handle to `\Device\NPCAP\<iface>` (Windows).
Both are inherent to packet capture and are the reason capture is a separate
subcommand you can decline to allow.

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

