# 6 · Collectors

[← Evidence Container](05-Evidence-Container.md) · [Home](Home.md) · [Next: Network Forensics →](07-Network-Forensics.md)

What `arachnid-core collect` gathers, where it comes from, and what it cannot
see. Every read on this page is a **read**: no writes, no ioctls, no privileged
syscalls, no `ptrace`.

---

## Contents

- [The five collectors](#the-five-collectors)
- [Degradation](#degradation-is-the-contract)
- [Processes](#processes)
- [Connections](#connections)
- [Sessions](#sessions)
- [Kernel modules](#kernel-modules)
- [Persistence](#persistence)
- [Memory acquisition](#memory-acquisition)
- [Binary hashing](#binary-hashing)
- [Platform support](#platform-support)
- [Known gaps](#known-gaps)

---

## The five collectors

They run in this fixed order. It is the same order the TUI's checklist shows,
driven by the same list — a test asserts the progress callback reports exactly
these names in exactly this order, so a UI can never show an operator a
checklist that does not match the collection.

| # | Collector | Artifact |
|---|---|---|
| 1 | `processes` | `processes.json` |
| 2 | `connections` | `connections.json` |
| 3 | `sessions` | `sessions.json` |
| 4 | `kernel_modules` | `kernel_modules.json` |
| 5 | `persistence` | `persistence.json` |

`connections` runs after `processes` because it uses the process table to attach
a readable name to each owning PID.

**One artifact per collector**, deliberately: an analyst can hash-verify and
cite each independently, and a downstream tool can consume just the one it
needs.

---

## Degradation is the contract

A collector that fails does not abort the run. It records why:

```json
"warnings": [
  "sessions: read /var/run/utmp: No such file or directory (os error 2)"
]
```

and that warning appears in the report, in the custody log as a `note`, and in
**exit code 4**.

> **An empty result set is never allowed to look like a clean host.**
> "No persistence entries" and "nobody looked" are different findings.

The same principle applies *within* a collector: one unreadable
`/proc/<pid>/maps` yields an empty module list for that process, not a failed
process table. One unhashable binary yields `exe_sha256: null`, not a failed
run.

---

## Processes

Source: `sysinfo` (cross-platform), plus a per-platform module enumerator.

```json
{
  "pid": 11519,
  "parent_pid": 4611,
  "name": "claude",
  "cmdline": ["claude", "--resume"],
  "exe": "/usr/lib/node_modules/claude/bin/claude",
  "exe_sha256": "9b1c…4f2a",
  "user": "analyst",
  "start_time": 1787846420,
  "cwd": "/home/analyst/case-4471",
  "loaded_modules": ["/usr/lib/libc.so.6", "/usr/lib/libssl.so.3"]
}
```

| Field | Notes |
|---|---|
| `pid` / `parent_pid` | sorted by `pid` in the artifact |
| `cmdline` | **full argv as a list**, not a joined string — an argument containing a space is not ambiguous |
| `exe` | resolved image path, where the OS reports one |
| `exe_sha256` | SHA-256 of the on-disk image. `null` when unreadable, missing, or over 512 MiB |
| `user` | resolved from the uid against the user database |
| `start_time` | seconds since the Unix epoch |
| `loaded_modules` | distinct file-backed **executable** mappings |

### `loaded_modules`

**Linux** — parsed from `/proc/<pid>/maps`. Only mappings with the `x`
permission and a path starting with `/` are kept, deduplicated and sorted.
Anonymous and pseudo-mappings (`[heap]`, `[vdso]`) are not modules. An unreadable
`maps` yields an empty list.

**Windows** — `EnumProcessModulesEx` with `LIST_MODULES_ALL`, after
`OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ`.
Read-only. Protected and cross-session processes are expected failures even for
an administrator; they yield an empty list rather than costing the process
record. Failures are **not** retried with escalated rights.

This is the field where an injected image shows up: a DLL or `.so` mapped
executable into a process whose distribution package never referenced it.

### Analyst note

The report calls out **processes with an unhashable image** in their own
section:

> A missing hash means the path did not resolve to a readable file: a deleted or
> replaced binary, or insufficient privilege.

A process whose `exe` exists but whose `exe_sha256` is `null` when you *are*
privileged is worth a second look — a deleted-but-running binary is a classic
of both malware and legitimate updates.

---

## Connections

Source: `netstat2` — `/proc/net/{tcp,tcp6,udp,udp6}` and `/proc/<pid>/fd` on
Linux, the IP Helper tables on Windows. IPv4 and IPv6, TCP and UDP.

```json
{
  "protocol": "tcp",
  "local_addr": "172.16.0.2",
  "local_port": 43290,
  "remote_addr": "160.79.104.10",
  "remote_port": 443,
  "state": "ESTABLISHED",
  "pids": [11519],
  "process_name": "claude"
}
```

| Field | Notes |
|---|---|
| `protocol` | `tcp`, `tcp6`, `udp`, `udp6` |
| `state` | the TCP state. UDP is connectionless, so it is recorded as `STATELESS` |
| `remote_addr` / `remote_port` | `null` for UDP |
| `pids` | every PID associated with the socket |
| `process_name` | resolved from `pids` against the process table, for readability |

Sorted by `(protocol, local_port)`.

Mapping a socket to its owning process needs privilege on both platforms. Run
unprivileged and you will see sockets with an empty `pids` — the connection is
real, the attribution is missing.

The report highlights two subsets: **listening sockets**, and **connections to
routable addresses** (excluding loopback, link-local and RFC 1918 space). The
second is where triage actually starts.

---

## Sessions

Who is logged in.

### Linux

Parsed from the **utmp** database at `/var/run/utmp` (or `/run/utmp`) — a flat
array of fixed-size `struct utmp` records, read by byte offset rather than by
linking libc's `getutent`, which is not thread-safe and would pull in a
dependency for one record type. Only `USER_PROCESS` (type 7) entries are kept.

```json
{
  "user": "analyst",
  "terminal": "tty1",
  "remote_host": null,
  "login_time": "2026-08-28T21:40:20Z",
  "session_id": null,
  "state": null
}
```

> The offsets are the x86_64 / aarch64 glibc and musl layout (384-byte records).
> They are stable ABI for a given architecture. A platform with a different
> `utmp` layout would need its own offsets.

### Windows

The Terminal Services API — `WTSEnumerateSessionsW`, plus
`WTSQuerySessionInformationW` for the user name and client name. Covers console,
RDP, and disconnected-but-live sessions. Sessions with no user (services, the
listener pseudo-sessions) are skipped.

`login_time` is `null` on Windows: `WTS_SESSION_INFOW` exposes no login
timestamp. Get it from the Security event log, which is a separate artifact.

### The gap that matters

**A cleared utmp is already gone before Arachnid runs.** Wiping login records is
one of the oldest anti-forensic moves there is, and this collector records what
is present — it does not recover what was removed. That is the Recover module's
job.

---

## Kernel modules

### Linux

`/proc/modules`, plus `/proc/sys/kernel/osrelease` to locate the on-disk image.

```json
{
  "name": "nvidia_drm",
  "size": 131072,
  "path": "/lib/modules/6.11.5-arch1-1/kernel/drivers/gpu/nvidia-drm.ko.zst",
  "sha256": "4a2f…9c11",
  "used_by": ["nvidia_modeset"]
}
```

The `.ko` is searched for under `/lib/modules/<release>`, trying `.ko`,
`.ko.xz`, `.ko.zst` and `.ko.gz`, and both the `_` and `-` spellings of the
name (module names normalise `-` to `_`; filenames may use either).

**A module that resolves to no file is a finding, not a bug.** A module loaded
from an unusual path — or one whose backing file has been removed — yields
`path: null, sha256: null`. Sorted by name.

### Windows

`EnumDeviceDrivers` + `GetDeviceDriverFileNameW`, hashed against the on-disk
image where the path resolves. `used_by` is unused on Windows.

---

## Persistence

**Enumerated, never modified.** Nothing here is disabled, removed, rewritten,
registered or unregistered. All registry access is `KEY_READ`.

```json
{
  "kind": "systemd",
  "location": "/etc/systemd/system",
  "name": "backdoor.service",
  "value": "/usr/local/bin/updater --daemon",
  "sha256": "e3b0…b855"
}
```

| Field | Meaning |
|---|---|
| `kind` | `registry_run` \| `scheduled_task` \| `startup_folder` \| `systemd` \| `cron` \| `autostart` \| `rc_local` |
| `location` | the key, directory or file the entry lives in |
| `name` | the entry's name |
| `value` | the command or target it executes, where one is parseable |
| `sha256` | SHA-256 of the file backing the entry, where resolvable |

Sorted by `(kind, location, name)`.

### Linux locations

| Kind | Read from |
|---|---|
| `systemd` | `/etc/systemd/system`, `/run/systemd/system`, `/usr/lib/systemd/system`, `/lib/systemd/system`, `/etc/systemd/user`, `/usr/lib/systemd/user` — `.service` and `.timer` files. `value` is the `ExecStart=` line |
| `cron` | `/etc/crontab`, `/etc/cron.d/*`, `/var/spool/cron/*`, `/var/spool/cron/crontabs/*` — one entry per crontab line, with the line as `value`. Comments and environment assignments (`PATH=`, `MAILTO=`) are skipped |
| `cron` | `/etc/cron.{hourly,daily,weekly,monthly}/*` — these hold scripts, not crontab lines, so `value` is `null` and the script itself is hashed |
| `autostart` | `/etc/xdg/autostart`, **every** `/home/*/.config/autostart`, and `/root/.config/autostart` — `.desktop` files. `value` is the `Exec=` line |
| `rc_local` | `/etc/rc.local`, `/etc/rc.d/rc.local` |

The systemd directories are listed in precedence order — an admin-placed unit in
`/etc` shadows a vendor one. A unit symlinked into a `.wants/` directory is
*enabled*; the file itself is what executes, so the file is what gets recorded.

Autostart covers **every** real home directory, not just the invoking user's.

### Windows locations

| Kind | Read from |
|---|---|
| `registry_run` | under both `HKLM` and `HKCU`: `Software\Microsoft\Windows\CurrentVersion\{Run, RunOnce, RunServices, RunServicesOnce}`, `…\CurrentVersion\Policies\Explorer\Run`, `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`, `Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run` |
| `scheduled_task` | `%SystemRoot%\System32\Tasks\**` — the task XML. `value` is the `<Command>` element |
| `startup_folder` | `%ProgramData%\Microsoft\Windows\Start Menu\Programs\StartUp\*`, and `%SystemDrive%\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\*` — **every** profile |

An absent registry key is the norm, not an error, and is skipped silently.

A **non-string Run value** (`REG_BINARY`, `REG_DWORD`) is itself worth recording,
so it is described rather than dropped:

```json
"value": "<non-string value: REG_BINARY, 284 bytes>"
```

For `registry_run`, the executable is extracted from the command line so it can
be hashed. Quoted paths are handled directly; for the unquoted-with-spaces case
the longest prefix that is an existing file wins, falling back to the first
whitespace-delimited token.

### Known limitation: scheduled tasks

Tasks are read from the **on-disk store**, not through the Task Scheduler COM
API. This misses a task registered only in the registry `TaskCache` with no
matching file — a known anti-forensics technique.

Closing the gap means `ITaskService::GetFolder` enumeration, or cross-checking
against
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`.
The limitation and the fix are documented on the function itself in
`crates/arachnid-collect/src/windows.rs`.

---

## Memory acquisition

Optional, and **not** a collector — it is a separate step that runs after the
five collectors when `--memory-tool` is given.

Arachnid ships **no kernel-mode memory driver of its own**. A custom driver
would be new kernel attack surface on the very host under investigation, and it
would carry none of the review history that AVML and WinPmem already have. So it
wraps an external, vetted tool.

```bash
arachnid-core collect -o ./ev-host01 \
    --memory-tool /opt/avml \
    --memory-tool-sha256 3f6a…c21b \
    --memory-arg --compress
```

The invocation shape is `<tool> [extra args…] <output-path>`, which AVML and
WinPmem share.

**The tool's SHA-256 is verified before execution**, and a mismatch aborts the
run:

```
error: acquisition tool hash mismatch for /opt/avml: expected 3f6a…c21b,
       found 91d0…4e77. Refusing to execute an unverified tool.
```

On a host that may already be compromised, an unverified acquisition binary does
not get to run just because it had the right filename. `--memory-tool-sha256` is
**required** by `clap`, not merely recommended.

Recorded in the report under `memory`:

```json
{
  "tool": "/opt/avml",
  "tool_sha256": "3f6a…c21b",
  "args": ["--compress", "./ev-host01/artifacts/memory.raw"],
  "output_artifact": "memory.raw",
  "started_utc": "2026-08-28T16:20:11Z",
  "finished_utc": "2026-08-28T16:24:47Z",
  "exit_code": 0,
  "stderr_tail": "…"
}
```

`stderr_tail` is the last 20 lines. A non-zero exit fails the run with that tail
in the error.

The image is streamed-hashed, so a multi-gigabyte capture never lands in RAM.

Skipped entirely under `--dry-run` — the tool is not executed.

> **Why acquire memory at all?** Because live enumeration goes through OS APIs,
> and a kernel-level implant can lie to those APIs. A memory image is the
> countermeasure. See
> [Threat Model § A compromised kernel lies](10-Security-and-Threat-Model.md#a-compromised-kernel-lies).

---

## Binary hashing

On by default; `--no-hash-binaries` turns it off.

- **Hashed once per distinct path.** One image is usually mapped by many
  processes; the digest is cached in a map keyed by path.
- **Files over 512 MiB are recorded without a hash.** Nothing legitimate on a
  persistence path is that big, and a hostile 40 GiB file should not stall
  triage.
- **An unreadable file yields `null`**, never a failed run.
- Applies to process images, kernel module files, and the files backing
  persistence entries.

It is the expensive part of a collection. Skip it when time matters more than
image integrity — and note the choice, because a report full of `null` digests
looks the same as one taken without privilege.

---

## Platform support

| | Linux | Windows | macOS / other |
|---|---|---|---|
| processes | ✅ | ✅ | ✅ (`sysinfo`) |
| connections | ✅ | ✅ | ✅ (`netstat2`) |
| sessions | ✅ utmp | ✅ WTS | ❌ explicit gap |
| kernel_modules | ✅ `/proc/modules` | ✅ `EnumDeviceDrivers` | ❌ explicit gap |
| persistence | ✅ | ✅ | ❌ explicit gap |
| loaded_modules | ✅ `/proc/<pid>/maps` | ✅ `EnumProcessModulesEx` | ❌ empty |

On an unsupported platform the three host-specific collectors return an explicit
error rather than an empty list:

```
sessions: session enumeration is not implemented on macos
```

which becomes a warning, a custody note, and exit code 4 — so an analyst is
never shown "no persistence entries" when the truth is "nobody looked".

macOS is a stretch goal, not a blocker.

---

## Known gaps

These are limitations of the approach, not bugs. State them in your notes.

| Gap | Consequence |
|---|---|
| **A compromised kernel lies.** Every collector reads through OS APIs | A rootkit that hooks them hides from Arachnid as easily as from `ps`. Correlate with a memory image |
| **Collection is not atomic.** The host keeps running | A process can exit between the process-table read and the connection-table read. Custody timestamps let you reconstruct order; they cannot give you a consistent snapshot. Only a memory image can |
| **The operator's privilege is the ceiling.** Arachnid never escalates | Running as a normal user yields materially less: unreadable `maps`, unattributable sockets, inaccessible `HKLM` values. It says so in `warnings` |
| **Windows scheduled tasks** are read from disk, not COM | A task registered only in `TaskCache` is missed |
| **Anti-forensics that predates collection** | A cleared utmp, a deleted unit file, a task removed before you arrived is already gone. Arachnid records what is present |
| **Collected content is hostile input** | Command lines, DNS names, persistence values are attacker-controlled. Stored verbatim, escaped on output. Anything downstream that renders this data must escape it too |

---

[← Evidence Container](05-Evidence-Container.md) · [Home](Home.md) · [Next: Network Forensics →](07-Network-Forensics.md)
