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

