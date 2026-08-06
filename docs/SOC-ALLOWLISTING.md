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

