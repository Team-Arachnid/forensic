---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# Arachnid Core — Wiki

**Live triage and network forensics for the Arachnid Forensic suite.**

Arachnid Core collects volatile system state and network evidence from a running
host into a tamper-evident, cryptographically signed evidence container. It is
read-only against the target: the only writes go to the container directory you
name.

For use by authorized analysts on systems they have permission to examine.

The suite also ships **Arachnid Recover**, which pulls deleted files back out
of an acquired image — see [File Recovery](15-File-Recovery.md) — and **Arachnid
Sanitize**, which is the one tool here that *destroys* data — see
[Secure Erasure](14-Secure-Erasure.md).

```
arachnid-core collect     -o ./ev-host01              # volatile state
arachnid-core capture     -o ./ev-net -d eth0 --duration 300 -f "not port 22"
arachnid-core parse-pcap  suspicious.pcap -o ./ev-pcap
arachnid-core verify      ./ev-host01                 # exit 0 = intact, 3 = tampered
arachnid-core report      ./ev-host01 --format html -o triage.html

arachnid-tui                                          # the same engine, driven from a TUI

arachnid-recover scan   -i ./ev-host01/artifacts/disk.img -o ./rec --carve-pass
arachnid-recover export -i ./rec/results.json -o ./rec/out --confidence high,medium
```

---

## Start here

| If you are… | Read |
|---|---|
| New to the tool | [Getting Started](01-Getting-Started.md) |
| An incident responder with a host in front of you | [Workflows](09-Workflows.md) |
| Looking up a flag | [CLI Reference](03-CLI-Reference.md) |
| Driving the TUI | [Terminal UI Guide](04-TUI-Guide.md) |
| A SOC being asked to allow this binary | [Security & Threat Model](10-Security-and-Threat-Model.md), then [SOC Allowlisting](../SOC-ALLOWLISTING.md) |
| Consuming the output from another tool | [Reports & Schemas](08-Reports-and-Schemas.md) |
| Recovering deleted files from an image | [File Recovery](15-File-Recovery.md) |
| Wiping a drive for disposal | [Secure Erasure](14-Secure-Erasure.md) |
| Contributing code | [Development](11-Development.md) |
| Stuck | [Troubleshooting](12-Troubleshooting.md) · [FAQ](13-FAQ.md) |

---

## All pages

1. **[Getting Started](01-Getting-Started.md)** — requirements, building, release
   builds, your first container, verifying a release binary.
2. **[Core Concepts](02-Concepts.md)** — the design stance, the evidence
   container, custody chains, degraded collection, exit codes, the read-only
   rule.
3. **[CLI Reference](03-CLI-Reference.md)** — every subcommand, every flag,
   worked examples with real output.
4. **[Terminal UI Guide](04-TUI-Guide.md)** — all nine screens, every key,
   editing, confirmations, layout behaviour, persisted state.
5. **[The Evidence Container](05-Evidence-Container.md)** — the on-disk format
   byte by byte, the hash chain, the signing scheme, what verification checks
   and in what order.
6. **[Collectors](06-Collectors.md)** — what each collector gathers, every path
   and registry key read, per-platform behaviour, data shapes.
7. **[Network Forensics](07-Network-Forensics.md)** — live capture, BPF filters,
   drops, TCP reassembly, indicator extraction.
8. **[Reports & Schemas](08-Reports-and-Schemas.md)** — the JSON contract, the
   Markdown and HTML renderings, schema versioning, validating output.
9. **[Workflows](09-Workflows.md)** — end-to-end playbooks: endpoint triage,
   network investigation, third-party verification, SOAR integration,
   air-gapped analysis.
10. **[Security & Threat Model](10-Security-and-Threat-Model.md)** — what
    Arachnid defends against, what it explicitly does not, non-goals, supply
    chain.
11. **[Development](11-Development.md)** — the eleven crates, building, testing,
    CI, and how to add a collector or a screen.
12. **[Troubleshooting](12-Troubleshooting.md)** — every error message you are
    likely to see, and what to do about it.
13. **[FAQ](13-FAQ.md)** — the questions that come up in review.
14. **[Secure Erasure](14-Secure-Erasure.md)** — Arachnid Sanitize: methods and
    compliance, the safety rails, the CLI, read-back verification, signed
    certificates. **This module destroys data.**
15. **[File Recovery](15-File-Recovery.md)** — Arachnid Recover: NTFS, ext4 and
    APFS parsing, signature carving, confidence scoring and its rationale, the
    CLI, and how a recovery export verifies as evidence.

---

## Three things to internalize before you run it

**1. Record the key fingerprint.** Every run prints one. Without
`--signing-key`, the signing key is generated per run, and `verify` can then
prove only that a container is internally consistent — not who produced it. See
[Signing Keys](02-Concepts.md#signing-keys-and-what-verification-proves).

**2. One binary in this suite destroys data.** `arachnid-core`,
`arachnid-recover` and `arachnid-tui` are read-only against the target.
`arachnid-sanitize` is not —
it exists to make a device unreadable, and a wipe cannot be undone. It is a
separate allowlisting decision and a separate habit: `--dry-run` first, every
time. See [Secure Erasure](14-Secure-Erasure.md).

**3. A compromised kernel lies to you.** Every collector reads through OS APIs.
A rootkit that hooks those APIs hides from Arachnid exactly as it hides from
`ps`. Live triage is one input, not the answer. See
[What it does not defend against](10-Security-and-Threat-Model.md#what-it-does-not-defend-against).

---

## The suite

| Module | Status |
|---|---|
| **Arachnid Core** | shipping — `arachnid-core`, `arachnid-tui`. Read-only |
| **Arachnid Recover** | shipping — `arachnid-recover`, and screen 8 of the TUI. Read-only. See [File Recovery](15-File-Recovery.md) |
| **Arachnid Sanitize** | shipping — `arachnid-sanitize`, and screen 7 of the TUI. **Destroys data.** See [Secure Erasure](14-Secure-Erasure.md) |

Core acquires, Recover extracts, Sanitize destroys. Recover reads Core's
containers directly and writes its exports back into new ones, so the whole
chain verifies with `arachnid-core verify`.

---

## Other documents in this repository

| Document | For |
|---|---|
| [`README.md`](../../README.md) | the repository front page |
| [`arachnid-usage-guide.md`](../../arachnid-usage-guide.md) | task-oriented usage guide for operators |
| [`docs/SOC-ALLOWLISTING.md`](../SOC-ALLOWLISTING.md) | full behavioural disclosure for detection engineering |
| [`schema/report.schema.json`](../../schema/report.schema.json) | the report contract |
| [`schema/custody.schema.json`](../../schema/custody.schema.json) | one custody record |
| [`schema/samples/`](../../schema/samples/) | a real erasure certificate and a real recovery results index, both generated by a test |
| [`test-fixtures/`](../../test-fixtures/) | synthetic NTFS and ext4 images for the recovery parsers. No real data |

Version documented: **0.1.0**. Report schema **1.0.0**, container schema
**1.0.0**, certificate schema **1.0.0**. Licensed MIT.
