---
title: Arachnid Forensic
description: Live triage, network forensics and secure erasure for authorized DFIR use.
---

<div class="hero" markdown="1">

<img class="hero-mark" src="{{ '/assets/logo.png' | relative_url }}" alt="" width="128" height="128">

# Arachnid Forensic

<p class="tagline">Live triage, network forensics and secure erasure — collected into a tamper-evident, signed evidence container.</p>

</div>

Arachnid Core collects volatile system state and network evidence from a running
host and seals it into a container whose every artifact is hashed, signed and
chained. It is read-only against the target: the only writes go to the container
directory you name.

For use by authorized analysts on systems they have permission to examine.

```bash
arachnid-core collect     -o ./ev-host01              # volatile state
arachnid-core capture     -o ./ev-net -d eth0 --duration 300 -f "not port 22"
arachnid-core parse-pcap  suspicious.pcap -o ./ev-pcap
arachnid-core verify      ./ev-host01                 # exit 0 = intact, 3 = tampered
arachnid-core report      ./ev-host01 --format html -o triage.html

arachnid-tui                                          # the same engine, from a TUI
```

## Start here

<ul class="cards">
<li><a href="wiki/01-Getting-Started.html"><strong>Getting Started</strong><span>Requirements, building, verifying a release binary, and your first container in five minutes.</span></a></li>
<li><a href="wiki/02-Concepts.html"><strong>Core Concepts</strong><span>The design stance, the custody chain, degraded collection, exit codes, and what verification actually proves.</span></a></li>
<li><a href="wiki/03-CLI-Reference.html"><strong>CLI Reference</strong><span>Every subcommand and flag, with worked examples and real output.</span></a></li>
<li><a href="wiki/09-Workflows.html"><strong>Workflows</strong><span>End-to-end playbooks: endpoint triage, network investigation, SOAR, air-gapped analysis, disposal.</span></a></li>
<li><a href="wiki/10-Security-and-Threat-Model.html"><strong>Threat Model</strong><span>What it defends against, and — written down rather than glossed over — what it does not.</span></a></li>
<li><a href="wiki/14-Secure-Erasure.html"><strong>Secure Erasure</strong><span>Arachnid Sanitize: compliance mapping, the safety rails, and signed certificates.</span></a></li>
</ul>

## Two things to internalize

**Record the key fingerprint.** Every run prints one. Without `--signing-key` the
signing key is generated per run, so `verify` can prove a container is internally
consistent but not who produced it. The fingerprint, recorded out-of-band, is
what turns integrity into origin.

**A compromised kernel lies to you.** Every collector reads through OS APIs. A
rootkit that hooks those APIs hides from Arachnid exactly as it hides from `ps`.
Live triage is one input, not the answer — correlate it with a memory image.

<div class="warn-note" markdown="1">

**One binary in this suite destroys data.** `arachnid-core` and `arachnid-tui`
are read-only against the target. `arachnid-sanitize` is not: it exists to make a
device unreadable, and a wipe cannot be undone. It is a separate allowlisting
decision and a separate habit — `--dry-run` first, every time.

</div>

## The suite

| Module | Status |
|---|---|
| **Arachnid Core** | shipping — `arachnid-core`, `arachnid-tui` |
| **Arachnid Sanitize** | shipping — `arachnid-sanitize`, and screen 7 of the TUI |
| **Arachnid Recover** | not built. Consumes Core's containers directly |

## Elsewhere

- [Repository](https://github.com/ArachnidGs/forensic) — source, issues, releases
- [GitHub wiki](https://github.com/ArachnidGs/forensic/wiki) — the same pages, rendered by GitHub
- [SOC allowlisting](SOC-ALLOWLISTING.html) — full behavioural disclosure for detection engineering

Licensed MIT. Version documented: **0.1.0**.
