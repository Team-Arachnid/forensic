---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 13 · FAQ

[← Troubleshooting](12-Troubleshooting.md) · [Home](Home.md)

The questions that come up in review, in procurement, and from responders using
it for the first time.

---

## General

### What is Arachnid Core for?

Collecting volatile system state and network evidence from a running host into a
tamper-evident, signed container — so that what you collected can be shown later
to be what you collected.

It is a **triage** tool. It answers "what is happening on this host right now,
and can I prove that is what I saw". It is not a disk forensics suite, not a
malware sandbox, and not a monitoring agent.

### Is it a monitoring agent?

No. It runs when you run it and exits. It installs no service, no scheduled
task, no registry key and no unit. It has no daemon mode.

### Does it phone home?

No. **No outbound network connections of any kind** — no telemetry, no update
check, no indicator lookup, no DNS resolution of anything it collected.
`reqwest` and `hyper` are banned at the dependency level, so an accidental one
fails CI rather than shipping.

### Will it change the host I run it on?

No. Collectors read `/proc`, `/sys`, the registry (`KEY_READ` only) and config
paths. Persistence entries are enumerated, never modified. The only writes go to
the container directory you name with `-o`, plus the `--log` path if you use it.

The one caveat with teeth: **`--promiscuous` changes an interface's receive
mode**, which is an observable change to the host. It is off by default for
exactly that reason.

### Which platforms?

Linux and Windows are fully supported. macOS gets processes and connections
(`sysinfo` and `netstat2` work there), but sessions, kernel modules and
persistence report an explicit gap rather than an empty list. macOS is a stretch
goal.

### Is it free?

MIT licensed. See [`LICENSE`](../../LICENSE).

---

## Evidence and trust

### What does `verify` actually prove?

That every artifact matches what the custody log recorded, that every custody
record's signature is valid, and that the hash chain is unbroken.

That is **integrity**. It is not **origin** unless the key fingerprint matches
one you recorded out-of-band at collection time.

### Why is that distinction such a big deal?

Because without `--signing-key`, the key is generated per run and stored in the
container. Anyone who can rewrite the whole container can swap the key and
re-sign everything — and `verify` will then say VERIFIED, correctly, because the
container *is* internally consistent.

The fingerprint is what turns integrity into origin. Record it. Every run prints
it for that reason.

### So should I always use `--signing-key`?

For anything that might be challenged, yes. Issue each responder a persistent
key, record the fingerprint once in a system the adversary cannot reach, and pass
`--signing-key` on every run. See
[Workflow 8](09-Workflows.md#workflow-8--team-key-management).

For a quick look at a lab machine, the default is fine — but say so in your
notes.

### Why a directory instead of a single archive file?

Because an analyst can hash, cite, diff and hand off a single artifact without
unpacking anything, and because a multi-gigabyte memory image never has to be
read into a container format to be stored. The Recover module consumes these
directories directly.

### Can I add a file to a container afterwards?

No — and you should not want to. `verify` reports any file in `artifacts/` that
has no custody record as a tamper signal. Put working notes anywhere else.

### Can I re-run into the same container?

No. Pointing `-o` at a directory that already holds a `custody.log` is refused.
One run, one container.

### Why is `report.json` so much bigger than the other artifacts?

It embeds the full collection alongside the summary. If you only need one
collector, read its artifact directly — each is hashed and cited independently in
the custody log, so using one on its own loses nothing evidentially.

### Do I need Arachnid to read a container?

No. Everything is text.

```bash
jq . container/manifest.json
cut -d' ' -f2- container/custody.log | jq .
```

Artifact digests can be checked with coreutils alone. Signatures and the chain
need an Ed25519 implementation — the algorithm is documented in
[Writing a third-party verifier](05-Evidence-Container.md#writing-a-third-party-verifier).

### Why Ed25519 and SHA-256 specifically?

Both are conservative, widely implemented choices with no configuration surface.
There is no algorithm negotiation and no cipher suite to get wrong — a forensic
format with options is a forensic format with a downgrade path.

---

## Collection

### Does it need root?

No, but it collects materially less without it: unreadable `/proc/<pid>/maps`,
sockets with no attributable owner, inaccessible `HKLM` values. Gaps are recorded
in `warnings` and set exit code 4.

**Arachnid never escalates.** It uses the token it was launched with, and never
retries a failed access with more rights.

### What does exit code 4 mean, exactly?

You have evidence and it is incomplete. A collector failed, a capture dropped
packets, or frames failed to decode. Read `warnings`.

Do not treat it as success. Do not treat it as failure. Record what was missed.

### Why is a failed collector a warning instead of an error?

Because the rest of the evidence is still worth having. A host where one query is
unavailable should still yield everything else — but the gap must be **loud**, so
it appears in four places at once.

The rule behind it: *an empty result set is never allowed to look like a clean
host.* "No persistence entries" and "nobody looked" are different findings.

### Why does hashing binaries take so long?

Every distinct process image is hashed (once per path, cached). On a host with
thousands of processes that dominates the run. `--no-hash-binaries` skips it —
at the cost of not being able to say *this `sshd` is not the distribution's
`sshd`*.

### Why don't you ship a memory acquisition driver?

A custom kernel driver would be new kernel attack surface **on the host under
investigation**, and it would carry none of the review history AVML and WinPmem
already have. Arachnid wraps a vetted external tool instead — and hash-verifies
it before execution, so a swapped binary on a compromised host is caught before
it runs.

### Why is `--memory-tool-sha256` mandatory?

Because on a host that may already be compromised, an acquisition binary should
not run just because it had the right filename. There is deliberately no way to
run an unverified one.

### Is collection atomic?

**No.** The host keeps running while collectors execute; a process can exit
between the process-table read and the connection-table read. Custody timestamps
let you reconstruct the *order*; they cannot give you a consistent *snapshot*.
Only a memory image can. State this in your notes.

### Why two timestamps on every record?

`ts_utc` is what an analyst reads and cites. `mono_ns` preserves ordering when
the examined host's clock steps mid-collection — from an ordinary NTP correction,
or from an adversary. If they disagree about order, trust `mono_ns`.

---

## Network

### Why doesn't `capture` analyse what it captured?

Because decoding frames inside the capture loop is how a capture falls behind the
link and drops evidence. The savefile is written, flushed and sealed first; run
`parse-pcap` on it afterwards.

(The TUI *does* show a flow breakdown after a capture — from a read-only re-read
of the sealed savefile, and it is display only. Nothing from it enters the
container, because `arachnid-core capture` does not add it either.)

### Why is promiscuous mode off by default?

Enabling it changes the interface's receive mode, which is an observable change
to the host you are examining. Opt in when you actually need traffic not
addressed to this host.

### Does the BPF filter really keep traffic out of userspace?

Yes. Filters are compiled and applied in the kernel, so excluded traffic is never
copied. You can state that it was **never collected**, not merely discarded —
which matters when the exclusion is legally required.

### Can it decrypt TLS?

No, and it will not. It reads the plaintext handshake for SNI. Encrypted
ClientHello yields nothing. A triage tool that decrypted traffic would need keys
it has no business holding.

### Does it do injection, ARP spoofing, or MITM?

No. The capture library's send path is never called. Capture is receive-only, by
design rather than by omission.

### What about HTTP/2 and HTTP/3?

Not parsed — both are binary and usually inside TLS. You get IP indicators and
`tls_sni`.

### Why is a flow marked `truncated`?

It hit the per-flow reassembly ceiling (8 MiB by default). A capture holding a
multi-gigabyte download must not put that download in RAM. The flow is flagged,
**never silently shortened** — raise `--max-stream-bytes` if you need more.

---

## Detection and deployment

### Will my EDR flag it?

Possibly, and that is a reasonable first reaction — the tool enumerates
processes, reads persistence locations and captures packets, which is what
reconnaissance looks like.

The answer is disclosure, not evasion. Hand your SOC
[`docs/SOC-ALLOWLISTING.md`](../SOC-ALLOWLISTING.md), which lists every path,
registry key, API and network behaviour so they can write a **narrow** rule.

### Why doesn't it hide from AV?

Because a tool that hides from defenders is indistinguishable from malware and
deserves to be treated as such — and being quarantined mid-collection on the one
host that matters is a real failure mode.

The release build **fails** if the subcommand names are not visible to `strings`.
That is a deliberate gate.

### How do I prove to my SOC what it does before allowing it?

`--dry-run`. Every collector runs, every hash is computed, nothing reaches disk —
not even the container directory. They watch exactly what it touches, and no
evidence is produced that you then have to account for. See
[Workflow 7](09-Workflows.md#workflow-7--validating-an-edr-rule).

### Should I allowlist by hash or by publisher?

**By publisher** — the Authenticode certificate on Windows, the GPG key on
Linux — so patch releases do not require a new rule. Allowlist by hash only if
your tooling cannot do publisher rules.

And if you can, rebuild from the tagged commit: builds are reproducible, so the
hash you allowlist can be confirmed against the source you reviewed.

### Do I need to exclude the evidence path from scanning?

Yes. Collected artifacts contain malware paths, and a memory image of an infected
host contains malware *code*. Your scanner will hit on it — that is the image
working correctly. Put the container on a dedicated collection volume and exclude
that path from real-time scanning.

---

## The tools

### How many binaries are there?

Three: `arachnid-core` (triage CLI), `arachnid-tui` (terminal UI over both
modules), and `arachnid-sanitize` (secure erasure). The first two are read-only
against their target. The third is not.

### CLI or TUI?

The TUI for interactive work on one host — it shows privilege, capture
availability, a live collector checklist, and a per-artifact verify table. The
CLI for anything scripted, and for the options the TUI does not expose (memory
acquisition, dry run, capture stop conditions, reassembly ceiling).

### Can the TUI do anything the CLI cannot?

No. It is a deliberate subset. It never shells out to the CLI, and a container it
writes verifies with the CLI and validates against the same schemas.

### Why is the TUI's toolchain floor higher?

ratatui 0.30 needs Rust 1.88. Only that crate does; the engine crates and the CLI
stay buildable on 1.82, so a locked-down build host with an older toolchain can
still produce the CLI.

### Does the TUI store anything sensitive?

It remembers the operator name and recent paths in
`$XDG_STATE_HOME/arachnid/tui-state.json` (`%APPDATA%` on Windows). **That file
is a convenience, never evidence.** Delete it freely; it costs two retyped paths.

### Where is `arachnid-sanitize`?

**It ships.** `arachnid-sanitize` performs NIST SP 800-88 / DoD 5220.22-M
erasure, verifies by read-back, and issues signed certificates; it is also
screen `7` of the TUI. Full chapter: [Secure Erasure](14-Secure-Erasure.md).

Recover (recovering what anti-forensics removed before collection) is specified
but not implemented.

### Is Sanitize safe to allowlist alongside Core?

Treat it as a **separate decision**. At the syscall level it is deliberately
indistinguishable from disk-wiping wiper malware, because it is doing the same
thing for an authorized reason. Many sites will want it allowed on dedicated
disposal workstations only — or not at all, preferring to alert on it and
confirm out of band. See [`SOC-ALLOWLISTING.md` §4a](../SOC-ALLOWLISTING.md).

### Can Sanitize really claim NIST Purge?

**No, and it says so.** This build issues no hardware sanitize command:
`--method nist-purge` probes the device, reports which command would apply, then
runs a 3-pass software overwrite — and the certificate states plainly that it is
a software overwrite to be assessed against Clear, not Purge. A test asserts no
code path can claim a completed hardware purge.

Crypto-erase is refused on every device for the same reason: confirming a
working self-encrypting drive needs the same pass-through path, and claiming an
unverifiable crypto-erase is the most dangerous false statement the tool could
make.

### Does an overwrite really erase an SSD?

Not necessarily. Wear levelling means an overwrite cannot guarantee every
physical cell holding old data is reached. That is a property of the media, not
of the tool — and since neither hardware purge nor crypto-erase is available in
this build, flash leaving your organization wants physical destruction or the
vendor's own utility.

---

## Output

### Can I trust the JSON to be safe to render?

It is **faithful, not safe**. Process command lines, hostnames, HTTP headers and
persistence values are all attacker-controlled and stored verbatim, because a
sanitized artifact is a modified artifact.

Arachnid escapes on output — the HTML report escapes every field, with a test
asserting a `<script>` tag in a hostname cannot break out. **Anything downstream
that renders this data must escape it too.**

### Why does the Markdown report cut tables off at 20 rows?

Screen space. The JSON always holds everything, and the per-collector artifacts
hold it without the summary's framing.

### Can I build my own report format?

Yes — `report.json` is the contract, and it is schema-versioned. Reject a major
version you do not implement, as Arachnid does itself.

But do not hand-render a summary you present *as* the container's report: unlike
`arachnid-core report`'s output, yours is not covered by the custody chain, and a
divergence between the two is exactly the kind of thing that gets noticed at the
worst moment.

### Will the schema break on me?

Not within a major version. Additive changes (new optional fields, new enum
members) are minor bumps; anything that breaks a consumer is a major bump. CI
validates a **real container** against the published schemas on every push, so
drift fails the build rather than shipping.

---

## Contributing

### How do I add a collector?

[Development § Adding a collector](11-Development.md#adding-a-collector). Eight
steps, of which the two people forget are: add a `bail!` stub to
`unsupported.rs` (never an empty `Ok(vec![])`), and document every path you read
in `docs/SOC-ALLOWLISTING.md`.

### Can I add a dependency?

Read [Supply-chain checks](11-Development.md#supply-chain-checks) first. Crates
that make outbound requests or load code dynamically are banned outright, and CI
enforces it. Prefer stdlib: several places in this codebase read an env var or a
`/proc` file rather than linking libc for one value, and each carries a comment
explaining the trade.

### Why does so much of the code have comments explaining *why*?

Because most non-obvious lines here prevent a specific failure mode, and a future
maintainer removing one needs to know what it costs. Match that when you add
code.

---

[← Troubleshooting](12-Troubleshooting.md) · [Home](Home.md)
