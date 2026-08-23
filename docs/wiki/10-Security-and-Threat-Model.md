---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 10 · Security & Threat Model

[← Workflows](09-Workflows.md) · [Home](Home.md) · [Next: Development →](11-Development.md)

What Arachnid Core defends against, what it explicitly does not, and why the
second list is written down rather than glossed over.

For the operational disclosure a SOC needs to write an allow rule, see
[`docs/SOC-ALLOWLISTING.md`](../SOC-ALLOWLISTING.md).

> **This page is about Arachnid Core.** `arachnid-sanitize` destroys data by
> design and has its own threat surface, its own safety rails and its own
> allowlisting decision — see [Secure Erasure](14-Secure-Erasure.md) and
> [`SOC-ALLOWLISTING.md` §4a](../SOC-ALLOWLISTING.md). Allowlisting Core does
> **not** imply allowlisting Sanitize, and for most sites it should not.

---

## Contents

- [The adversary](#the-adversary)
- [What it defends against](#what-it-defends-against)
- [What it does not defend against](#what-it-does-not-defend-against)
- [Non-goals](#non-goals)
- [Supply chain](#supply-chain)
- [Hostile input](#hostile-input)
- [Authorization](#authorization)
- [Reporting a security issue](#reporting-a-security-issue)

---

## The adversary

Arachnid Core assumes an attacker who:

- has code execution on the examined host, possibly at kernel level;
- may know a triage tool is coming, and may have prepared for it;
- may gain access to the evidence container **after** collection;
- controls the *content* of everything collected — command lines, hostnames,
  HTTP headers, persistence values.

It does **not** assume an attacker who controls the responder's kit, the signing
key, or the out-of-band record of the key fingerprint. Those are the trust
anchors; if they fall, nothing below holds.

---

## What it defends against

### Post-collection tampering

Anyone who modifies an artifact, edits a custody record, removes a record, or
plants an unlogged file is detected by `verify`. **This is the property the
container exists to provide.**

| Tampering | Detected by |
|---|---|
| Editing an artifact | its recorded SHA-256 no longer matches |
| Truncating or padding one | its recorded size no longer matches |
| Deleting an artifact | file missing |
| Planting a file | present on disk, absent from the log |
| Editing a custody record | that line's Ed25519 signature fails |
| Deleting or reordering records | the `prev` hash chain breaks |

Each of these has a test in `crates/arachnid-evidence/src/lib.rs`. Mechanism:
[The Evidence Container](05-Evidence-Container.md).

Verification is deliberately implemented **independently of the collection
path** — it re-reads and re-hashes rather than sharing writer state — so a bug
in collection cannot make a broken container verify clean.

### A swapped acquisition tool

The memory acquisition binary is **hash-pinned and verified before execution**,
so a replaced `avml` on a compromised host is caught before it runs rather than
recorded after.

`--memory-tool-sha256` is required by the argument parser, not merely
recommended. There is no way to ask Arachnid to run an unverified acquisition
tool.

### Silent partial collection

Every collector that fails records **why** — in `warnings`, in the custody log,
at the top of the report, and in exit code 4.

> An empty result set is never allowed to look like a clean host.

### Capture gaps

Kernel and interface drop counters are recorded, surfaced prominently in the
report, noted in the custody log, and set exit code 4. A capture with drops has
holes, and holes in evidence must be visible.

### Its own detectability

Arachnid does not hide. It is designed so a SOC can allow it *narrowly*: no
child processes but the one you name, no writes outside `-o`, no network, no
persistence, read-only registry. The release build fails if the subcommand names
are not visible to `strings`.

This is a security property, not a cosmetic one. A tool that hides from
defenders gets treated as malware — and being quarantined mid-collection on the
one host that matters is a real failure mode, not a hypothetical one.

---

## What it does not defend against

These are limitations of live triage itself, not gaps to be patched. **State
them in your notes.**

### A compromised kernel lies

Every collector reads through OS APIs. A rootkit that hooks those APIs — a
malicious LKM, an SSDT hook, a hypervisor-level implant — can hide processes,
sockets and files from Arachnid as easily as from `ps`.

**The countermeasure is memory acquisition and offline analysis**, which is why
`collect` supports acquiring an image. Correlate; do not trust live enumeration
alone against a kernel-level adversary.

Signs worth escalating on: a kernel module with no on-disk file, a process whose
image cannot be hashed while you are privileged, a socket with no owning PID
when you are root.

### Ephemeral-key containers prove integrity, not origin

Without `--signing-key`, a key is generated per run. Anyone who can rewrite the
whole container can also swap the key and re-sign everything. `verify` then
proves only that the container is self-consistent.

It proves **origin** only when the key fingerprint matches one recorded
out-of-band.

> **For chain of custody that must survive challenge in a proceeding, issue each
> responder a persistent key and always pass `--signing-key`.**

The fingerprint is printed at the end of every run precisely so it can be
recorded. See [Workflow 8](09-Workflows.md#workflow-8--team-key-management).

### Collection is not atomic

The host keeps running while collectors execute. A process can exit between the
process-table read and the connection-table read; a file can be deleted between
being listed and being hashed.

Timestamps in the custody log let you **reconstruct the order**; they cannot
give you a **consistent snapshot**. Only a memory image can.

This is why both clocks exist: `ts_utc` for what you cite, `mono_ns` for
ordering that survives a host whose wall clock moves mid-collection.

### The operator's privilege is the ceiling

Arachnid **never escalates**. It uses the token it was launched with, and never
adjusts, impersonates, or retries a failed access with more rights.

Running as a normal user yields materially less evidence — unreadable
`/proc/<pid>/maps`, sockets with no attributable owner, inaccessible `HKLM`
values — and says so in `warnings`.

### Anti-forensics that predates collection

A cleared utmp, a deleted unit file, a scheduled task removed before you
arrived: already gone. **Arachnid records what is present; it does not recover
what was removed.** That is the Arachnid Recover module's job.

The known specific case: Windows scheduled tasks are read from the on-disk
`System32\Tasks` store, so a task registered only in the registry `TaskCache`
with no matching file is missed. Documented in
[Collectors](06-Collectors.md#known-limitation-scheduled-tasks) and on the
function itself.

### Encrypted traffic

Arachnid reads the plaintext TLS handshake for SNI and **does not attempt to
decrypt anything**. Encrypted ClientHello yields no SNI. HTTP/2 and HTTP/3
inside TLS yield IPs and SNI only.

A triage tool that decrypted traffic would need keys it has no business holding.

### The examined host observing the capture

Packet capture is not invisible. Expect `AF_PACKET` socket creation and
`SO_ATTACH_FILTER` on Linux, or a handle to `\Device\NPCAP\<iface>` on Windows.
An attacker with kernel visibility can see a capture starting.

`--promiscuous` is off by default specifically because enabling it changes the
interface's receive mode, which is an observable change to the host — but the
capture itself is never fully hidden, and Arachnid does not pretend otherwise.

---

## Non-goals

These are hard design constraints, enforced in review and in `deny.toml`.
Arachnid Core contains **no**:

- anti-EDR, anti-AV, anti-debugging, or sandbox-detection logic
- packing, binary encryption, or runtime obfuscation
- dynamic code loading, self-modification, or reflective loading
- process injection, hooking, or memory writes into other processes
- exploit or privilege-escalation code
- self-persistence: no service, task, key or unit is installed
- outbound network connections of any kind — no telemetry, no update check, no
  indicator lookup
- listening sockets
- packet injection or interception — capture is receive-only

**If a future feature would require any of the above, the design is out of scope
and gets flagged rather than implemented.**

`arachnid-sanitize` shares every one of these non-goals — no network, no
scheduling, no persistence, no self-deletion, no log clearing — while inverting
the read-only rule, and only for the device the operator names.

That is not a promise about intent; it is enforced by CI. See below.

---

## Supply chain

Dependencies are few, audited in CI, and constrained by policy.

### Banned outright

`deny.toml` denies, at the dependency level:

| Crate | Reason |
|---|---|
| `reqwest`, `hyper` | Arachnid Core never makes outbound requests |
| `openssl-sys` | no TLS client belongs in a triage binary |
| `libloading` | no dynamic code loading in the shipped binary |
| `dlopen` | same |

`libloading` is permitted only as a **build-time** dependency of `clang-sys`
(bindgen's libclang probe) and `pcap` (its `wpcap.dll` build-script probe). Both
run on the build host and contribute no code to the shipped binary. **If either
ever becomes a normal dependency, the check fails** — which is the point.

On Windows, `wpcap.dll` is a normal import-library link (delay-loaded), not a
runtime `LoadLibrary` of attacker-reachable code.

### Sources

```toml
unknown-registry = "deny"
unknown-git      = "deny"
allow-git        = []       # no git dependencies
```

Every input is a versioned, checksummed crates.io release. `wildcards = "deny"`
— no unpinned version requirements.

### Advisories

`cargo deny check` and `cargo audit` both run in CI against the RustSec
database. One documented exception:

> **RUSTSEC-2024-0436** — `paste` is archived-but-correct, reached via
> `netstat2 → netlink-packet-*`. It is a compile-time proc-macro contributing no
> code to the shipped binary, and no vulnerability is known against it. Reviewed
> 2026-08-27; the rationale and revisit criteria are in `deny.toml`, and
> `.cargo/audit.toml` is kept in sync so a bare `cargo audit` agrees with CI.

An exception with a review date is a decision. An exception without one is a
hole.

### Build integrity

- **Reproducible**: `SOURCE_DATE_EPOCH` and `--remap-path-prefix` are set, so
  rebuilding a tagged commit reproduces the published hash. A SOC can confirm
  the binary it allowlisted matches the source it reviewed — the strongest check
  available.
- **Signed**: detached GPG (Linux), Authenticode with RFC 3161 timestamping
  (Windows).
- **Statically linked**: verified with `ldd`, and the build fails if any dynamic
  dependency remains. (Windows keeps `wpcap.dll` as a delay-loaded import; it is
  the user-mode half of a kernel driver and cannot be static.)
- **Inspectable**: the build fails if `strings` cannot find the subcommand names.

Prefer allowlisting by **code-signing certificate** or **GPG key** over by hash,
so patch releases do not require a new rule.

---

## Hostile input

**Everything Arachnid collects is attacker-controllable**: process command
lines, DNS names, HTTP headers, User-Agents, persistence values, file paths.

The rule is:

> Store verbatim. Escape on output.

- Values go into the JSON exactly as collected. Nothing is sanitized away,
  because a sanitized artifact is a modified artifact.
- The HTML report escapes `&`, `<` and `>` in **every** field. There is a test
  asserting a `<script>` tag in a hostname cannot break out of the page.
- The Markdown renderer escapes `|` in truncated cells so a value containing a
  pipe cannot break a table.

**Anything downstream that renders this data must escape it too.** If you build
a dashboard on `report.json`, treat every string field as untrusted input. The
JSON is faithful, not safe — and that is the correct trade.

Parsers are written defensively against the same principle:

- DNS name decompression follows pointers with a **bounded budget** (128 steps),
  because a corrupt or malicious message can point in a cycle.
- Question and answer sections are capped at 64 entries each.
- The HTTP scan is bounded to the first 64 KiB of a stream.
- TCP reassembly is capped per flow, and a flow that hits the cap is flagged
  rather than silently shortened.
- Files over 512 MiB are recorded without a hash, so a hostile 40 GiB file on a
  persistence path cannot stall triage.
- Unrecognised link types are counted as decode errors rather than misparsed
  into phantom flows.

---

## Authorization

Arachnid Core is for **authorized analysts on systems they have permission to
examine**.

The tool does not, and cannot, enforce authorization scope. That is a process
control, not a software one. What it *does* provide is a record of what was
done: the custody log holds the full invocation, the operator identity, and a
timestamped entry for every artifact produced.

Operationally that means:

- Get the authorization in writing before you run it.
- Use `--operator` honestly. It is self-asserted and attributable only through
  the signing key.
- Scope captures with a BPF filter when the scope is legally bounded — kernel
  filtering means excluded traffic is **never collected**, not merely discarded.
- Remember that a memory image of a shared host contains other people's data.

---

## Reporting a security issue

If Arachnid Core does something not described in this wiki or in
[`docs/SOC-ALLOWLISTING.md`](../SOC-ALLOWLISTING.md), **that is a defect and we
want the report.**

Include:

- the operational log (`--log <path>`, ideally `--log-level debug`),
- the custody log from the affected container,
- the tool version (`arachnid-core --version`) and platform.

Between them, those record every action the tool took.

For a vulnerability, describe the class of problem rather than publishing a
working exploit path.

---

[← Workflows](09-Workflows.md) · [Home](Home.md) · [Next: Development →](11-Development.md)
