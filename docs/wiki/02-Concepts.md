# 2 · Core Concepts

[← Getting Started](01-Getting-Started.md) · [Home](Home.md) · [Next: CLI Reference →](03-CLI-Reference.md)

Everything on this page is a design decision with a reason attached. The reasons
matter more than the mechanics — they are what tell you when the tool is the
wrong tool.

---

## Contents

- [The design stance](#the-design-stance)
- [The evidence container](#the-evidence-container)
- [The chain of custody](#the-chain-of-custody)
- [Signing keys and what verification proves](#signing-keys-and-what-verification-proves)
- [Two clocks](#two-clocks)
- [Degraded collection](#degraded-collection-is-loud)
- [Exit codes](#exit-codes)
- [The read-only rule](#the-read-only-rule)
- [Dry run](#dry-run)
- [Two logs](#two-logs)
- [Two front ends, one engine](#two-front-ends-one-engine)
- [Vocabulary](#vocabulary)

---

## The design stance

A triage tool runs with high privilege on a host that may already be
compromised, and it does things that resemble reconnaissance. Two consequences
shape every decision in the codebase.

### 1 · Be inspectable, not evasive

There is no packing, no obfuscation, no anti-debugging, and no attempt to hide
from AV or EDR. The release build **fails** if the subcommand names are not
visible to `strings`.

The reasoning is not squeamishness. A tool that hides from defenders is
indistinguishable from malware and deserves to be treated as such — and the
moment it is treated as such, it is quarantined mid-collection on the one host
where that costs you the most. The alternative is disclosure: the
[SOC allowlisting guide](../SOC-ALLOWLISTING.md) lists every path, registry
key, API and network behaviour so a SOC can write a narrow allow rule.

Explicitly out of scope, and flagged rather than implemented if a future feature
would need them:

anti-EDR · anti-AV · anti-debugging · packing · runtime obfuscation · exploit
or privilege-escalation code · process injection · dynamic code loading ·
self-persistence · packet injection or interception

These are enforced, not just intended: `deny.toml` bans `reqwest`, `hyper`,
`openssl-sys`, `libloading` and `dlopen` at the dependency level, so an
accidental dependency that could phone home or load code fails CI rather than
shipping.

### 2 · Never write to the target

Collectors open `/proc`, `/sys`, the registry (`KEY_READ` only) and config
paths **for reading and nothing else**. Persistence entries are *enumerated*,
never modified. There are no temp files, no scratch directories, no config
files, and no writes to any system location.

The only writes are:

- into the container directory you name with `-o`;
- the operational log path, if you pass `--log`.

The only child process is the memory acquisition tool you name yourself with
`--memory-tool` — and it is hash-verified before execution.

---

## The evidence container

A container is a **directory**, not an archive file. It holds everything one run
produced plus the metadata needed to prove nothing has changed since.

```
ev-host01/
├── manifest.json          run metadata + Ed25519 public key
├── custody.log            append-only signed hash chain, one record per line
└── artifacts/
    ├── processes.json     connections.json     sessions.json
    ├── kernel_modules.json    persistence.json
    ├── memory.raw         (if acquired)
    ├── capture.pcap       (capture runs)
    ├── pcap_analysis.json (parse-pcap runs)
    └── report.json  report.md  report.html
```

Why a directory: an analyst can hash, cite, diff and hand off a single artifact
without unpacking anything, and a multi-gigabyte memory image never has to be
read into a container format. The [Recover module](Home.md#the-suite) consumes
these directories directly.

**Containers are never appended to.** Pointing `-o` at a directory that already
holds a `custody.log` is refused:

```
error: ./ev-host01 already contains a custody log; refusing to append to an
       existing container
```

One run, one container. Two runs with interleaved custody timestamps would be a
chain of custody nobody could read.

Full format reference: [The Evidence Container](05-Evidence-Container.md).

---

## The chain of custody

`custody.log` is append-only, one record per line:

```
<ed25519-signature-hex> <record-json>
```

A real line, wrapped for legibility:

```
6b3ce525…39a005 {"seq":1,"ts_utc":"2026-08-28T16:19:01.581837122Z","mono_ns":37550,
"operator":"analyst-7","event":"note","detail":"invocation: arachnid-core collect
-o ./demo --operator analyst-7 --no-hash-binaries","prev":"e6bdf9ef…"}
```

Three properties combine to make the container tamper-evident:

| Tampering | Detected by |
|---|---|
| Editing an artifact | its recorded SHA-256 no longer matches |
| Editing a log record | that line's signature no longer verifies |
| Deleting or reordering records | the `prev` hash chain breaks |
| Adding an unlogged artifact | file present on disk with no custody record |

Each record's `prev` field holds the SHA-256 of the **entire previous line's
exact bytes**, which is what makes the log a chain rather than a list.

Signing is over the exact bytes following the first space on the line. **Nothing
is re-serialized during verification**, so JSON canonicalization is never a
correctness question — a consumer that re-orders keys cannot accidentally
invalidate a signature, and one that rewrites a record cannot re-sign it without
the operator's key.

Four event types: `run_start` (carries the manifest digest), `artifact`, `note`,
`run_end`.

The invocation itself is recorded as a `note`, so the log states what was
*asked for* as well as what came back.

---

## Signing keys and what verification proves

**This is the most important thing on this page.**

Without `--signing-key`, Arachnid generates an Ed25519 key for that run alone.
That makes the container tamper-**evident** against modification after
collection — which is what most of the tamper matrix above is about. But anyone
who can rewrite the whole container can also swap the public key in
`manifest.json` and re-sign every record. `verify` will then print VERIFIED.

So:

| | Ephemeral key (default) | Persistent key (`--signing-key`) |
|---|---|---|
| Proves **integrity** — nothing changed since the log was written | ✅ | ✅ |
| Proves **origin** — this came from this responder | ❌ | ✅, *if* the fingerprint matches one recorded out-of-band |

The fingerprint (SHA-256 of the public key) is printed at the end of **every**
run, precisely so it can be recorded:

```
Signing key fingerprint: 6e5cbdeecd531dc9b69681ac71b890c6e5338b0dd9664823626c6f9c03d827c7
Record this fingerprint out-of-band; `verify` can only prove origin against it.
```

**For chain of custody that must survive challenge in a proceeding, issue each
responder a persistent key and always pass `--signing-key`.** Record the
fingerprint once, in a system the adversary cannot also rewrite.

The key file is a 32-byte Ed25519 seed, raw or hex — both are accepted:

```bash
head -c 32 /dev/urandom > ~/.arachnid/analyst-7.key
chmod 600 ~/.arachnid/analyst-7.key
```

The fingerprint is stable across every run with that key.

---

## Two clocks

Every custody record carries both:

| Field | What it is | Why |
|---|---|---|
| `ts_utc` | wall clock, RFC 3339 UTC | what an analyst reads and cites |
| `mono_ns` | nanoseconds since container creation, monotonic | preserves **ordering** when the examined host's clock steps mid-collection |

A hostile host — or an ordinary NTP correction — can move the wall clock
backwards while collectors are running. The monotonic offset cannot be moved.
Use `ts_utc` for the timeline you present; use `mono_ns` when you need to prove
the order things actually happened in.

---

## Degraded collection is loud

Collectors **degrade rather than abort**. A host where `/proc/<pid>/maps` is
unreadable, or where the operator lacks privilege for one query, still yields
evidence for everything else.

But the gap is recorded in four places:

1. `Collection.warnings` in the JSON report,
2. a `note` record in the custody log (`collector degraded: …`),
3. the top of the Markdown and HTML report, under **⚠ Collection gaps**,
4. exit code **4**.

```
## ⚠ Collection gaps

These collectors did not complete. Absence below is not evidence of absence on the host.

- sessions: read /var/run/utmp: No such file or directory (os error 2)
```

**An empty result set is never allowed to look like a clean host.** That sentence
is the whole design rule. "No persistence entries found" and "nobody looked" are
different findings, and confusing them is how a triage tool gets someone hurt.

---

## Exit codes

Stable across releases, so SOAR playbooks and IR scripts can branch on them.

| Code | Name | Meaning |
|---|---|---|
| `0` | OK | everything requested completed |
| `1` | ERROR | runtime failure — I/O, permission, missing device, unusable input |
| `2` | USAGE | argument or usage error (from `clap`) |
| `3` | INTEGRITY | `verify` found a container that does not check out |
| `4` | PARTIAL | evidence was produced, but at least one collector was degraded |

**Code 4 is the one worth special handling.** You *have* evidence and it is
incomplete. Treating it as success loses the gap; treating it as failure loses
the evidence. Read `warnings` and record what was missed.

`capture` also returns 4 when the kernel or interface dropped packets — a
capture with drops has gaps in exactly the same sense.

Scripting example: [Workflows § SOAR integration](09-Workflows.md#workflow-5--soar-and-scripted-response).

---

## The read-only rule

Stated once, formally, because it is the property everything else rests on:

> Arachnid Core never writes to the system under examination. The only writes go
> to the evidence container directory named by `-o/--output`, plus the
> operational log path if `--log` is given.

**This rule is about Arachnid Core.** The suite also ships `arachnid-sanitize`,
whose entire purpose is to write to a device until nothing is recoverable. It is
a separate binary, a separate allowlisting decision, and a separate chapter —
[Secure Erasure](14-Secure-Erasure.md). Nothing below applies to it.

Consequences you can rely on:

- No temp files, anywhere.
- No configuration file is read or written.
- All registry access is `KEY_READ`. No key or value is created, modified or
  deleted.
- No scheduled task is registered or removed. No systemd unit is enabled or
  disabled. Persistence is **enumerated**, never touched.
- No process memory is written. No thread is created in another process.
- No outbound network connection of any kind. No telemetry, no update check, no
  indicator lookup, no DNS resolution of anything collected.
- No listening sockets.
- No self-persistence: no service, task, key or unit is installed.

Every one of these is enumerated with the exact paths and APIs in
[SOC-ALLOWLISTING.md](../SOC-ALLOWLISTING.md).

---

## Dry run

`--dry-run` runs **every collector and every hash** while writing nothing at
all — not even the container directory:

```bash
arachnid-core collect -o ./ev-test --dry-run
ls ./ev-test
# ls: cannot access './ev-test': No such file or directory
```

The custody chain is still computed in memory, so the same code path executes.
This exists so you can validate an EDR rule before a real engagement: the SOC
watches exactly what the tool touches, and no evidence is produced that you then
have to account for.

In a dry run, artifact records are written to the (in-memory) log with no digest
and a `"dry-run"` detail; `verify` renders those as
`no digest recorded (dry run)` rather than as failures.

Memory acquisition is skipped in a dry run — the acquisition tool is not
executed.

---

## Two logs

They are strictly separate and never share a stream.

| | Evidence log | Operational log |
|---|---|---|
| Where | `<container>/custody.log` | stderr, or `--log <path>` |
| Signed | yes, per line | no |
| Purpose | chain of custody | debugging, operational visibility |
| Verbosity | fixed | `--log-level`, or `ARACHNID_LOG` |
| In the TUI | same file | in-app pane, `Ctrl-L`, last 1000 lines |

`--log-level` takes precedence over `ARACHNID_LOG`: an operator who asks for a
level on the command line gets it regardless of the ambient environment. Default
is `info`.

In human mode the report goes to **stdout** and the operational log to
**stderr**, so the two never interleave and `> report.md` does what you expect.

---

## Two front ends, one engine

`arachnid-core` (CLI) and `arachnid-tui` (TUI) are both thin layers over the
same four library crates. (`arachnid-sanitize` is a third binary over a
different, destructive engine — see [Secure Erasure](14-Secure-Erasure.md).)

- The TUI **never shells out** to the CLI. It calls the same library functions.
- The TUI can do **nothing the CLI cannot**. It is a subset — see
  [what the TUI does not expose](04-TUI-Guide.md#what-the-tui-does-not-expose).
- A container written by the TUI verifies with the CLI, and validates against
  the same published schemas.
- Both go through `arachnid_report::seal_into`, so the JSON, Markdown and HTML
  renderings can never disagree between front ends.

---

## Vocabulary

| Term | Means |
|---|---|
| **Container** | the output directory of one run: manifest, custody log, artifacts |
| **Artifact** | one collected file inside `artifacts/` |
| **Custody record** | one signed line of `custody.log` |
| **Manifest** | `manifest.json` — run metadata and the public key |
| **Fingerprint** | SHA-256 of the Ed25519 public key; the value you record out-of-band |
| **Collector** | one of the five volatile-state gatherers: processes, connections, sessions, kernel_modules, persistence |
| **Indicator** | something extracted from packet bytes that an analyst pivots on: an IP, DNS name, TLS SNI, HTTP host/URI/UA |
| **Flow** | one transport-layer conversation, keyed by the 5-tuple as first observed |
| **Degraded** | a collector that failed; recorded in `warnings` and exit code 4 |
| **Sealed** | an artifact written by something else (pcap, AVML) and then hashed into the custody log |
| **Clearance** | Sanitize only: proof every safety rail passed for one specific wipe. `engine::wipe` accepts nothing else |
| **Certificate** | Sanitize only: the signed statement that a device was erased and the erasure verified |

---

[← Getting Started](01-Getting-Started.md) · [Home](Home.md) · [Next: CLI Reference →](03-CLI-Reference.md)
