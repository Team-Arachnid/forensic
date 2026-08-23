---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 5 · The Evidence Container

[← Terminal UI](04-TUI-Guide.md) · [Home](Home.md) · [Next: Collectors →](06-Collectors.md)

The container is the point of the tool. Everything else produces data; this is
what makes the data defensible.

Container schema version: **1.0.0**.

---

## Contents

- [Layout](#layout)
- [`manifest.json`](#manifestjson)
- [`custody.log`](#custodylog)
- [Record fields](#record-fields)
- [The hash chain](#the-hash-chain)
- [The signature scheme](#the-signature-scheme)
- [Artifacts](#artifacts)
- [Verification, step by step](#verification-step-by-step)
- [The tamper matrix](#the-tamper-matrix)
- [Dry-run containers](#dry-run-containers)
- [Reading a container by hand](#reading-a-container-by-hand)
- [Writing a third-party verifier](#writing-a-third-party-verifier)

---

## Layout

A container is a **directory**, not an archive.

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

Which artifacts appear depends on the subcommand:

| Subcommand | Artifacts |
|---|---|
| `collect` | the five collector JSONs, `memory.raw` if acquired, plus the three reports |
| `capture` | `capture.pcap`, plus the three reports |
| `parse-pcap` | `pcap_analysis.json`, plus the three reports |

The three reports — `report.json`, `report.md`, `report.html` — are written last
and hashed like any other artifact, so the summary is covered by the same
custody chain as the evidence it describes.

**Containers are never appended to.** Pointing `-o` at a directory that already
holds a `custody.log` is refused before anything is written.

---

## `manifest.json`

Run metadata, written once at creation and never modified.

```json
{
  "schema_version": "1.0.0",
  "tool": "arachnid-core",
  "tool_version": "0.1.0",
  "container_id": "848b9f935ffcfb4e757c80712b3c61a3",
  "created_utc": "2026-08-28T16:19:01.581759466Z",
  "operator": "analyst-7",
  "host": "arch",
  "platform": "linux/x86_64",
  "public_key": "4d321e81c9f87371a7cc5d5087ebe6c283d6acfc0806a76c10bef23abeb35bde"
}
```

| Field | Meaning |
|---|---|
| `schema_version` | container layout version. Bumped on any incompatible change |
| `tool` / `tool_version` | which build produced this |
| `container_id` | 128 random bits, hex. Unique per run |
| `created_utc` | RFC 3339 UTC, at container creation |
| `operator` | as supplied. **Self-asserted** — attributable only through the signing key |
| `host` | from `HOSTNAME`, `COMPUTERNAME`, or `/proc/sys/kernel/hostname` |
| `platform` | `<os>/<arch>` |
| `public_key` | Ed25519 verifying key, 32 bytes hex |

The manifest's own SHA-256 is recorded in the **first** custody record
(`run_start`), so editing the manifest — including swapping the public key — is
itself detectable, as long as you have the record's signature to check it
against.

> `public_key` must be trusted **out-of-band**. An attacker who can rewrite the
> whole container can swap this key and re-sign every record. The fingerprint
> printed at the end of a run is what closes that gap. See
> [Concepts § Signing keys](02-Concepts.md#signing-keys-and-what-verification-proves).

---

## `custody.log`

Append-only. One record per line. Each line is:

```
<ed25519-signature-hex> <record-json>
```

- The signature is **128 hex characters** (64 bytes).
- Exactly one space separates it from the record.
- The record is compact JSON (no pretty-printing, no trailing newline inside).
- The line ends with `\n`.
- Every line is `fsync`ed before the next is written, so custody entries survive
  a crash mid-collection.

A real first line, wrapped here for legibility:

```
323ae9b6…3640d {"seq":0,"ts_utc":"2026-08-28T16:19:01.581802898Z","mono_ns":3386,
"operator":"analyst-7","event":"run_start","name":"manifest.json",
"sha256":"c5179bdb1071c43dc3131853094430cb6b49f67faeaedf2ce99cc2662a2d3313",
"prev":"0000000000000000000000000000000000000000000000000000000000000000"}
```

A typical `collect` run produces 11 records:

| `seq` | `event` | Which |
|---|---|---|
| 0 | `run_start` | manifest digest |
| 1 | `note` | the invocation |
| 2–6 | `artifact` | the five collector JSONs |
| 7–9 | `artifact` | `report.json`, `report.md`, `report.html` |
| 10 | `run_end` | closes the log |

Degraded collectors add a `note` each (`collector degraded: sessions: …`).

---

## Record fields

Formally specified in
[`schema/custody.schema.json`](../../schema/custody.schema.json).

| Field | Type | Required | Meaning |
|---|---|---|---|
| `seq` | integer ≥ 0 | ✅ | zero-based position. **Must** increase by exactly one per line |
| `ts_utc` | RFC 3339 UTC | ✅ | wall clock at the event. Subject to clock adjustment on the examined host |
| `mono_ns` | integer ≥ 0 | ✅ | nanoseconds since container creation, monotonic. Immune to NTP steps and to a hostile host moving its clock |
| `operator` | string | ✅ | identity as supplied. Self-asserted |
| `event` | enum | ✅ | `run_start` \| `artifact` \| `note` \| `run_end` |
| `name` | string | for `artifact` | path relative to `artifacts/` |
| `sha256` | 64 hex chars | for `artifact` | the artifact's digest. Absent for a dry-run placeholder |
| `size` | integer | for `artifact` | bytes on disk |
| `detail` | string | for `note` | free text |
| `prev` | 64 hex chars | ✅ | SHA-256 of the **entire previous line's exact bytes**; all zeroes for `seq: 0` |

**Field order is the serialization order and is part of the signed bytes.**
Reordering them without bumping `schema_version` would invalidate every existing
signature.

Optional fields use `skip_serializing_if`, so absent means absent — a `note`
record simply has no `name`, `sha256` or `size` key.

### Two clocks, again

`ts_utc` is what an analyst reads and cites. `mono_ns` is what preserves
ordering when the examined host's clock steps mid-collection — from an ordinary
NTP correction or from an adversary. If the two disagree about ordering, trust
`mono_ns`, and say so in your notes.

---

## The hash chain

```
line[0].prev = 000…000                    (genesis)
line[n].prev = SHA-256(exact bytes of line[n-1], excluding the trailing newline)
```

The hashed input is the **entire line** — signature, space, and record JSON —
not just the record. That is what makes deletion, reordering and truncation all
detectable:

- **Delete a record** → the next record's `prev` no longer matches.
- **Reorder records** → same.
- **Edit a record** → its own signature fails *and* the next record's `prev`
  fails.
- **Truncate the log** → `run_end` is missing; the chain up to the cut is still
  internally consistent, which is why you also check for `run_end`.

---

## The signature scheme

- Algorithm: **Ed25519** (`ed25519-dalek`).
- Key: 32-byte seed. Provided by `--signing-key` (raw or hex), or generated per
  run from the OS CSPRNG.
- Signed input: **the exact bytes following the first space on the line** — the
  record JSON, as written.
- Encoding: signature hex-encoded, lowercase, 128 characters.

> **Nothing is re-serialized during verification.** The verifier reads the raw
> bytes and checks them; it never parses the record and re-emits it. So JSON
> canonicalization is not a correctness question for Arachnid, and it is not one
> for you either: a consumer that re-orders keys in memory cannot invalidate a
> signature, and one that rewrites a record on disk cannot re-sign it without
> the operator's key.

### Key fingerprint

```
fingerprint = SHA-256(public_key_bytes)   # 32 raw bytes, not the hex string
```

Printed at the end of every run and by `verify`. This is the value to record
out-of-band.

---

## Artifacts

Artifacts reach the container two ways:

**Written by Arachnid** — `add_bytes` / `add_json`. The bytes are hashed as they
are written; JSON artifacts are pretty-printed.

**Written by something else, then sealed** — `seal`. Used for
`capture.pcap` (written by libpcap) and `memory.raw` (written by the acquisition
tool). Arachnid hands out the path via `artifact_path`, the external writer
fills it, and `seal` then streams the file to compute its digest and size.

Streaming matters: `sha256_file` reads in 1 MiB chunks, so a multi-gigabyte
memory image is hashed without ever landing in RAM.

Nested paths are supported (`name` may contain `/`), and are normalized with
forward slashes when verification walks the directory, so a container written on
Windows verifies on Linux.

---

## Verification, step by step

`arachnid-core verify <container>` — deliberately implemented **independently of
the collection path**. It re-reads and re-hashes from disk rather than sharing
any writer state, so a bug in collection cannot make a broken container verify
clean.

### 1 · Read the manifest

`manifest.json` must exist and parse. If it does not, that is a **runtime
error** (exit 1) — the container is unreadable, not tampered.

### 2 · Recover the public key

If `public_key` is not 32 hex-encoded bytes, or is not a valid Ed25519 key,
that is an **integrity problem** (exit 3), not a runtime error — and
verification **continues without signature checks**, because the hash chain and
the artifact digests still have something to say about what was changed.

```
FAILED: 1 problem(s).
  - manifest public_key is not a valid Ed25519 key
```

Artifacts are still hashed and reported, so you learn what else is intact.

### 3 · Walk the log, line by line

For each line, in order:

| Check | Problem when it fails |
|---|---|
| a space separates signature from record | `line N: malformed, no signature separator` |
| the Ed25519 signature verifies | `line N: signature does not verify` |
| the record parses as JSON | `line N: unparseable record: …` |
| `seq` equals the expected value | `line N: sequence X out of order, expected Y` |
| `prev` equals SHA-256 of the previous line | `line N: hash chain broken (record removed, reordered, or edited)` |

Failures do not stop the walk. Verification reports **everything** that is
wrong, not the first thing.

### 4 · Check each artifact record

For every `event: "artifact"` record:

| Check | Problem when it fails |
|---|---|
| the record has a `name` | `line N: artifact record without a name` |
| the file exists and is readable | `artifact X: missing` |
| its SHA-256 matches `sha256` | `artifact X: content modified since collection` |
| its size matches `size` | `artifact X: size differs from record` |

A record with no `sha256` is a dry-run placeholder and is reported as
`no digest recorded (dry run)` — a note, not a problem.

### 5 · Check for unlogged files

Every file under `artifacts/` is compared against the set of logged names:

```
artifact evil.txt: present on disk but not in custody log
```

**A file nobody logged is as much a tamper signal as a modified one.** An
attacker who adds a file cannot add a matching custody record without the key.

### 6 · Verdict

```rust
ok = problems.is_empty()
```

Exit **0** if ok, **3** otherwise.

---

## The tamper matrix

| Tampering | Detected by | Message |
|---|---|---|
| Edit an artifact | recorded SHA-256 no longer matches | `content modified since collection` |
| Truncate or pad an artifact | recorded size no longer matches | `size differs from record` |
| Delete an artifact | file missing | `missing` |
| Plant an extra file | present on disk, absent from the log | `present on disk but not in custody log` |
| Edit a custody record | that line's signature fails | `signature does not verify` |
| Delete a custody record | the next record's `prev` fails | `hash chain broken` |
| Reorder custody records | `prev` and `seq` both fail | `hash chain broken`, `sequence out of order` |
| Corrupt the public key | key does not decode or is not valid Ed25519 | `manifest public_key is not …` |
| **Rewrite everything and re-sign under a new key** | **not detected by `verify` alone** | — see below |

The last row is the honest limit of tamper-evidence without an external anchor.
`verify` will print VERIFIED for a wholly reconstructed container, because it
*is* internally consistent. What catches it is the fingerprint: if the
fingerprint printed by `verify` is not the one recorded out-of-band at
collection, the container did not come from that responder — whatever else it
says.

Each row above has a corresponding test in
`crates/arachnid-evidence/src/lib.rs`.

---

## Dry-run containers

`--dry-run` runs the entire code path — collectors, hashing, chain
construction — while writing nothing, including the container directory itself.
Nothing reaches disk, so there is no container to verify afterwards.

The distinction matters if you are reading the code: `Container::add_bytes` in a
dry run still computes the digest and appends a record to the in-memory chain;
`Container::seal` appends a record with no digest and a `"dry-run"` detail,
because there is no file to hash. It is the same code path, which is the point.

---

## Reading a container by hand

You do not need Arachnid to read a container. Everything is text.

**The manifest:**

```bash
jq . ev-host01/manifest.json
```

**Every custody record, pretty:**

```bash
cut -d' ' -f2- ev-host01/custody.log | jq .
```

**Just the artifacts and their digests:**

```bash
cut -d' ' -f2- ev-host01/custody.log \
  | jq -r 'select(.event=="artifact") | "\(.sha256)  \(.name)"'
```

```
db2a865115beb1ec6a7cf9bd70b55d37735a6b09f241a5ecc6fe2ea22b0b36e2  processes.json
4b81618bddcb869ee417a109de58ae0c0b8536b3fe09182fa1261ac7df56a851  connections.json
80303b515fcf0e01d738150c96dc819e36f175a02a6b2af9536b66307a6c347c  sessions.json
…
```

**Check those digests with coreutils, no Arachnid at all:**

```bash
cd ev-host01/artifacts
cut -d' ' -f2- ../custody.log \
  | jq -r 'select(.event=="artifact" and .sha256) | "\(.sha256)  \(.name)"' \
  | sha256sum -c -
```

```
processes.json: OK
connections.json: OK
sessions.json: OK
…
```

That checks artifact integrity. It does **not** check signatures or the chain —
for that you need the public key and an Ed25519 implementation, or
`arachnid-core verify`.

**The timeline:**

```bash
cut -d' ' -f2- ev-host01/custody.log \
  | jq -r '[.seq, .ts_utc, .event, (.name // .detail // "")] | @tsv'
```

**Any degraded collectors:**

```bash
jq -r '.collection.warnings[]?' ev-host01/artifacts/report.json
```

---

## Writing a third-party verifier

Everything you need is in this page and the two schemas. The algorithm:

1. Parse `manifest.json`; decode `public_key` from hex to 32 bytes.
2. Set `expect_prev = "0" * 64`, `expect_seq = 0`.
3. For each line of `custody.log`, **as raw bytes**:
   1. split at the first `0x20`; the left side is 128 hex chars of signature,
      the right side is the signed message — **use it verbatim, do not
      re-serialize**;
   2. verify the Ed25519 signature over the right side;
   3. parse the right side as JSON; check `seq == expect_seq` and
      `prev == expect_prev`;
   4. set `expect_prev = SHA256(the whole line, without the trailing newline)`,
      `expect_seq = seq + 1`;
   5. if `event == "artifact"`, hash `artifacts/<name>` and compare to `sha256`
      and `size`.
4. Walk `artifacts/` and flag any file that no record named.
5. Compare the fingerprint — `SHA256(public_key_bytes)` — against the value
   recorded out-of-band at collection.

Step 5 is the one that turns integrity into origin. Do not skip it.

A working validator for the *schema* side is
[`scripts/validate-schemas.py`](../../scripts/validate-schemas.py), which CI runs
against a freshly produced container on every push.

---

[← Terminal UI](04-TUI-Guide.md) · [Home](Home.md) · [Next: Collectors →](06-Collectors.md)
