---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 8 · Reports & Schemas

[← Network Forensics](07-Network-Forensics.md) · [Home](Home.md) · [Next: Workflows →](09-Workflows.md)

**The JSON report is the contract.** The Markdown and HTML renderings are for a
human skimming the run and carry no information the JSON lacks — which is why
they can be regenerated at any time with `arachnid-core report`.

Report schema version: **1.0.0**.

---

## Contents

- [Three renderings, one source](#three-renderings-one-source)
- [`report.json`](#reportjson)
- [Schema versioning](#schema-versioning)
- [The Markdown summary](#the-markdown-summary)
- [The HTML report](#the-html-report)
- [Escaping and hostile input](#escaping-and-hostile-input)
- [The published schemas](#the-published-schemas)
- [Validating output](#validating-output)
- [Consuming a report](#consuming-a-report)

---

## Three renderings, one source

Every front end goes through one function, `arachnid_report::seal_into`, which:

1. serializes the report to JSON,
2. writes `report.json` as an artifact,
3. renders Markdown from the same in-memory report and writes `report.md`,
4. renders HTML from that Markdown and writes `report.html`.

So the three can never disagree, and all three are covered by the same custody
chain as the evidence they describe. `report.json` is written first because it is
the contract.

```
artifacts/report.json    the machine-readable contract
artifacts/report.md      human summary, top-N tables
artifacts/report.html    self-contained page, no external assets
```

---

## `report.json`

```json
{
  "schema_version": "1.0.0",
  "manifest": { … },
  "collection": { … },     // present for a collect run
  "memory": { … },         // present when memory was acquired
  "capture": { … },        // present for a capture run
  "pcap": { … },           // present for a parse-pcap run
  "artifacts": [
    { "name": "processes.json", "sha256": "db2a8651…b36e2" }
  ]
}
```

| Field | Required | Present when |
|---|---|---|
| `schema_version` | ✅ | always. `^\d+\.\d+\.\d+$` |
| `manifest` | ✅ | always — a copy of `manifest.json` as written at run start |
| `collection` | | a `collect` run |
| `memory` | | memory was acquired |
| `capture` | | a `capture` run |
| `pcap` | | a `parse-pcap` run |
| `artifacts` | ✅ | always. `name` → `sha256` index |

Absent sections are **omitted**, not null.

> `artifacts` is a **convenience index**. The custody log remains the authority;
> verify against it, not against this list.

### `collection`

Required keys: `processes`, `connections`, `sessions`, `kernel_modules`,
`persistence`, `warnings` — all arrays, all always present, even when empty.

**`warnings` is the one to check first.** A non-empty array means the
corresponding arrays are **incomplete**, and an empty list there is not evidence
of absence on the host. The process exits **4** when it is non-empty.

Element shapes are documented in [Collectors](06-Collectors.md) and specified in
the schema.

### `memory`

Records the acquisition tool invocation: `tool`, `tool_sha256` (verified
**before** execution), `args`, `output_artifact`, `started_utc`, `finished_utc`,
`exit_code`, `stderr_tail` (last 20 lines).

### `capture`

`device`, `filter`, `promiscuous`, `snaplen`, `datalink`, the time window,
`packets_written`, `bytes_written`, `packets_dropped_kernel`,
`packets_dropped_interface`, `stop_reason`.

> **Non-zero drops mean the capture has gaps. Treat the PCAP as incomplete
> evidence.** That sentence is in the schema itself, so a consumer that reads
> the schema cannot claim it was not told.

### `pcap`

`source`, `source_sha256`, `datalink`, `packets`, `bytes`, `decode_errors`, the
packet-time window, `flows[]` and `indicators[]`. See
[Network Forensics](07-Network-Forensics.md).

---

## Schema versioning

Two independent versions live in a container:

| Version | Governs | Current |
|---|---|---|
| `manifest.schema_version` | the **container layout** — the on-disk structure and the custody record shape | `1.0.0` |
| report `schema_version` | the **report document** shape | `1.0.0` |

They are independent by design: the container format can stabilize while the
report grows fields, and vice versa.

**Consumers must reject a major version they do not implement.** Arachnid does
this itself — `arachnid-core report` refuses a report whose major version this
build does not know:

```
error: report schema 2.0.0 is not supported by this build (expected 1.x)
```

A consumer should do the same:

```python
major = report["schema_version"].split(".")[0]
if major != "1":
    raise SystemExit(f"unsupported report schema {report['schema_version']}")
```

Within a major version, expect **additive** changes: new optional fields, new
enum members. Do not write a consumer that fails on an unknown key it does not
need — but note that the published schemas set `additionalProperties: false`,
so validation *will* flag genuinely unexpected keys, which is what makes drift
detectable in CI.

---

## The Markdown summary

Printed to stdout by every container-producing run, written as `report.md`, and
regenerable with `arachnid-core report --format markdown`.

Sections, in order, each present only when it has content:

| Section | Contents |
|---|---|
| Header table | container id, collection time, host, operator, tool version, signing key, report schema |
| **⚠ Collection gaps** | every degraded collector, with the reason. First, because it changes how you read everything below |
| Summary | counts: processes, connections, listening sockets, connections to routable addresses, sessions, kernel modules, persistence entries |
| Active sessions | user, terminal, remote host, login time |
| Connections to routable addresses | sorted by remote address — where triage starts |
| Persistence entries | kind, location, name, value |
| Processes with an unhashable image | PID, name, path |
| Memory acquisition | tool, verified hash, image, time window |
| Live capture | device, filter, promiscuous, packets, window, stop reason, **drops** |
| PCAP analysis | source and its digest, packets, flows, window, indicators, top flows |
| Artifacts | every artifact and its SHA-256 |

### Top-N truncation

Human tables cut at **20 rows** (40 for indicators), with a marker:

```
_483 more in the JSON report._
```

**The JSON always holds everything.** Top-N governs only what fits on a screen.
If a table is truncated, go to `report.json` — or to the per-collector artifact,
which is the same data without the summary's framing.

### "Connections to routable addresses"

Excludes loopback, private (RFC 1918), link-local, broadcast, multicast and
unspecified addresses. What remains is traffic that actually left the network,
which is where an investigation usually starts.

### "Processes with an unhashable image"

> A missing hash means the path did not resolve to a readable file: a deleted or
> replaced binary, or insufficient privilege.

A process whose `exe` is set but whose `exe_sha256` is `null`, when you *were*
privileged, is worth a second look.

---

## The HTML report

```bash
arachnid-core report ./ev-host01 --format html -o triage.html
```

A **single self-contained file**: no external stylesheets, no fonts, no scripts,
no images. It renders on an air-gapped analysis workstation, which is where
evidence usually gets read.

- `color-scheme: light dark` — respects the reader's system theme.
- Tables scroll horizontally inside their own container rather than breaking the
  page.
- System font stack; monospace for code spans.

The renderer is a small Markdown-to-HTML pass over the summary that handles
exactly the constructs the summary uses: headings, tables, list items,
paragraphs, `code` spans, and `**bold**`. It is not a general Markdown engine,
and does not need to be.

---

## Escaping and hostile input

**Collected content is attacker-controlled.** Process command lines, DNS names,
HTTP headers, User-Agents and persistence values all come from a host that may
be compromised, and an attacker who anticipates a triage tool can plant
something designed to break the report that renders it.

Arachnid's rule:

> Store verbatim. Escape on output.

- Values are stored in the JSON exactly as collected — nothing is sanitized
  away, because a sanitized artifact is a modified artifact.
- The HTML renderer escapes `&`, `<` and `>` in **every** field, including
  inside table cells and code spans, before re-applying the two inline markers
  the summary uses.
- There is a test asserting that a `<script>` tag in a hostname cannot break out
  of the page.

**Anything downstream that renders this data must escape it too.** If you build
a dashboard on `report.json`, treat every string field as untrusted input. The
JSON is faithful, not safe — that is the correct trade, and it makes the
escaping obligation yours at the point of display.

The Markdown renderer escapes `|` inside truncated cells so a value containing a
pipe cannot break a table, and truncates long values with `…`.

---

## The published schemas

| File | Describes |
|---|---|
| [`schema/report.schema.json`](../../schema/report.schema.json) | the full report document |
| [`schema/custody.schema.json`](../../schema/custody.schema.json) | one custody record (the JSON after the signature) |
| [`schema/samples/`](../../schema/samples/) | a real erasure certificate in JSON, Markdown and HTML — see [Secure Erasure](14-Secure-Erasure.md#certificates-and-the-register) |

Arachnid Sanitize carries its own `SCHEMA_VERSION` (also `1.0.0`) for the
certificate layout, versioned independently of the report and container
schemas. The samples are **generated by a test**, so they cannot drift from real
output.

Both are JSON Schema **draft 2020-12**. Both use `additionalProperties: false`
throughout, and both carry prose descriptions on the fields that carry a
caveat — the drop counters, the `warnings` array, `exe_sha256` being null, the
self-asserted operator, the out-of-band trust requirement on `public_key`.

Read the schema descriptions. They are not filler; several of them are the only
place a specific caveat is stated formally.

The container format is **shared with the Arachnid Recover module**, which
consumes these containers directly. That is why the schemas are a contract and
not just documentation.

---

## Validating output

CI produces a **real container** on every push and validates it against the
published schemas — not a hand-written fixture, because drift between what the
tool emits and what the schema promises is a breaking change that must not merge
silently.

```bash
pip install jsonschema
arachnid-core collect -o ./ci-container --no-hash-binaries
python3 scripts/validate-schemas.py ./ci-container
```

```
schemas are valid draft 2020-12
report.json validates: {'processes': 989, 'connections': 26, 'sessions': 1,
                        'kernel_modules': 198, 'persistence': 765, 'warnings': 0}
all 11 custody records validate
```

The script also checks that every custody signature is exactly 128 hex
characters before validating the record body.

Run it against any container you receive, not just your own.

---

## Consuming a report

### Check the version first

```bash
jq -r '.schema_version' ev/artifacts/report.json
```

### Check for gaps before you trust a count

```bash
jq -r '.collection.warnings[]?' ev/artifacts/report.json
```

If that prints anything, every "we found N of X" statement below it is a floor,
not a total.

### Useful queries

```bash
# every listening socket with its owner
jq -r '.collection.connections[]
       | select(.state == "LISTEN")
       | "\(.protocol)\t\(.local_addr):\(.local_port)\t\(.process_name // "-")"' \
   ev/artifacts/report.json

# processes running from a temp or user-writable path
jq -r '.collection.processes[]
       | select(.exe != null and (.exe | test("/tmp/|/dev/shm/|\\\\AppData\\\\")))
       | "\(.pid)\t\(.exe)"' ev/artifacts/report.json

# persistence entries whose backing file could not be hashed
jq -r '.collection.persistence[]
       | select(.sha256 == null)
       | "\(.kind)\t\(.location)\t\(.name)"' ev/artifacts/report.json

# every distinct binary hash, for bulk lookup against your own corpus
jq -r '.collection.processes[].exe_sha256 | select(. != null)' \
   ev/artifacts/report.json | sort -u

# capture drop check
jq '.capture | select(.) | {dropped: .packets_dropped_kernel, written: .packets_written}' \
   ev/artifacts/report.json
```

### Prefer the per-collector artifact

`report.json` embeds the full collection, which makes it large — the demo run
above produced a 3.3 MB `report.json` next to a 2.8 MB `processes.json`. If you
only need one collector, read its artifact directly:

```bash
jq '.[] | select(.name == "sshd")' ev/artifacts/processes.json
```

Each is hashed and cited independently in the custody log, so using one on its
own loses nothing evidentially.

### Never re-render by hand

If you need Markdown or HTML, call `arachnid-core report`. Re-rendering from
your own template risks a summary that disagrees with the container it claims to
describe — and unlike the tool's own output, yours is not covered by the custody
chain.

---

[← Network Forensics](07-Network-Forensics.md) · [Home](Home.md) · [Next: Workflows →](09-Workflows.md)
