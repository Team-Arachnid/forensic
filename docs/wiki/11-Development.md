---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 11 · Development

[← Security & Threat Model](10-Security-and-Threat-Model.md) · [Home](Home.md) · [Next: Troubleshooting →](12-Troubleshooting.md)

How the workspace is put together, how to build and test it, and how to add
something without breaking the properties the tool depends on.

---

## Contents

- [The eleven crates](#the-eleven-crates)
- [Dependency graph](#dependency-graph)
- [Building](#building)
- [Testing](#testing)
- [Linting the Windows code from Linux](#linting-the-windows-code-from-linux)
- [Supply-chain checks](#supply-chain-checks)
- [CI](#ci)
- [Adding a collector](#adding-a-collector)
- [Adding a TUI screen](#adding-a-tui-screen)
- [Changing the schema](#changing-the-schema)
- [House rules](#house-rules)

---

## The eleven crates

`arachnid-evidence` is the foundation every other one depends on.

| Crate | Binary | Responsibility |
|---|---|---|
| `arachnid-evidence` | — | hashing, Ed25519 custody chain, container creation, verification |
| `arachnid-collect` | — | read-only volatile collectors; external memory acquisition |
| `arachnid-netcap` | — | live capture, PCAP parsing, TCP reassembly, indicators |
| `arachnid-report` | — | schema-versioned JSON, Markdown and HTML summaries |
| `arachnid-core-cli` | `arachnid-core` | argument parsing, orchestration, exit codes |
| `arachnid-core-tui` | `arachnid-tui` | terminal UI over the same library calls the CLI makes |
| `arachnid-sanitize-core` | — | **destructive.** Device enumeration, wipe engines, safety rails, read-back verification, signed certificates |
| `arachnid-sanitize-cli` | `arachnid-sanitize` | argument parsing and orchestration for erasure |
| `arachnid-recover-core` | — | read-only NTFS/ext4/APFS parsing, signature carving, confidence scoring, export |
| `arachnid-recover-cli` | `arachnid-recover` | argument parsing and orchestration for recovery |
| `arachnid-cli` | `arachnid-cli` | the single entry point: the TUI bare, or dispatch into any of the three CLIs without re-exec. Also owns `doctor`, `self update` and the version check |

**The front ends contain no engine logic.** The TUI in particular is a
view/controller layer: it never shells out to a CLI, and it can do nothing the
CLIs cannot.

> `arachnid-sanitize-core` is the one crate in this workspace that **writes to
> the target by design**. Everything about its structure — the `Clearance`
> token, the non-`Clone` guarantee, the refusal-to-certify rule — exists because
> of that inversion. Read
> [Secure Erasure § The inversion](14-Secure-Erasure.md#the-inversion) before
> changing anything in it.

> `arachnid-recover-core` is its mirror image. Its `Source` trait has **no write
> method at all**, so no code path in the crate can write to the media under
> examination. The two traits must never converge, and a `write_at` on `Source`
> is not a feature request — it is the bug. See
> [File Recovery § Read-only, structurally](15-File-Recovery.md#read-only-structurally).

### Toolchain floors

| | Floor |
|---|---|
| workspace | Rust 1.82 |
| `arachnid-core-tui` | Rust 1.88 |
| `arachnid-sanitize-core` | Rust 1.88 |
| `arachnid-sanitize-cli` | Rust 1.88 |
| `arachnid-recover-core` | Rust 1.88 |
| `arachnid-recover-cli` | Rust 1.88 |
| `arachnid-cli` | Rust 1.88 |

The Core engine crates and `arachnid-core-cli` stay buildable on **1.82**, so a
locked-down build host with an older toolchain can still produce the triage CLI.
The crates above the floor need it for a real reason: ratatui 0.30 for the TUI,
and the `windows` crate's raw-device I/O for Sanitize and Recover. Keep it that
way — if a change to a Core engine crate needs 1.88, it belongs in a front end
instead.

---

## Dependency graph

```
                    arachnid-evidence
                     ▲      ▲      ▲
         ┌───────────┘      │      └───────────┐
  arachnid-collect          │            arachnid-netcap
         ▲                  │                  ▲
         └──────────► arachnid-report ◄────────┘
                       ▲          ▲
           arachnid-core-cli   arachnid-core-tui
```

Sanitize and Recover hang off `arachnid-evidence` too — Sanitize for the signing
and hash-chain construction its certificate register reuses, Recover for the
whole container it writes its exports into:

```
  arachnid-evidence ◄── arachnid-sanitize-core ◄── arachnid-sanitize-cli
                    ◄── arachnid-recover-core  ◄── arachnid-recover-cli
                                  ▲
                          arachnid-core-tui  (the Sanitize and Recover screens)
```

`arachnid-recover-core` also depends on `arachnid-sanitize-core`'s
`device::enumerate` — via the CLI and the TUI, not the engine — rather than
carrying a second device enumeration. That code is already read-only and already
computes the system-volume cross-reference; what Recover adds is a handle that
cannot write.

`arachnid-cli` sits above everything, linking the three CLIs and the TUI:

```
  arachnid-core-cli ──┐
  arachnid-recover-cli├──► arachnid-cli
  arachnid-sanitize-cli┤
  arachnid-core-tui ──┘
```

External dependencies are deliberately few:

| Crate | Used by | For |
|---|---|---|
| `anyhow` | all | error context |
| `serde`, `serde_json` | all | serialization |
| `sha2` | evidence | hashing |
| `ed25519-dalek`, `getrandom` | evidence | signing, entropy |
| `time` | evidence, netcap | RFC 3339 timestamps |
| `tracing`, `tracing-subscriber` | all | operational log |
| `sysinfo`, `netstat2` | collect | processes, sockets |
| `windows`, `windows-registry` | collect, tui (Windows) | Win32 query APIs |
| `pcap`, `etherparse` | netcap | capture, packet decode |
| `clap` | cli | argument parsing |
| `ctrlc` | cli | clean capture interruption |
| `ratatui` | tui | terminal rendering |
| `ureq`, `base64` | cli | the update check and `self update`. The only network client in the suite; see THREAT_MODEL.md |
| `windows` | sanitize-core, recover-core (Windows) | raw device I/O and storage ioctls |
| `tempfile` | sanitize-core, recover-core (dev) | file-backed virtual devices and export targets in tests |

Recover adds **no new external dependency**. Its filesystem parsers are
hand-written over byte slices rather than pulled from `ntfs`/`ext4`-style crates:
a triage binary that runs with high privilege on a possibly-compromised host
should be auditable end to end, and three parsers of a few hundred lines each
cost less trust than three more crates in the tree.

Before adding one, read [Supply-chain checks](#supply-chain-checks). Several
categories of crate are banned outright.

---

## Building

```bash
cargo build --release                        # everything
cargo build --release -p arachnid-core-cli   # just the CLI
cargo build --release -p arachnid-core-tui   # just the TUI
cargo build --release -p arachnid-sanitize-cli   # just the erasure CLI
cargo run -p arachnid-core-tui               # run the TUI
```

Release profile: `opt-level = "z"`, LTO, one codegen unit, `panic = "abort"`,
symbols stripped — a small single binary per platform.

Formatting is `rustfmt` with `max_width = 100`:

```bash
cargo fmt --all
cargo fmt --all --check     # what CI runs
```

Release builds: [Getting Started § Release build](01-Getting-Started.md#release-build).

---

## Testing

```bash
cargo test --workspace
```

**Tests run unprivileged.** Anything needing root — live capture, memory
acquisition — is exercised on its **refusal path** in CI and belongs to a
disposable-VM suite otherwise.

### What is covered, and why each test exists

| Area | Tests |
|---|---|
| `arachnid-evidence` | a clean container verifies; a modified, deleted, or planted artifact is detected; a removed log line breaks the chain; an edited line breaks its signature; a swapped or truncated public key is an integrity problem rather than a runtime error; a dry run writes nothing; hex round-trips |
| `arachnid-collect` | this process appears in its own process list and is not its own parent; connections enumerate unprivileged and have a valid protocol; named connections have a PID; `collect_all` never panics and its warnings are readable; **the progress callback reports exactly `COLLECTORS`, in order**; memory acquisition refuses a hash mismatch; `hash_file_opt` tolerates a missing file. Linux-specific: `/proc/modules` parses; persistence entries are well formed; `sessions` does not error when utmp exists; our own maps include our binary; the maps of a dead PID are `None` rather than an error |
| `arachnid-netcap` | a synthetic mixed capture yields the expected flows and indicators; a BPF filter narrows the parse; the reassembly ceiling is reported rather than silent; an empty capture is not an error; a truncated file fails loudly |
| `arachnid-report` | routable-address classification; collection gaps appear prominently in Markdown; **HTML escapes hostile content**; tables and code spans render; an empty report still renders; pipes in values do not break a table |
| `arachnid-core-cli` | collect → verify round trip; modified/planted artifact and truncated log all fail verification; dry run writes nothing; a supplied signing key is used and is reproducible; report re-renders; `--json` emits only JSON on stdout; collecting into an existing container is refused; memory acquisition refuses an unverified tool; missing `--memory-tool-sha256` is a usage error; error paths return the right exit codes; **the operational log stays separate from the evidence log**; `--help` documents the exit codes |
| `arachnid-core-tui` | **every screen renders at every supported size** with every overlay combination; the splash names the tool; **every advertised binding dispatches to its own action**; jump keys cover exactly the tabs; text input edits correctly |
| `arachnid-sanitize-core` | the unit suite covers every `authorize` rail; the **`safety_rails` integration suite** runs each one end to end against file-backed virtual devices — see below |

### The safety-rail suite

`crates/arachnid-sanitize-core/tests/safety_rails.rs` is the most important test
file in the repository, because it is the one standing between an operator and
the wrong drive. Each test is an end-to-end run against a file-backed virtual
device:

| Test | Asserts |
|---|---|
| `a_full_wipe_destroys_the_data_verifies_and_certifies` | the happy path actually destroys the seeded data |
| `a_serial_mismatch_is_refused_and_writes_nothing` | **and writes nothing** — the file is byte-identical after |
| `a_system_device_is_refused_without_the_force_flag` | the system-volume block holds |
| `forcing_a_system_device_clears_and_is_recorded_on_the_certificate` | the override is not silent |
| `a_hot_swapped_device_is_refused_even_with_the_right_serial` | re-enumeration catches path reuse |
| `a_device_that_vanished_is_refused` | so does a device that is simply gone |
| `a_device_without_a_serial_cannot_be_wiped_at_all` | no serial, no wipe |
| `crypto_erase_is_refused_because_this_build_cannot_confirm_an_sed` | the crypto-erase refusal cannot regress |
| `a_dry_run_writes_not_one_byte_and_earns_no_certificate` | both halves of the dry-run promise |
| `surviving_data_fails_verification_and_blocks_the_certificate` | verification actually detects surviving data |
| `a_cancelled_wipe_cannot_be_certified` | a partial wipe cannot be filed as a complete one |
| `every_method_leaves_exactly_its_final_pass_across_the_whole_device` | the pass sequences are byte-for-byte what the certificate claims |
| `a_purge_that_fell_back_says_so_on_the_certificate` | **no unearned compliance claim** |
| `the_register_detects_a_removed_certificate` | the certificate hash chain works |

Run it on its own, the way CI does:

```bash
cargo test -p arachnid-sanitize-core --test safety_rails
```

`tests/fixture.rs` regenerates the checked-in sample certificate in
`schema/samples/`, signing with a fixed key so the sample is stable across
regenerations and cannot drift from real output.

Three of the Core tests carry more weight than the rest:

- **`progress_reports_every_collector_in_order`** — drift here would show an
  operator a checklist that does not match the collection.
- **`every_screen_renders_at_every_supported_size`** — a layout that panics takes
  the terminal with it. This fails in CI instead of on a responder's laptop.
- **`every_advertised_binding_dispatches`** — the help overlay cannot advertise a
  binding that does not work.

The netcap integration test builds its PCAP **byte by byte in the test** rather
than checking in a fixture, so the test states exactly what traffic it expects
each indicator to come from.

---

## Linting the Windows code from Linux

```bash
rustup target add x86_64-pc-windows-msvc
cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc
```

**Use `clippy`, not `check`.** Lints that only fire on `cfg(windows)` code are
invisible to a Linux build, and waiting for the `windows-latest` CI job to find
them costs a full round trip.

No linker is required — this is a typecheck-and-lint pass.

---

## Supply-chain checks

```bash
cargo deny check     # advisories, bans, licenses, sources
cargo audit          # RustSec advisories (same database)
```

`deny.toml` is the CI gate. `.cargo/audit.toml` is kept in sync so a bare
`cargo audit` agrees with it.

### Before you add a dependency

Banned at the dependency level, and CI fails if one appears:

| Crate | Why |
|---|---|
| `reqwest`, `hyper` | Arachnid Core never makes outbound requests |
| `openssl-sys` | no TLS client belongs in a triage binary |
| `libloading` | no dynamic code loading in the shipped binary |
| `dlopen` | same |

`libloading` is whitelisted only as a **build-time** dependency of `clang-sys`
and `pcap`, both of which run on the build host. If either becomes a normal
dependency, the check fails — which is the point.

Also enforced: `wildcards = "deny"` (no unpinned versions), no git dependencies,
crates.io only.

If a change would need a banned crate, the design is out of scope. Flag it
rather than working around the check.

---

## CI

Seven jobs, on every push to `main` and every PR:

| Job | Runs |
|---|---|
| **test** (ubuntu + windows) | `cargo clippy --workspace --all-targets -- -D warnings`, then `cargo test --workspace`, then the safety-rail suite on its own |
| **cross typecheck** | clippy for `x86_64-pc-windows-msvc` from Linux |
| **fmt** | `cargo fmt --all --check` |
| **supply-chain** | `cargo-deny` + `rustsec/audit-check` |
| **schema** | produces a **real container** and validates it against the published schemas |
| **installer scripts** | `dash -n` and `shellcheck` on `install.sh`, and a PowerShell parse of `install.ps1` |
| **publish wiki** | pushes `docs/wiki/` to the GitHub wiki. Push to `main` only |

A separate **Release** workflow (`.github/workflows/release.yml`) runs on a
`v*` tag: it builds `arachnid-cli` for six targets, writes one `SHA256SUMS` for
the set, signs it once with minisign, and attaches everything to the release.
See `release/README.md` for the key setup it needs, and note that it has not
run yet — no release has been tagged.

Three details worth knowing:

**No `RUSTFLAGS` in the workflow env.** The environment variable *replaces*
`target.*.rustflags` from `.cargo/config.toml` rather than adding to it, which
silently dropped `/DELAYLOAD:wpcap.dll` and `+crt-static` on Windows. Warnings
are denied through clippy's own `-- -D warnings`, which is appended instead.
**Do not reintroduce a `RUSTFLAGS` env var in CI.**

**Windows CI installs the Npcap SDK but not the Npcap runtime.** The SDK
provides the import library, which is all the link step needs. Leaving the
runtime out makes CI a standing check that the **no-Npcap path works** — which
is how most analyst workstations are configured.

**The installers are linted as source, because they are.** `install.sh` claims
in its header to be POSIX sh rather than bash, and dash is what makes that claim
true or false — on Debian and Ubuntu dash *is* `/bin/sh`, so a bashism there is
a broken install for most Linux users. The job runs `dash -n`, `bash -n` and
`shellcheck --shell=sh`, and parses `install.ps1` with the PowerShell parser.

**Documentation publishes two different ways, and only one is automatic by
itself.** The Pages site at `arachnidgs.github.io/forensic` is built by GitHub
from `main` + `/docs`, so it updates on merge with no job involved. The **wiki
is a separate git repository** (`<repo>.wiki.git`) that nothing merges into —
`scripts/publish-wiki.sh` pushes to it, and the `publish wiki` job is what runs
that script. Before the job existed the script was manual, and the published
wiki sat five commits behind `main`. Both sources live in `docs/`; editing a
page and merging is all either needs.

**The safety rails get their own CI step.** `cargo test -p arachnid-sanitize-core
--test safety_rails` runs separately from the workspace suite, against
file-backed virtual devices so it needs no attached disk and no elevation. It is
called out on its own so a failure reads as *"a safety rail broke"* rather than
as one line in a hundred — this is the suite that stands between an operator and
the wrong drive.

The schema job is the one that catches contract drift:

```bash
cargo run --release -p arachnid-core-cli -- \
  --log-level warn collect -o ./ci-container --no-hash-binaries
python3 scripts/validate-schemas.py ./ci-container
```

A real container, not a fixture, because drift between what the tool emits and
what the schema promises is a breaking change that must not merge silently.

---

## Adding a collector

1. **Define the record type** in `crates/arachnid-collect/src/lib.rs`, with
   `Serialize` and `Deserialize`. Make fields that can be absent `Option`, and
   say *why* absence is possible in a doc comment.
2. **Implement it per platform** in `linux.rs` and `windows.rs`, and add a
   `bail!` stub to `unsupported.rs` — never an empty `Ok(vec![])`. An analyst
   must never be shown "none found" when the truth is "nobody looked".
3. **Add a field to `Collection`** and a name to the `COLLECTORS` array.
4. **Call it in `collect_all_with_progress`**, with a `starting("name")` call
   before it, in the same position as its entry in `COLLECTORS` — the test
   asserts the two match exactly.
5. **Add an artifact** in `cmd_collect` (CLI) and in `screens::collect` (TUI).
   One artifact per collector.
6. **Extend the schema** — `schema/report.schema.json`, under `$defs`, added to
   `collection`'s `required` list. CI validates a real container against it.
7. **Document the paths** in [`docs/SOC-ALLOWLISTING.md`](../SOC-ALLOWLISTING.md)
   §4. Every path the collector reads. This is not optional: a behaviour not on
   that page is a bug by definition.
8. **Add it here**, in [Collectors](06-Collectors.md).

Non-negotiables: read-only, degrade rather than abort, and record the reason for
every gap.

---

## Adding a TUI screen

The screen state machine is designed so a new module (Sanitize, Recover) touches
no existing screen:

1. **A variant** in `AppScreen` (`app.rs`).
2. **An entry** in `TABS` if it is a numbered tab — note that the `1`–`7` jump
   binding indexes `TABS` by subtracting `'1'`, and a test asserts the jump
   chords and `TABS` are the same length, so both change together.
3. **A title** in `AppScreen::title`.
4. **A module** in `screens/`, exposing `State`, `render`, `on_key`, and a
   `KEYS` table.
5. **Three match arms** in `screens/mod.rs`: `render`, `on_key`, `keys`.
6. **A field** on `App`.
7. **A variant** in `Msg` if it does background work, plus an arm in
   `App::handle`.

Then:

- **Anything that starts, replaces or stops evidence collection must go through
  `App::ask`** and a `Action` variant. Nothing that touches evidence happens on a
  single keypress.
- **Long work goes on a thread** and reports back through `Msg`. Claim the job
  slot with `App::begin` — one job at a time.
- **The layout must survive 32×8.** The render test will tell you if it does not.
- **Every binding in `KEYS` must actually be handled** in `on_key`.

---

## Changing the schema

Two versions, independent:

| Constant | Governs |
|---|---|
| `arachnid_evidence::SCHEMA_VERSION` | the container layout and custody record shape |
| `arachnid_report::REPORT_SCHEMA_VERSION` | the report document |

Rules:

- **Additive changes** (a new optional field, a new enum member) are a **minor**
  bump.
- **Anything that breaks an existing consumer** — a removed or renamed field, a
  changed type, a reordered custody record — is a **major** bump.
- **Reordering `Record`'s fields is a breaking change even if the JSON looks the
  same.** Field order is the serialization order and is part of the signed
  bytes.
- Update the matching `schema/*.json` in the same commit. CI validates a real
  container, so a mismatch fails the build.
- Update the `additionalProperties: false` object's `properties` and `required`
  lists too.

Consumers must reject a major version they do not implement, and Arachnid does
this itself in `cmd_report`.

---

## House rules

Distilled from the code's own comments. They are the reason the tool behaves the
way it does.

**Never write to the target.** Not a temp file, not a config file, not a
registry value. The only writes go to the container and the `--log` path.

**Degrade, never abort.** One unreadable file must not cost a collector; one
failed collector must not cost the run. Record every gap in `warnings`.

**An empty result is never allowed to look like a clean host.** Return an error
that becomes a warning, not an empty list.

**Verification is independent of collection.** It re-reads and re-hashes. Do not
refactor the two together — the duplication is deliberate.

**Never re-serialize a signed record.** Signing is over exact bytes. Verification
reads them as bytes.

**Do not put work in the capture loop.** Per-packet work on behalf of a UI is how
a capture falls behind the link and drops evidence. Counters only.

**Escape on output, store verbatim.** Collected content is attacker-controlled.

**Prefer stdlib over a dependency.** `hostname()` reads an env var and a
`/proc` file rather than linking libc. `utmp` is parsed by offset rather than
pulling in `getutent`. `xml_tag` extracts one element rather than adding an XML
parser. Each of these is a comment in the source explaining the trade.

**In Sanitize, safety is structural, never advisory.** If you add a code path
that can reach the write loop, it must go through `safety::authorize` — and it
will, because `engine::wipe` takes a `Clearance` and nothing else can build one.
Do not add a constructor, do not derive `Clone`, and do not move a rail out of
`authorize` into a caller. Likewise, never let a certificate be issued outside
`cert::issue`.

**Never claim a compliance property the code did not perform.** A `nist-purge`
that fell back to software says so on the certificate, in words. A test asserts
no path can claim a completed hardware purge. This is the failure mode that
would matter most and be noticed least.

**Comment the *why*, not the *what*.** Most non-obvious lines in this codebase
carry a comment explaining the failure mode they prevent. Match that when you
add code — a future maintainer removing your line needs to know what it costs.

---

[← Security & Threat Model](10-Security-and-Threat-Model.md) · [Home](Home.md) · [Next: Troubleshooting →](12-Troubleshooting.md)
