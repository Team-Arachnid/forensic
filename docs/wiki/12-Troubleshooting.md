---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 12 · Troubleshooting

[← Development](11-Development.md) · [Home](Home.md) · [Next: FAQ →](13-FAQ.md)

Error messages you are likely to see, what they mean, and what to do. Grouped by
where they come from.

**First step for anything unclear:**

```bash
arachnid-core --log-level debug --log ./debug.log <your command>
```

The operational log records every action the tool took.

---

## Contents

- [Container errors](#container-errors)
- [Verification failures](#verification-failures)
- [Capture errors](#capture-errors)
- [PCAP parsing errors](#pcap-parsing-errors)
- [Memory acquisition errors](#memory-acquisition-errors)
- [Report errors](#report-errors)
- [Signing key errors](#signing-key-errors)
- [Build errors](#build-errors)
- [Sanitize refusals and failures](#sanitize-refusals-and-failures)
- [TUI problems](#tui-problems)
- [Unexpected results](#unexpected-results)

---

## Container errors

### `already contains a custody log; refusing to append to an existing container`

```
error: ./ev-host01 already contains a custody log; refusing to append to an
       existing container
```

**Why:** containers are never appended to. One run, one container — two runs
with interleaved custody timestamps would be a chain of custody nobody could
read.

**Fix:** use a new directory. Name them per run:

```bash
arachnid-core collect -o ./ev-host01-$(date -u +%Y%m%dT%H%M%SZ)
```

Do **not** delete the existing container to reuse the name unless you are
certain it holds nothing you need.

---

### `create container at …: Permission denied`

**Why:** you cannot write to the parent directory.

**Fix:** pick a writable path, or create the parent first. Prefer a dedicated
collection volume or share — and get it excluded from real-time scanning, since
a memory image of an infected host will trigger signature hits.

---

### The container directory was not created at all

You used `--dry-run`. That is the intended behaviour: every collector runs and
every hash is computed, but nothing reaches disk, including the container
directory. Drop `--dry-run` for a real run.

---

## Verification failures

All of these produce **exit code 3**.

### `artifact X: content modified since collection`

The file's SHA-256 no longer matches what the custody log recorded.

**Benign causes:** someone opened it in an editor that rewrote it; a sync tool
normalised line endings; a virus scanner "cleaned" it.

**Non-benign cause:** the container was tampered with.

**There is no fix.** A modified artifact is not evidence any more. Go back to the
original container. This is the property working, not a bug.

---

### `artifact X: size differs from record`

Usually appears alongside the previous message. A truncated or padded file.

---

### `artifact X: missing`

The file was deleted or moved. Check whether the whole `artifacts/` directory
travelled — a copy that missed a file is the common innocent cause.

```bash
diff <(cut -d' ' -f2- container/custody.log \
        | jq -r 'select(.event=="artifact") | .name' | sort) \
     <(cd container/artifacts && find . -type f | sed 's|^\./||' | sort)
```

---

### `artifact X: present on disk but not in custody log`

A file was added to `artifacts/` after collection.

**Benign cause:** someone dropped notes or a scratch file in there. **Do not do
that** — put working notes anywhere else. The `artifacts/` directory is
evidence-only.

**Non-benign cause:** something was planted.

---

### `line N: hash chain broken (record removed, reordered, or edited)`

A custody record was removed, reordered or edited. Also fires on a **truncated**
log — check whether the last record is `run_end`:

```bash
tail -1 container/custody.log | cut -d' ' -f2- | jq -r .event
```

If it is not `run_end`, the run was interrupted or the log was cut. An
interrupted run leaves a chain that is internally consistent up to the cut — the
evidence collected before it is still hashed and signed.

---

### `line N: signature does not verify`

That line's bytes changed after signing. Even a whitespace edit does it.

**Do not try to repair it.** Re-signing is impossible without the operator's key,
and a repaired log would be worthless anyway.

---

### `manifest public_key is not 32 hex-encoded bytes` / `not a valid Ed25519 key`

The manifest parsed but its key is unusable. Reported as an **integrity problem**
(exit 3), not a runtime error — and verification continues without signature
checks, so you still learn which artifacts are intact.

---

### `read manifest.json: No such file or directory`

**Exit code 1**, not 3 — the container is unreadable, not tampered.

**Fix:** point at the container **directory**, not at a file inside it:

```bash
arachnid-core verify ./ev-host01              # correct
arachnid-core verify ./ev-host01/manifest.json   # wrong
```

---

### `verify` says VERIFIED but I do not trust it

Correct instinct. Check the fingerprint:

```
key fingerprint:  6e5cbdee…d827c7
```

If that does not match a fingerprint you recorded out-of-band for the responder
who claims to have produced this container, VERIFIED means only "internally
consistent". Anyone who can rewrite the whole container can also swap the key and
re-sign. See
[Concepts § Signing keys](02-Concepts.md#signing-keys-and-what-verification-proves).

---

## Capture errors

### `No capture devices visible.`

```
No capture devices visible. Capture needs root/CAP_NET_RAW on Linux, Npcap on Windows.
```

**Linux:**

```bash
sudo arachnid-core capture --list-devices
# or grant the capability once:
sudo setcap cap_net_raw,cap_net_admin=eip $(which arachnid-core)
```

**Windows:** install [Npcap](https://npcap.com/), and run from an elevated
prompt.

---

### `open "eth0" for capture (needs root/CAP_NET_RAW on Linux, Npcap on Windows)`

The device exists but you cannot open it. Same fixes as above.

---

### `capture device "eth0" not found`

The name did not match. Device names are exact — check them:

```bash
arachnid-core capture --list-devices
```

On Windows they look like `\Device\NPF_{GUID}`; use `--json` and copy the
`name` field exactly. On Linux, `any` captures on all interfaces.

---

### `apply BPF filter "…": syntax error`

Bad filter. Test it with `tcpdump` first — the syntax is identical:

```bash
sudo tcpdump -i eth0 -d "tcp port 443 and not host 10.0.0.1"
```

Common mistakes: `and`/`or` instead of `&&`/`||` is fine (both work), but
`portt`, a missing quote, or a hostname that does not resolve will all fail.

---

### `--device is required (see --list-devices)`

Exit code 1. Pass `-d <name>`.

---

### The capture is dropping packets

```
⚠ Dropped 1204 (kernel) / 0 (interface) — this capture has gaps.
```

Exit code 4. In order of effectiveness:

1. **Tighten the BPF filter.** Kernel-side filtering is free.
2. **Lower `--snaplen`** — 1500, or 256 for headers only. This truncates
   payloads, so reassembly and HTTP/TLS parsing suffer.
3. **Write to faster storage.** A USB stick is a common culprit.
4. **Capture in shorter windows.**

Never present a lossy capture as a complete record.

---

### `Npcap is not installed, or wpcap.dll is not on the DLL search path.`

Install [Npcap](https://npcap.com/). Note that `collect`, `verify` and `report`
work **without** it — only `capture` and `parse-pcap` need it.

If Npcap *is* installed and you still see this: it installs to
`%SystemRoot%\System32\Npcap`, which is not on the default DLL search path.
Arachnid prepends it automatically, so check that the directory actually exists
and holds `wpcap.dll`.

---

### Ctrl-C did not stop the capture immediately

It can take up to about 250 ms — the read timeout. The delay is deliberate: it
is what lets the loop notice the stop flag on an idle link instead of blocking
in the driver until the next packet arrives.

If you kill the process harder than that, **you lose the savefile's custody
record**. Let it finish.

---

## PCAP parsing errors

### `X is not a readable file`

Check the path and permissions. `parse-pcap` takes the file as a positional
argument, before or after the flags:

```bash
arachnid-core parse-pcap capture.pcap -o ./ev-pcap    # correct
```

---

### `open savefile …: … ` / the file fails to parse

Not a PCAP/PCAPNG, or truncated. Check the magic:

```bash
xxd -l 8 suspicious.pcap
```

`d4c3b2a1` or `a1b2c3d4` is PCAP; `0a0d0d0a` is PCAPNG. Anything else is not a
savefile.

---

### `decode_errors` is high

```bash
jq '{errors: .decode_errors, packets: .packets, datalink: .datalink}' \
   ev/artifacts/pcap_analysis.json
```

| `datalink` | Meaning |
|---|---|
| `Linktype(1)` | Ethernet — supported |
| `Linktype(113)` | Linux cooked v1 (`any` device) — supported |
| `Linktype(276)` | Linux cooked v2 — supported |
| `Linktype(0)` | BSD loopback — supported |
| `Linktype(12/14/101)` | Raw IP — supported |
| anything else | **not decoded** — every frame counts as an error |

If the link type is supported, the likely cause is frames truncated by a low
snaplen at capture time. Recapture with `--snaplen 65535`.

---

### Flows are marked `truncated`

They hit the reassembly ceiling (8 MiB per flow by default). Raise it if you need
more of the payload:

```bash
arachnid-core parse-pcap big.pcap -o ./ev --max-stream-bytes 33554432
```

Indicators live in the first few KiB, so this rarely changes what you find.

---

### No `tls_sni` for a connection I can see

Expected if:

- the ClientHello was **encrypted** (ECH) — nothing is decrypted, ever;
- the handshake omitted SNI;
- the ClientHello was truncated by a low `--snaplen` at capture time;
- the flow is not TCP, or the handshake was not at the start of the stream.

---

## Memory acquisition errors

### `acquisition tool hash mismatch`

```
error: acquisition tool hash mismatch for /opt/avml: expected 3f6a…c21b,
       found 91d0…4e77. Refusing to execute an unverified tool.
```

**This is the check working.** Either you typed the wrong hash, or the binary on
this host is not the one you expected — which on a host under investigation is a
finding, not an inconvenience.

Verify the hash from a source you trust, **not** by re-hashing the file on the
suspect host:

```bash
# on your own kit, not the target
sha256sum /path/to/known-good/avml
```

---

### `error: the following required arguments were not provided: --memory-tool-sha256`

Exit code 2. `--memory-tool` requires `--memory-tool-sha256`. There is no way to
run an unverified acquisition tool, by design.

---

### `/opt/avml exited with Some(1): …`

The acquisition tool itself failed; the last 20 lines of its stderr are in the
error. Usually privilege, or a kernel that will not allow the read. Run the tool
directly to see its full output.

---

### Memory acquisition was skipped

You used `--dry-run`. The tool is deliberately not executed in a dry run.

---

## Report errors

### `read X/artifacts/report.json (is this an Arachnid container?)`

Point at the container **directory**:

```bash
arachnid-core report ./ev-host01                      # correct
arachnid-core report ./ev-host01/artifacts/report.json   # wrong
```

---

### `report schema 2.0.0 is not supported by this build (expected 1.x)`

The container was written by a newer Arachnid. Use a build that implements that
major version. `report.json` is still readable directly — the schema is
published.

---

### The report table says `483 more in the JSON report`

Human tables cut at 20 rows (40 for indicators). **The JSON always holds
everything.** Go to `report.json`, or to the per-collector artifact:

```bash
jq '.[] | select(.state=="LISTEN")' ev/artifacts/connections.json
```

---

## Signing key errors

### `signing key must decode to 32 bytes` / `is neither 32 raw bytes nor hex`

The key file must be a 32-byte Ed25519 seed — **raw bytes or hex text**. Both
work; nothing else does.

```bash
head -c 32 /dev/urandom > key.bin           # raw
xxd -p -c 64 key.bin > key.hex              # hex — same fingerprint
```

A PEM or OpenSSH key is not accepted.

---

### `read signing key …: Permission denied`

```bash
chmod 600 ~/.arachnid/analyst-7.key
```

---

### The fingerprint changed between runs

Either you forgot `--signing-key` (a key is then generated per run), or you
pointed at a different file. Check:

```bash
sha256sum ~/.arachnid/analyst-7.key
```

The fingerprint is deterministic: the same key always produces the same
fingerprint, whether the file is raw or hex.

---

## Build errors

### `could not find system library 'libpcap'`

```bash
sudo apt install libpcap-dev      # Debian / Ubuntu
sudo dnf install libpcap-devel    # Fedora / RHEL
sudo pacman -S libpcap            # Arch
```

---

### `LINK : fatal error LNK1181: cannot open input file 'wpcap.lib'`

The Npcap **SDK** is missing (the runtime is a separate thing). Download it, then:

```powershell
$env:LIB = "C:\npcap-sdk-1.13\Lib\x64;$env:LIB"
```

---

### `package requires rustc 1.88 or newer`

That is `arachnid-core-tui`, the one crate above the workspace floor (ratatui
0.30 needs 1.88). Either update your toolchain, or build only the CLI:

```bash
cargo build --release -p arachnid-core-cli
```

---

### The release script failed at "verifying static linkage"

`ldd` found a dynamic dependency. Almost always libpcap: the script builds it
from source against musl for exactly this reason. Check that step succeeded, and
that `musl-gcc` is installed.

---

### The release script failed at "verifying the binary is inspectable"

`strings` could not find a subcommand name. **This is a deliberate gate.** Some
step in your build pipeline is packing, compressing or obfuscating the binary —
which would make it indistinguishable from malware to the defenders you are
asking to allowlist it. Remove that step.

---

## Sanitize refusals and failures

`arachnid-sanitize` destroys data, so most of what you will see is it **refusing
to**. A refusal is the tool working. Full chapter:
[Secure Erasure](14-Secure-Erasure.md).

### `REFUSED: serial confirmation failed`

```
REFUSED: serial confirmation failed: you typed "S4EVNF0M12346", the selected
device reports "S4EVNF0M12345". Nothing was written.
```

Exit **3**. Copy the serial from `list-devices` exactly — matching is
**case-sensitive**, because folding case would let `abc123` confirm a wipe of the
drive labelled `ABC123`, and hosts exist with both. Surrounding whitespace is
forgiven; nothing else is.

### `REFUSED: … hosts the running operating system`

The device backs a mounted system volume. Confirm you have the right path with
`list-devices` — the offending device is flagged `SYSTEM`.

If it genuinely is the drive you mean to destroy, `--force-system-volume` (CLI)
or `f` (TUI) overrides it, and **the override is recorded on the certificate**.

Note that `is_system` fails *closed*: if the OS cross-reference cannot be
resolved, every disk is reported as system-hosting.

### `REFUSED: … reports no serial number`

No serial, no wipe — the typed-serial rail has nothing to protect the wipe with.
Common on USB bridges, which frequently do not pass the drive's serial through.

Attach the drive over a direct SATA/NVMe connection, or wipe it from a host that
can read its serial.

### `REFUSED: … is no longer the device that was selected`

A drive was unplugged mid-session and another took its path. Re-enumerate (`r`
in the TUI) and select again. This is the rail that stops you wiping the drive
that replaced the one you chose.

### `REFUSED: … does not report a crypto-erase capability`

Expected on **every** device: `--method crypto-erase` is refused unconditionally
in this build, because confirming a working self-encrypting drive needs
pass-through I/O this build does not implement. Choose an overwrite method.

### My `nist-purge` certificate says "software overwrite"

That is correct and deliberate. This build issues **no hardware sanitize
command**; `nist-purge` falls back to a 3-pass software overwrite and the
certificate says so, in words, so the claim cannot be read as Purge-grade. See
[the caveats](14-Secure-Erasure.md#two-honest-caveats-read-these-first).

### Exit code 4 — verification failed

The wipe ran and the read-back found surviving data. **No certificate is
issued**, and the drive must not be released. Usually a failing drive, or media
that silently remapped writes. Re-run, and if it fails again, destroy the drive
physically.

### Exit code 5 — unwritable regions

The wipe completed but some regions could not be written. No certificate. The
drive is failing; the bad regions are listed. Destroy it physically rather than
releasing it.

### `refused N consecutive writes … the device is failing`

100 consecutive chunk failures (~400 MiB) aborts the job. At that point the drive
is not being wiped, it is being waited on.

### `no certificate: the wipe did not complete`

A dry run, a cancelled wipe, or unwritable regions. All three mean the device may
still hold recoverable data, so `cert::issue` refuses to sign — by design, and
not overridable.

### The TUI will not accept my commit key

Two possibilities. The commit key is **`Shift-W`**, not `Enter` and not `y` —
deliberately, so a wipe cannot be cleared by the reflex that clears an ordinary
confirmation. And the key is **rejected, not ignored**, until the 3-second
cooldown elapses.

---

## TUI problems

### `terminal too small / needs 32x8`

Resize. Below 32×8 the TUI refuses to draw rather than drawing something corrupt.

---

### Typing a path with `q` in it quits

You are not in edit mode. Press `Enter` on the field first — fields have an
explicit edit mode precisely so this works. `Esc` or `Enter` leaves it.

---

### The terminal is broken after a crash

It should not be — a panic hook restores raw mode and leaves the alternate
screen before the panic prints. If it happens anyway:

```bash
reset
```

and please report it with the panic message.

---

### `collect is still running`

One job at a time. Two concurrent runs would mean two containers with
interleaved custody timestamps. Wait for it.

---

### The TUI forgot my recent paths

The state file was deleted or is unwritable:

| Platform | Path |
|---|---|
| Linux | `$XDG_STATE_HOME/arachnid/tui-state.json`, or `~/.local/state/arachnid/…` |
| Windows | `%APPDATA%\arachnid\tui-state.json` |

It is a convenience file, never evidence. Losing it costs two retyped paths, and
a write failure is deliberately silent (a debug log line) rather than a failed
run.

---

### No colour in the TUI

`NO_COLOR` is set. That is respected on purpose. Every verdict is also stated in
text, so nothing is lost.

---

## Unexpected results

### Exit code 4 and I do not know why

```bash
jq -r '.collection.warnings[]?' ev/artifacts/report.json
jq '.capture | select(.) | {kernel: .packets_dropped_kernel, interface: .packets_dropped_interface}' ev/artifacts/report.json
jq '.pcap.decode_errors // 0' ev/artifacts/report.json
```

One of the three will be non-empty or non-zero. Code 4 means **you have
evidence and it is incomplete** — never treat it as either plain success or
plain failure.

---

### Far fewer processes than `ps` shows

You are unprivileged. Check:

```bash
jq -r '.collection.warnings[]?' ev/artifacts/report.json
```

Arachnid **never escalates** — it uses the token it was given. Re-run elevated.

---

### `exe_sha256` is null everywhere

Either `--no-hash-binaries` was used, or you were unprivileged and could not read
the images. The two look identical in the output, which is why the choice is
worth noting in your log.

Individual nulls are different: an image that exists but cannot be hashed when
you *are* privileged is a finding — a deleted or replaced binary. The report
lists these under **Processes with an unhashable image**.

---

### Connections have no `process_name` or `pids`

Socket-to-process mapping needs privilege on both platforms. The connection is
real; the attribution is missing.

---

### `sessions` is empty on Linux

Either nobody is logged in interactively, or `/var/run/utmp` is absent (common in
containers) — which shows up as a warning and exit code 4, or

**a cleared utmp**, which is one of the oldest anti-forensic moves there is.
Arachnid records what is present; it does not recover what was removed.

---

### A kernel module has `path: null`

The `.ko` was not found under `/lib/modules/<release>`. That is **a finding, not
a bug** — a module loaded from an unusual path, or whose backing file has been
removed.

---

### The report shows nothing suspicious but I know the host is compromised

Live enumeration goes through OS APIs, and a kernel-level implant can lie to
them. **Acquire memory and analyse it offline**; correlate the two. See
[Threat Model § A compromised kernel lies](10-Security-and-Threat-Model.md#a-compromised-kernel-lies).

---

## Still stuck

Collect the evidence a maintainer needs:

```bash
arachnid-core --version
arachnid-core --log-level debug --log ./debug.log <the failing command>
```

Then open an issue with `debug.log`, the custody log from the affected container,
and your platform. Between them they record every action the tool took.

If the tool did something not described in this wiki or in
[`docs/SOC-ALLOWLISTING.md`](../SOC-ALLOWLISTING.md), say so explicitly — that is
a defect worth prioritising.

---

[← Development](11-Development.md) · [Home](Home.md) · [Next: FAQ →](13-FAQ.md)
