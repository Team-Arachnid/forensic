---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 14 · Secure Erasure (Arachnid Sanitize)

[← FAQ](13-FAQ.md) · [Home](Home.md) · [File Recovery →](15-File-Recovery.md)

> **This module destroys data.** Every other tool in the suite is read-only
> against its target. `arachnid-sanitize` exists to make a device unreadable,
> and a wipe cannot be undone. Use `--dry-run` first, every time.

`arachnid-sanitize` performs standards-compliant destruction of data on storage
media, verifies the result by read-back sampling, and issues an Ed25519-signed
certificate. It is also reachable as screen `7` in `arachnid-tui`.

---

## Contents

- [The inversion](#the-inversion)
- [Two honest caveats](#two-honest-caveats-read-these-first)
- [Methods and compliance](#methods-and-compliance)
- [The safety rails](#the-safety-rails)
- [CLI reference](#cli-reference)
- [`list-devices`](#list-devices)
- [`wipe`](#wipe)
- [`verify-wipe`](#verify-wipe)
- [`cert`](#cert)
- [Verification](#verification)
- [Certificates and the register](#certificates-and-the-register)
- [The TUI Sanitize screen](#the-tui-sanitize-screen)
- [Exit codes](#exit-codes)
- [Asset-disposal workflow](#asset-disposal-workflow)
- [Not in scope](#not-in-scope)

---

## The inversion

`arachnid-collect`'s hard rule is that it never writes to the target. This crate
inverts that rule completely, which is why its safety is **structural rather
than advisory**:

- **`engine::wipe` takes a `Clearance`**, and the only way to build one is
  `safety::authorize`, which runs every rail. There is no path to the write loop
  that skips them — not a new subcommand, not another TUI screen, not a batch
  runner.
- **`Clearance` is not `Clone` or `Copy`.** It is consumed by the wipe it was
  issued for. Carrying one to a second device is exactly the mistake the
  no-bulk-select rail exists to prevent.
- **`cert::issue` refuses to sign** a certificate for a wipe that did not
  complete or did not verify. That rule lives in `issue`, not in the callers, so
  a caller cannot forget it.
- **A device whose system-volume status cannot be determined is reported as
  system-hosting.** For a destructive tool, "unsure" and "yes" mean the same
  thing.

---

## Two honest caveats, read these first

### 1 · This build issues no hardware sanitize command

`--method nist-purge` probes the device, reports which command *would* apply,
then runs a **3-pass software overwrite instead** — and the certificate says so,
in terms an auditor cannot misread:

> SOFTWARE OVERWRITE, not a hardware purge — … Assess against NIST 800-88
> Clear, not Purge.

ATA `SECURITY ERASE UNIT`, ATA `SANITIZE` and NVMe `FORMAT NVM` (SES=1) all need
vendor-quirk-laden pass-through I/O — `IOCTL_ATA_PASS_THROUGH_DIRECT` and
`IOCTL_STORAGE_PROTOCOL_COMMAND` on Windows, `SG_IO` / `NVME_IOCTL_ADMIN_CMD` on
Linux — where a malformed command can leave a drive frozen or password-locked
and needing a vendor tool to recover. Shipping a half-tested version of that is
worse than not shipping it.

A test asserts **no code path can claim a completed hardware purge**, so this
cannot quietly regress into an unearned compliance claim.

### 2 · Crypto-erase is refused on every device

```
REFUSED: /dev/nvme0n1 does not report a crypto-erase capability. Choose an
overwrite method, or verify the drive is a self-encrypting model.
```

`purge::supports_crypto_erase` returns `false` unconditionally in this build.
Confirming a drive is a working self-encrypting drive means reading its TCG Opal
feature set over that same pass-through path.

> Claiming a crypto-erase we cannot verify is the most dangerous false statement
> this tool could make: the operator believes the data is gone when it is not.

### 3 · And a caveat about the media itself

On modern SSDs, **wear levelling means an overwrite cannot guarantee** every
physical cell holding old data is reached. That is a property of the media, not
of this tool. For flash, a hardware purge or crypto-erase is the only complete
answer — and neither is available in this build. Plan accordingly: for SSDs
leaving the organization, physical destruction or the vendor's own secure-erase
utility remains the defensible path.

---

## Methods and compliance

| Method | Flag | Passes | Satisfies | Use when |
|---|---|---|---|---|
| NIST SP 800-88 *Clear* | `--method nist-clear` | 1 (`0x00`) | NIST 800-88 Clear | media stays inside the organization |
| NIST SP 800-88 *Purge* | `--method nist-purge` | hardware, else 3 | **Clear**, see caveat | media leaves the organization |
| DoD 5220.22-M | `--method dod3` | 3 (`0x00`, `0xFF`, random) | DoD 5220.22-M (short) | a policy names DoD 3-pass |
| DoD 5220.22-M ECE | `--method dod7` | 7 | DoD 5220.22-M (full) | a policy names DoD 7-pass |
| Crypto-erase | `--method crypto-erase` | 0 | — | **refused in this build** |

There is **no default method**. The choice changes what standard the resulting
certificate can claim, so it must be made explicitly.

### The exact pass sequences

| Method | Sequence |
|---|---|
| `nist-clear` | `0x00` |
| `nist-purge` (software fallback) | `0x00`, `0xFF`, random |
| `dod3` | `0x00`, `0xFF`, random |
| `dod7` | random, `0x00`, `0xFF`, random, `0x00`, `0xFF`, random |

DoD 5220.22-M **never fixed byte values itself** — it specified "a character, its
complement, and a random pattern," and left the values to the implementer. The
byte values here follow the convention Eraser and DBAN ship under that name,
which is what an auditor reading a certificate will recognise. The sequences are
asserted byte-for-byte in
`crates/arachnid-sanitize-core/tests/safety_rails.rs`.

---

## The safety rails

Every rail exists for a failure that has actually destroyed data in the field.

| Rail | Behaviour |
|---|---|
| **System-volume block** | a device hosting the running OS is refused. Override needs `--force-system-volume` (CLI) or `f` plus the distinct confirm screen (TUI), and the override is **recorded on the certificate** |
| **Typed serial** | `--confirm-serial` must match exactly, **case-sensitively**. Folding case would let `abc123` confirm a wipe of the drive labelled `ABC123`, and hosts exist with both. Surrounding whitespace is forgiven |
| **No serial, no wipe** | a device reporting no serial is refused outright — the typed-serial rail has nothing to protect the wipe with. Common on USB bridges |
| **Re-enumeration** | devices are re-read immediately before authorizing and matched on model + serial + size. Catches a drive unplugged mid-session whose path was reused by another |
| **Dry run** | `--dry-run` walks selection, method choice and reporting, and writes **zero bytes**. Asserted by test, not by inspection |
| **No bulk select** | there is no verb that takes more than one device, and `Clearance` is not `Clone` |
| **Cooldown** | a **3-second** countdown precedes the first write. In the TUI the commit key is *rejected*, not merely ignored, until it elapses |

### Rail order

`authorize` checks in this order, and returns at the first failure:

1. zero-size device → `EmptyDevice`
2. re-enumeration mismatch → `DeviceChanged`
3. missing serial → `NoSerial`
4. serial mismatch → `SerialMismatch`
5. system volume without the override → `SystemVolume`
6. crypto-erase on a device that cannot do it → `CryptoEraseUnsupported`

Note that **the serial is checked before the system-volume block**, and
`--force-system-volume` does *not* bypass the serial check — there is a test
asserting exactly that.

### How `is_system` is computed

Never guessed from a device path or drive number. The OS is asked which physical
disks back the volumes the running system is mounted from:

- **Windows** — `IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS` per drive letter
- **Linux** — `/proc/mounts`, resolved through partitions and device-mapper
  slaves

**If that cross-reference fails, every disk is reported as system-hosting.**

### Seeing a rail work

A deliberately wrong serial, with `--dry-run` as a second guarantee:

```bash
arachnid-sanitize wipe /dev/nvme0n1 \
    --method nist-clear \
    --confirm-serial DEFINITELY-NOT-THE-SERIAL \
    --dry-run
```

```
REFUSED: serial confirmation failed: you typed "DEFINITELY-NOT-THE-SERIAL",
the selected device reports "S6B7NX0X602424". Nothing was written.
```

Exit code **3** — refused by a rail, nothing written.

The other refusal messages, verbatim:

```
/dev/sda hosts the running operating system (backs a filesystem the running OS
has mounted). Wiping it will destroy the system you are working from. Pass
--force-system-volume if that is genuinely what you intend.

/dev/sdc reports no serial number, so the typed-serial confirmation cannot
identify it. This is common on USB bridges. Attach the drive over a direct
SATA/NVMe connection, or wipe it from a host that can read its serial.

/dev/sdb is no longer the device that was selected (selected …, found …). A
drive was probably unplugged and another attached. Re-enumerate and select
again.
```

---

## CLI reference

```
arachnid-sanitize [OPTIONS] <COMMAND>

Commands:
  list-devices  List attached storage devices, flagging any that host the running OS
  wipe          Irreversibly erase one device
  verify-wipe   Re-read a device and check it against an expected wipe pattern
  cert          Print or verify erasure certificates
```

Global options are the same shape as `arachnid-core`'s: `--log <PATH>`,
`--log-level <LEVEL>` (overrides `ARACHNID_LOG`), `--json`, `-h`, `-V`.

Requires Administrator / root for raw device access. Enumeration degrades
gracefully without it.

---

## `list-devices`

Read-only. Always run this first.

```bash
arachnid-sanitize list-devices
```

```
PATH                   MODEL                      SERIAL                     SIZE  BUS      FLAGS
/dev/nvme0n1           SAMSUNG MZVL41T0HBLB-00BH1 S6B7NX0X602424        953.9 GiB  NVMe
/dev/sda               Elements SE SSD            23315C401334          931.5 GiB  USB      SYSTEM
                       └─ backs a filesystem the running OS has mounted

Devices flagged SYSTEM host the running operating system and are refused by
`wipe` unless --force-system-volume is passed.
```

The `SERIAL` column is what `--confirm-serial` must match, character for
character.

Machine-readable:

```bash
arachnid-sanitize --json list-devices | jq -r '.[] | select(.is_system|not) | .path'
```

Devices that cannot be interrogated are skipped with a log line rather than
failing the whole enumeration — an operator with one unreadable drive still
needs to see the others.

---

## `wipe`

```
arachnid-sanitize wipe [OPTIONS] --method <METHOD> <DEVICE>
```

| Flag | Meaning |
|---|---|
| `<DEVICE>` | device to erase, by OS path (`/dev/sdb`, `\\.\PhysicalDrive2`) |
| `--method <METHOD>` | **required, no default.** `nist-clear`, `nist-purge`, `dod3`, `dod7`, `crypto-erase` |
| `--confirm-serial <SERIAL>` | the device's serial, exactly as `list-devices` reports it |
| `--dry-run` | walk the whole flow, write nothing |
| `--force-system-volume` | permit erasing the device hosting the running OS |
| `--no-countdown` | skip the 3-second countdown, for unattended disposal runs where a human confirmed out of band |
| `--operator <NAME>` | identity recorded on the certificate |
| `--signing-key <PATH>` | Ed25519 key file (32-byte seed, raw or hex) |
| `--cert-dir <DIR>` | directory holding the append-only register (default `.`) |
| `--quick-verify` | verify a smaller sample; still covers head and tail |

### Always dry-run first

```bash
arachnid-sanitize wipe /dev/sdb \
    --method dod3 \
    --confirm-serial S4EVNF0M123456 \
    --dry-run
```

Every rail runs, the method is resolved, the estimate is produced, and **zero
bytes are written**. This is the rehearsal that catches a wrong serial or a
wrong path before it costs you a drive.

### The real thing

```bash
sudo arachnid-sanitize wipe /dev/sdb \
    --method dod3 \
    --confirm-serial S4EVNF0M123456 \
    --operator "tech-4" \
    --signing-key ~/.arachnid/tech-4.key \
    --cert-dir /srv/disposal/certs
```

A 3-second countdown precedes the first write. `Ctrl-C` cancels — and a
cancelled wipe leaves the device **partially overwritten and uncertified**,
which is recorded rather than hidden.

### The write loop

- **4 MiB chunks**, whole device, per pass.
- **Bad sectors do not abort the job.** An I/O error records the failed region
  and moves on; the certificate carries the list. A wipe that aborts on the
  first bad sector leaves a mostly-readable disk and no record of how far it
  got, which is the worst of both outcomes.
- **100 consecutive failures does abort it** — at that point the drive is not
  being wiped, it is being waited on.
- **Bad-region detail is capped at 1000 entries**; the *count* keeps rising, so
  a disk with millions of bad sectors cannot exhaust memory through its own
  error log.
- **Flush per pass, not per chunk**, so a crash cannot leave the passes
  reordered.

### ETA

Estimates are deliberately **pessimistic** — 80 MB/s over USB, 400 MB/s SATA,
1.2 GB/s NVMe. An operator told four hours who gets three is fine; the reverse
gets a drive unplugged mid-wipe. The live ETA stays `None` until at least 16 MiB
has been written, because an ETA computed off the first chunk is noise an
operator will plan around.

---

## `verify-wipe`

Re-read a device and check it against an expected fixed pattern. Use it on a
drive wiped by **another tool** or by an earlier run.

```bash
arachnid-sanitize verify-wipe /dev/sdb --expect-byte 00
arachnid-sanitize verify-wipe /dev/sdb --expect-byte ff --quick
```

This is a standalone check; it issues no certificate, because it has no
knowledge of who wiped the device or how.

---

## `cert`

```bash
arachnid-sanitize cert --cert-dir /srv/disposal/certs                       # list
arachnid-sanitize cert --cert-dir /srv/disposal/certs --verify              # check
arachnid-sanitize cert --id ccf8c85e… --format html -o cert.html            # render one
```

`--verify` checks every signature and the whole hash chain:

```
3 certificate(s) in /srv/disposal/certs/certificates.log
  ccf8c85e…  /dev/sdb  signature ok  chain ok
  a1f09b22…  /dev/sdc  signature ok  chain ok
  7e3d0c41…  /dev/sdd  signature ok  chain ok

VERIFIED: every certificate is intact and correctly chained.
```

---

## Verification

After a wipe, Sanitize reads back and compares **exactly**.

| Profile | Head | Tail | Samples | Per sample |
|---|---|---|---|---|
| default | 64 MiB | 64 MiB | 256 | 256 KiB |
| `--quick-verify` | 16 MiB | 16 MiB | 32 | 64 KiB |

Head and tail in full because that is where partition tables, superblocks and
journals live, and where a half-completed wipe shows first. On a 1 TB drive the
default profile reads ~192 MiB — a few seconds — and covers every structure that
would let a filesystem be reconstructed.

### Why random passes are still verifiable

A random pass is generated from a **recorded 32-byte seed**, so the expected
bytes at any offset can be recomputed. That makes a "random" pass verifiable by
**byte-for-byte match** rather than by entropy estimate.

> An entropy check cannot tell a wiped disk from an encrypted one that was never
> touched. This can.

The seeds are printed on the certificate, so an independent party can recompute
and re-check the pattern themselves.

### What blocks a certificate

Any of these, and `cert::issue` returns `Refused` rather than a signature:

- the wipe was a **dry run** — nothing was written
- the wipe was **cancelled** before completing
- **any region could not be written**
- **verification failed**

```
no certificate: the wipe did not complete (cancelled before completion)
no certificate: verification failed (…)
```

---

## Certificates and the register

Issued on success as JSON, Markdown and standalone HTML — no external assets, so
an auditor opening it in five years does not need a CDN to still exist.

```json
{
  "schema_version": "1.0.0",
  "certificate_id": "ccf8c85e2d552faf44ba1042e91a01bd",
  "tool": "arachnid-sanitize",
  "tool_version": "0.1.0",
  "device_path": "/dev/sdb",
  "device_model": "SAMSUNG MZ7LH480HAHQ-00005",
  "device_serial": "S4EVNF0M123456",
  "device_size_bytes": 4194304,
  "device_bus": "SATA",
  "device_removable": false,
  "method": "DoD 5220.22-M (3-pass)",
  "method_detail": "software overwrite, 3 pass(es), written and verified",
  "pass_count": 3,
  "passes": [
    "fixed 0x00",
    "fixed 0xFF",
    "random seed fca94b482e284dbf9d135dfe53d4d77b5857b59e6e033bb4d10ca40d8f5c5129"
  ],
  "verification_passed": true,
  "verification_samples": 34,
  "verification_bytes_sampled": 1572864,
  "verification_coverage_percent": 37.5,
  "operator": "analyst@forensics-lab",
  "host": "forensics-lab-01",
  "platform": "windows/x86_64",
  "forced_system_volume": false,
  "public_key": "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
  "prev": "0000000000000000000000000000000000000000000000000000000000000000"
}
```

Two fields deserve an auditor's attention:

- **`method_detail`** — the claim in plain words. A `nist-purge` job that fell
  back to software says so here.
- **`forced_system_volume`** — whether the operator overrode the system-volume
  block.

### The register is a hash chain

`certificates.log` uses **the same construction as the evidence container's
custody log**: each line is `<signature> <certificate-json>`, signed with Ed25519
over the exact bytes, and each carries `prev`, the SHA-256 of the previous line.

| Tampering | Detected by |
|---|---|
| Editing a certificate | its signature no longer verifies |
| Removing or reordering one | the `prev` chain breaks |

Same caveat as the evidence container, too: without `--signing-key` the key is
generated per run, so the register proves **integrity**, not **origin**, unless
the fingerprint matches one recorded out-of-band. See
[Concepts § Signing keys](02-Concepts.md#signing-keys-and-what-verification-proves).

The samples in [`schema/samples/`](../../schema/samples/) are **generated by a
test**, so they cannot drift from real output.

---

## The TUI Sanitize screen

Screen `7` in `arachnid-tui`. A four-step flow: **device list → method → confirm
→ progress**.

| Key | Does |
|---|---|
| `j` / `k` | select |
| `Enter` | next step |
| `Esc` | back a step |
| `r` | re-enumerate |
| `f` | permit system-disk wipes for this session |
| `d` | toggle dry run |
| `x` | cancel a running job |
| **`Shift-W`** | **commit the wipe** (on the confirm step) |

### The commit key is deliberately `Shift-W`

Not `Enter`, and not `y` — both are what the ordinary confirmation dialog takes,
and this must not be clearable by the reflex that clears those.

### Other screen behaviour

- The device list **refuses to hand a system disk to the wipe flow** at all
  unless `f` is set, so the operator never types a serial for a device they
  cannot wipe.
- Pressing `f` raises an error-styled toast: *"system-disk wipes are now
  permitted for this session — this will destroy the running OS"*.
- The commit key is **rejected, not ignored**, until the 3-second cooldown
  elapses.
- Cancelling a running job asks first: *"Cancel the running wipe? The device
  will be left partially overwritten and will NOT be certified."*

---

## Exit codes

Disposal scripts can distinguish "we did not touch it" from "we touched it and
it did not verify".

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | runtime error |
| `2` | usage error |
| `3` | **refused by a safety rail — nothing was written** |
| `4` | wipe ran but verification failed |
| `5` | wipe completed with unwritable regions |

---

## Asset-disposal workflow

```bash
#!/usr/bin/env bash
# Wipe one drive, certify it, and fail loudly on anything less than success.
set -uo pipefail

DEV="${1:?usage: dispose.sh /dev/sdX SERIAL}"
SERIAL="${2:?serial required}"
CERTS=/srv/disposal/certs
KEY=/etc/arachnid/disposal.key

# 1 · Confirm the drive is what the ticket says it is.
arachnid-sanitize --json list-devices \
  | jq -e --arg p "$DEV" --arg s "$SERIAL" \
      '.[] | select(.path == $p and .serial == $s)' >/dev/null \
  || { echo "device/serial mismatch — check the ticket"; exit 1; }

# 2 · Rehearse. Writes nothing.
arachnid-sanitize wipe "$DEV" --method dod3 --confirm-serial "$SERIAL" --dry-run \
  || { echo "dry run refused — resolve before proceeding"; exit 3; }

# 3 · For real.
arachnid-sanitize wipe "$DEV" \
    --method dod3 --confirm-serial "$SERIAL" \
    --operator "${DISPOSAL_TECH:?set DISPOSAL_TECH}" \
    --signing-key "$KEY" --cert-dir "$CERTS"
case $? in
  0) echo "erased and certified" ;;
  3) echo "REFUSED by a safety rail — nothing was written"; exit 3 ;;
  4) echo "VERIFICATION FAILED — drive still holds data, do not release"; exit 4 ;;
  5) echo "UNWRITABLE REGIONS — drive is failing, destroy physically"; exit 5 ;;
  *) echo "wipe failed"; exit 1 ;;
esac

# 4 · Prove the register is intact before filing.
arachnid-sanitize cert --cert-dir "$CERTS" --verify
```

Points worth keeping:

- **Codes 4 and 5 mean the drive still holds data.** Neither is a success, and
  neither should let a drive into the resale or return pile.
- **`--signing-key` is not optional** for disposal you may have to evidence
  later. Record the fingerprint against the technician.
- `--no-countdown` is for runs where a human already confirmed the device out of
  band. Do not put it in an interactive script.

---

## Not in scope

- **No network or remote wipe triggering.** No outbound connections of any kind.
- **No unattended scheduling.** Every wipe is operator-initiated and confirmed
  in-session.
- **No reaching into RAID controller-hidden member disks.** Devices the OS
  cannot enumerate directly are out of scope rather than partially supported.
- **No self-deletion, no log clearing**, no attempt to hide the operation.
- **No writes outside the named device and the certificate directory.**

### A word to your SOC

`arachnid-sanitize` is, at the syscall level, **deliberately indistinguishable
from disk-wiping wiper malware** — because it is doing the same thing for an
authorized reason.

**Treat it as a separate allowlisting decision from `arachnid-core`.**
Allowlisting one does not imply the other, and for most sites it should not.
Many will want it allowed on dedicated disposal workstations only, or not at
all — preferring to **alert on it and confirm out of band**, since a genuine run
is a planned, ticketed event and an unplanned one is exactly the incident you
want the alert for.

The full disclosure is
[`docs/SOC-ALLOWLISTING.md` §4a](../SOC-ALLOWLISTING.md).

---

[← FAQ](13-FAQ.md) · [Home](Home.md) · [File Recovery →](15-File-Recovery.md)
