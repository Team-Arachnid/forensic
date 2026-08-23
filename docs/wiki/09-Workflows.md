---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 9 · Workflows

[← Reports & Schemas](08-Reports-and-Schemas.md) · [Home](Home.md) · [Next: Security & Threat Model →](10-Security-and-Threat-Model.md)

End-to-end playbooks. Each one is a sequence you can follow with a host in front
of you.

---

## Contents

- [Before any engagement](#before-any-engagement)
- [Endpoint triage](#workflow-1--endpoint-triage)
- [Network investigation](#workflow-2--network-investigation)
- [Analysing a PCAP someone handed you](#workflow-3--analysing-a-pcap-someone-handed-you)
- [Verifying a container you received](#workflow-4--verifying-a-container-you-received)
- [SOAR and scripted response](#workflow-5--soar-and-scripted-response)
- [Air-gapped analysis](#workflow-6--air-gapped-analysis)
- [Validating an EDR rule](#workflow-7--validating-an-edr-rule)
- [Team key management](#workflow-8--team-key-management)
- [Media disposal](#workflow-9--media-disposal)

---

## Before any engagement

Once per responder, once per kit:

**1 · Issue a persistent signing key.**

```bash
mkdir -p ~/.arachnid && chmod 700 ~/.arachnid
head -c 32 /dev/urandom > ~/.arachnid/analyst-7.key
chmod 600 ~/.arachnid/analyst-7.key
```

**2 · Record its fingerprint out-of-band.**

```bash
arachnid-core collect -o /tmp/keycheck --signing-key ~/.arachnid/analyst-7.key | tail -3
rm -rf /tmp/keycheck
```

```
Signing key fingerprint: 6e5cbdee…d827c7
```

Put that in the case management system, the team roster, wherever an adversary
who rewrites a container cannot also reach. **Without this step, `verify` can
never prove origin.**

**3 · Verify your binary.**

```bash
sha256sum -c arachnid-core-0.1.0-x86_64-unknown-linux-musl.sha256
gpg --verify arachnid-core-0.1.0-x86_64-unknown-linux-musl.asc \
             arachnid-core-0.1.0-x86_64-unknown-linux-musl
```

**4 · Get it allowlisted.** Hand the SOC
[`docs/SOC-ALLOWLISTING.md`](../SOC-ALLOWLISTING.md) and, if they want it, a
`--dry-run` demonstration ([Workflow 7](#workflow-7--validating-an-edr-rule)).

**5 · Have somewhere to write.** Put the container on a dedicated collection
volume or share, and get that path excluded from real-time scanning. A memory
image of an infected host **will** trigger signature hits. That is the image
working correctly.

---

## Workflow 1 — Endpoint triage

A host is suspected compromised. You have a shell on it.

### 1 · Collect, with attribution

```bash
sudo arachnid-core collect \
    -o /mnt/collection/case-4471/host01 \
    --operator "analyst-7" \
    --signing-key ~/.arachnid/analyst-7.key \
    --log /mnt/collection/case-4471/host01.oplog
```

Elevate if you can. Unprivileged collection misses processes owned by other
users, cannot map sockets to owners, and cannot read `HKLM` values — and it says
so in `warnings`.

### 2 · Check the exit code before anything else

```bash
echo $?
```

`4` means gaps. Read them now, not later:

```bash
jq -r '.collection.warnings[]' /mnt/collection/case-4471/host01/artifacts/report.json
```

Every count in the report below a warning is a **floor**, not a total.

### 3 · Record the fingerprint from the run output

Compare it against the one on file for `analyst-7`. If it differs, something is
wrong with your kit before it is wrong with the host.

### 4 · Triage the report

```bash
arachnid-core report /mnt/collection/case-4471/host01 --format html \
    -o /mnt/collection/case-4471/host01-triage.html
```

Read in this order:

1. **Collection gaps** — what you cannot see.
2. **Connections to routable addresses** — what left the network, and which
   process owned it.
3. **Persistence entries** — what survives a reboot.
4. **Processes with an unhashable image** — deleted or replaced binaries.
5. **Active sessions** — who is on the box right now.

### 5 · Pull specific answers

```bash
C=/mnt/collection/case-4471/host01

# listening sockets and their owners
jq -r '.[] | select(.state=="LISTEN")
      | "\(.protocol)\t\(.local_addr):\(.local_port)\t\(.process_name // "-")"' \
  $C/artifacts/connections.json

# anything running from a temp path
jq -r '.[] | select(.exe != null and (.exe | test("/tmp/|/dev/shm/")))
      | "\(.pid)\t\(.exe)"' $C/artifacts/processes.json

# processes with no parent still alive — reparented, often after the parent exited
jq -r '.[] | select(.parent_pid == 1 and .pid > 1000) | "\(.pid)\t\(.name)"' \
  $C/artifacts/processes.json

# kernel modules with no on-disk file — a real finding
jq -r '.[] | select(.path == null) | .name' $C/artifacts/kernel_modules.json

# every distinct binary hash, for a bulk lookup against your own corpus
jq -r '.[].exe_sha256 | select(. != null)' $C/artifacts/processes.json | sort -u
```

### 6 · Acquire memory if the finding warrants it

Live enumeration goes through OS APIs, and a kernel-level implant can lie to
them. If anything above looks like a rootkit — a module with no file, a process
you cannot hash, sockets with no owner — a memory image is the countermeasure:

```bash
sha256sum /opt/avml
sudo arachnid-core collect \
    -o /mnt/collection/case-4471/host01-mem \
    --operator "analyst-7" --signing-key ~/.arachnid/analyst-7.key \
    --memory-tool /opt/avml --memory-tool-sha256 <hex>
```

A second container, not an append — containers are never appended to.

### 7 · Verify before you leave the host

```bash
arachnid-core verify /mnt/collection/case-4471/host01
```

Verify while you are still standing next to the evidence, not after it has
travelled.

### 8 · Note what the tool cannot tell you

In your case notes, state explicitly:

- collection was **not atomic** — a process could exit between the process-table
  read and the connection-table read;
- live enumeration is **API-mediated** and a kernel implant defeats it;
- anything an attacker removed **before** you arrived (cleared utmp, deleted unit
  file) is gone, not merely unreported.

---

## Workflow 2 — Network investigation

You need to see what a host is talking to.

### 1 · Find the interface

```bash
sudo arachnid-core capture --list-devices
```

### 2 · Capture, bounded and filtered

```bash
sudo arachnid-core capture \
    -o /mnt/collection/case-4471/net \
    --operator "analyst-7" --signing-key ~/.arachnid/analyst-7.key \
    -d eth0 \
    -f "not port 22" \
    --duration 900
```

Exclude your own session. Bound the run — an unbounded capture that fills the
volume is worse than a short one.

**Leave promiscuous off** unless you specifically need traffic not addressed to
this host: enabling it changes the interface's receive mode, which is an
observable change to the host you are examining.

### 3 · Check for drops immediately

```bash
jq '.capture | {kernel: .packets_dropped_kernel, interface: .packets_dropped_interface, written: .packets_written}' \
   /mnt/collection/case-4471/net/artifacts/report.json
```

Non-zero means the capture has holes. Tighten the filter, lower `--snaplen`, or
write to faster storage, and go again.

### 4 · Analyse the savefile

`capture` does not analyse. Run `parse-pcap` on what it wrote:

```bash
arachnid-core parse-pcap \
    /mnt/collection/case-4471/net/artifacts/capture.pcap \
    -o /mnt/collection/case-4471/net-analysis \
    --operator "analyst-7" --signing-key ~/.arachnid/analyst-7.key
```

That produces a **second container** whose custody log records the source
savefile's digest — so the analysis is bound to the exact bytes captured.

### 5 · Pivot on the indicators

```bash
A=/mnt/collection/case-4471/net-analysis/artifacts/pcap_analysis.json

# every hostname seen
jq -r '.indicators[] | select(.kind | test("dns_query|tls_sni|http_host")) | .value' $A \
  | sort -u

# top talkers by packet count
jq -r '.indicators[] | select(.kind=="ipv4") | "\(.count)\t\(.value)"' $A | sort -rn | head

# DNS resolutions observed
jq -r '.indicators[] | select(.kind=="dns_answer") | .value' $A

# biggest flows
jq -r '.flows[:10][] | "\(.bytes)\t\(.src_addr):\(.src_port) -> \(.dst_addr):\(.dst_port)"' $A

# anything cut short by the reassembly ceiling
jq -r '.flows[] | select(.truncated) | "\(.src_addr):\(.src_port) -> \(.dst_addr):\(.dst_port)"' $A
```

### 6 · Correlate with the host collection

The connection table from Workflow 1 and the flow table from here are two views
of the same traffic taken at different times. A flow with no matching process,
or a process with a socket that appears in no flow, is the interesting case.

---

## Workflow 3 — Analysing a PCAP someone handed you

```bash
# 1 · hash it before you touch it, and record that hash in your notes
sha256sum incoming.pcap

# 2 · analyse; the digest is recorded in the custody log automatically
arachnid-core parse-pcap incoming.pcap \
    -o ./ev-incoming \
    --operator "analyst-7" --signing-key ~/.arachnid/analyst-7.key

# 3 · confirm the recorded digest matches what you saw
cut -d' ' -f2- ./ev-incoming/custody.log | jq -r 'select(.event=="note") | .detail'
```

```
invocation: arachnid-core parse-pcap incoming.pcap -o ./ev-incoming …
source pcap incoming.pcap sha256=ce51b95b…7f6e02 size=454
```

The source file is **never modified and never copied** into the container. It
stays where it is; the container binds to its bytes by digest.

### If it is huge

```bash
arachnid-core parse-pcap huge.pcap -o ./ev-huge \
    -f "not port 445 and not port 139" \
    --max-stream-bytes 2097152
```

Then check what the ceiling cost you:

```bash
jq '[.flows[] | select(.truncated)] | length' ./ev-huge/artifacts/pcap_analysis.json
```

### If decode errors are non-zero

```bash
jq '.pcap.decode_errors' ./ev-incoming/artifacts/report.json
```

Likely causes: a link type this build does not decode, frames truncated by a low
snaplen at capture time, or genuine corruption. Check `datalink` in the analysis
against [the supported link types](07-Network-Forensics.md#link-types).

---

## Workflow 4 — Verifying a container you received

Anyone can re-check a container without trusting the collecting host.

```bash
arachnid-core verify /path/to/container
echo "exit=$?"
```

| Exit | Means |
|---|---|
| `0` | every artifact matches the signed custody log |
| `3` | one or more problems — the report lists each |
| `1` | not a readable container (missing `manifest.json` or `custody.log`) |

### The step most people skip

```
key fingerprint:  6e5cbdeecd531dc9b69681ac71b890c6e5338b0dd9664823626c6f9c03d827c7
```

**Compare that against the fingerprint recorded out-of-band at collection.** If
it does not match a key you have on file for the responder who claims to have
produced it, the container did not come from them — whatever `verify` says about
its internal consistency.

Verification of a container signed with an ephemeral key proves **integrity**
only. See [Concepts § Signing keys](02-Concepts.md#signing-keys-and-what-verification-proves).

### Independent verification, no Arachnid required

```bash
cd container/artifacts
cut -d' ' -f2- ../custody.log \
  | jq -r 'select(.event=="artifact" and .sha256) | "\(.sha256)  \(.name)"' \
  | sha256sum -c -
```

That checks artifact digests with coreutils alone. Signatures and the chain need
an Ed25519 implementation — see
[Writing a third-party verifier](05-Evidence-Container.md#writing-a-third-party-verifier).

### Read the chain of custody

```bash
cut -d' ' -f2- container/custody.log \
  | jq -r '[.seq, .ts_utc, .event, (.name // .detail // "")] | @tsv'
```

Or, interactively, `arachnid-tui` → Verify (`5`) → `c`.

---

## Workflow 5 — SOAR and scripted response

Exit codes are stable across releases. Branch on them.

```bash
#!/usr/bin/env bash
# Collect, handle partial results honestly, verify, and fail loudly on tampering.
set -uo pipefail

CASE="${1:?usage: triage.sh <case-id>}"
OUT="/mnt/collection/${CASE}/$(hostname)"
KEY="/etc/arachnid/responder.key"
RESPONDER="${ARACHNID_OPERATOR:-soar-runner}"

arachnid-core --json --log "${OUT}.oplog" collect \
    -o "$OUT" --operator "$RESPONDER" --signing-key "$KEY" > "${OUT}.collect.json"
rc=$?

case $rc in
  0) echo "collection complete" ;;
  4) echo "PARTIAL — the following collectors were degraded:"
     jq -r '.collection.warnings[]' "${OUT}.collect.json"
     # keep going: you have evidence, it is just incomplete
     ;;
  2) echo "usage error — check the invocation"; exit 2 ;;
  *) echo "collection FAILED (rc=$rc)"; exit 1 ;;
esac

arachnid-core --json verify "$OUT" > "${OUT}.verify.json"
vrc=$?
if [ "$vrc" -eq 3 ]; then
    echo "INTEGRITY FAILURE — do not use this container"
    jq -r '.problems[]' "${OUT}.verify.json"
    exit 3
fi

# Record the fingerprint for the case file
jq -r '.key_fingerprint' "${OUT}.verify.json"

arachnid-core report "$OUT" --format html -o "${OUT}.html"
echo "report: ${OUT}.html"
```

Key points:

- **`--json` on `collect`, `capture`, `parse-pcap` and `verify`** gives
  structured stdout. (`report` chooses its rendering with `--format json`
  instead.) The operational log goes to stderr or `--log`, so the two never
  interleave.
- **Exit 4 is not failure.** Handle it, record the gaps, continue.
- **Exit 3 is a hard stop.** A container that does not verify is not evidence.
- **`--signing-key` is not optional** in an automated pipeline: an unattended
  run producing ephemeral-key containers produces containers nobody can attribute.
- **Capture the fingerprint into the case record** on every run.

### Useful one-liners for a playbook

```bash
# a device list a playbook can choose from
arachnid-core --json capture --list-devices | jq -r '.[] | select(.loopback|not) | .name'

# did anything degrade?
jq -e '.collection.warnings | length == 0' report.json >/dev/null \
  && echo clean || echo degraded

# did the capture drop?
jq -e '.capture.packets_dropped_kernel == 0' report.json >/dev/null \
  && echo lossless || echo "GAPS"
```

---

## Workflow 6 — Air-gapped analysis

Collect on the network, analyse off it.

**On the host:**

```bash
sudo arachnid-core collect -o /media/usb/case-4471/host01 \
    --operator "analyst-7" --signing-key /media/usb/keys/analyst-7.key
arachnid-core verify /media/usb/case-4471/host01
```

**On the analysis workstation:**

```bash
# verify first, before you read a single field
arachnid-core verify /mnt/evidence/case-4471/host01
# compare the fingerprint against the case record

arachnid-core report /mnt/evidence/case-4471/host01 --format html -o triage.html
```

The HTML report is **fully self-contained** — no external stylesheets, fonts,
scripts or images — so it renders on a machine with no network at all.

And Arachnid itself makes **no outbound connections of any kind**: no telemetry,
no update check, no indicator lookup, no DNS resolution of anything collected.
An air-gapped run behaves identically to a connected one, which is not true of
most tooling in this space.

---

## Workflow 7 — Validating an EDR rule

Before a real engagement, prove to the SOC what the tool touches — without
producing evidence you then have to account for.

```bash
arachnid-core --log-level debug collect -o /tmp/rehearsal --dry-run
ls /tmp/rehearsal
# ls: cannot access '/tmp/rehearsal': No such file or directory
```

Every collector runs. Every hash is computed. The custody chain advances in
memory. **Nothing reaches disk**, including the container directory.

What the SOC should observe, and nothing else:

| Expected | Not expected |
|---|---|
| reads of `/proc`, `/sys`, systemd/cron/autostart paths | any write outside `-o` |
| `KEY_READ` registry opens (Windows) | any registry write |
| `OpenProcess` with `PROCESS_QUERY_LIMITED_INFORMATION \| PROCESS_VM_READ` | `ptrace`, injection, remote threads |
| no child processes | any child except a named `--memory-tool` |
| no sockets | any outbound connection, any listener |

The complete list, with every path and API, is
[`docs/SOC-ALLOWLISTING.md`](../SOC-ALLOWLISTING.md) §4 and §5. If the tool does
something not on that page, that is a defect worth reporting.

For a capture rule, expect `AF_PACKET` socket creation and `SO_ATTACH_FILTER`
(Linux) or a handle to `\Device\NPCAP\<iface>` (Windows). Both are inherent to
packet capture, and are why `capture` is a separate subcommand you can decline
to allow.

---

## Workflow 8 — Team key management

**One key per responder, not one per team.** The fingerprint is the attribution
claim; a shared key attributes nothing.

```bash
# per responder, on their own kit
mkdir -p ~/.arachnid && chmod 700 ~/.arachnid
head -c 32 /dev/urandom > ~/.arachnid/$(whoami).key
chmod 600 ~/.arachnid/$(whoami).key
```

Both raw and hex seed files are accepted, so a key can be transported as text
when that is easier:

```bash
xxd -p -c 64 ~/.arachnid/analyst-7.key > analyst-7.hex
# both files produce the same fingerprint
```

Maintain a roster the containers can be checked against:

| Responder | Fingerprint | Issued | Retired |
|---|---|---|---|
| analyst-7 | `6e5cbdee…d827c7` | 2026-08-01 | |
| analyst-3 | `a1f09b22…4e0c81` | 2026-06-14 | 2026-08-20 |

Treat the key file like any other credential:

- do not copy it onto the host you are examining if you can avoid it;
- rotate it if a kit is lost, and mark the old fingerprint retired rather than
  deleting the row — containers signed under it still exist;
- back it up somewhere the responder does not carry into the field.

**When there is no persistent key**, say so explicitly in the case notes: *"this
container was signed with an ephemeral key; verification establishes integrity,
not origin."* That sentence is much cheaper to write now than to explain later.

---

## Workflow 9 — Media disposal

> **This workflow destroys data.** Full chapter:
> [Secure Erasure](14-Secure-Erasure.md).

A drive is leaving the organization — resale, return, or scrap — and must be
provably erased.

### 1 · Identify it, and confirm against the ticket

```bash
arachnid-sanitize list-devices
```

```
PATH                   MODEL                      SERIAL                     SIZE  BUS      FLAGS
/dev/nvme0n1           SAMSUNG MZVL41T0HBLB-00BH1 S6B7NX0X602424        953.9 GiB  NVMe
/dev/sda               Elements SE SSD            23315C401334          931.5 GiB  USB      SYSTEM
                       └─ backs a filesystem the running OS has mounted
```

The `SERIAL` column is what you will type back. Match it against the disposal
ticket **before** going further — the serial, not the path. Paths get reused
when drives are hot-swapped; serials do not.

### 2 · Rehearse

```bash
arachnid-sanitize wipe /dev/sdb \
    --method dod3 --confirm-serial S4EVNF0M123456 --dry-run
```

Every rail runs, the estimate is produced, **zero bytes are written**. This is
what catches a wrong serial or a wrong path before it costs you a drive.

### 3 · Erase

```bash
sudo arachnid-sanitize wipe /dev/sdb \
    --method dod3 \
    --confirm-serial S4EVNF0M123456 \
    --operator "tech-4" \
    --signing-key ~/.arachnid/tech-4.key \
    --cert-dir /srv/disposal/certs
```

A 3-second countdown precedes the first write. `Ctrl-C` cancels — leaving the
device partially overwritten and **uncertified**, which is recorded rather than
hidden.

### 4 · Read the exit code as a disposition

| Exit | Means | Do |
|---|---|---|
| `0` | erased, verified, certified | release the drive |
| `3` | **refused by a rail — nothing written** | resolve and retry; the drive is untouched |
| `4` | wipe ran, **verification failed** | drive still holds data — destroy physically |
| `5` | completed with **unwritable regions** | drive is failing — destroy physically |

Codes 4 and 5 both mean data may survive. Neither is a success, and neither
should let a drive into the resale pile.

### 5 · File the certificate

```bash
arachnid-sanitize cert --cert-dir /srv/disposal/certs --verify
arachnid-sanitize cert --cert-dir /srv/disposal/certs --id <ID> \
    --format html -o /srv/disposal/certs/<ID>.html
```

Read two fields before filing:

- **`method_detail`** — states plainly whether a hardware purge ran or a
  software overwrite stood in for one. In this build it is always the latter.
- **`forced_system_volume`** — whether the operator overrode the system-volume
  block.

### 6 · Know what you can and cannot claim

- This build issues **no hardware sanitize command**. A `nist-purge` job is a
  3-pass software overwrite, and the certificate says so — assess against NIST
  800-88 **Clear**, not Purge.
- **Crypto-erase is refused** on every device.
- On **SSDs**, wear levelling means an overwrite cannot reach every physical
  cell. For flash leaving the organization, physical destruction or the vendor's
  own utility remains the defensible path.

Write those caveats into the disposal record. They are much cheaper to state now
than to explain to an auditor later.

---

[← Reports & Schemas](08-Reports-and-Schemas.md) · [Home](Home.md) · [Next: Security & Threat Model →](10-Security-and-Threat-Model.md)
