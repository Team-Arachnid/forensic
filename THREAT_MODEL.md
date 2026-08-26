# Threat model — the installer and the update check

This document covers exactly two things: **how `arachnid-cli` gets onto a
machine**, and **the one network request the binary makes on its own account**.

It exists separately from the suite's main threat model because these are the
parts a security reviewer has to assess before anything else runs. The rest of
the model — what the collectors read, what the erasure engine writes, what the
evidence container proves — is in
[README § Threat model](README.md#threat-model) and
[wiki § Security & Threat Model](docs/wiki/10-Security-and-Threat-Model.md).

> **Short version for an allowlisting decision.** The binary makes one outbound
> request: a version check against the GitHub releases API, once a day, only on
> an interactive terminal, capped at 500 ms, sending nothing but the request. It
> never installs anything by itself. `--no-update-check` or
> `ARACHNID_NO_UPDATE_CHECK=1` removes even that. Every other network byte comes
> from the installer or from `self update`, both of which you run deliberately.

---

## Contents

- [What the installer downloads](#what-the-installer-downloads)
- [What it verifies, and in what order](#what-it-verifies-and-in-what-order)
- [What it does with privileges](#what-it-does-with-privileges)
- [What it writes](#what-it-writes)
- [The update check](#the-update-check)
- [`self update`](#self-update)
- [What a reviewer should check](#what-a-reviewer-should-check)
- [Residual risks we do not claim to solve](#residual-risks-we-do-not-claim-to-solve)

---

## What the installer downloads

Four requests, all HTTPS, all to hosts you can pin:

| Request | To | Why |
|---|---|---|
| `GET /repos/ArachnidGs/forensic/releases/latest` | `api.github.com` | resolve the newest tag. Skipped entirely if you pass an explicit version |
| `GET /releases/download/<tag>/arachnid-cli-<target>` | `github.com` | the binary |
| `GET /releases/download/<tag>/SHA256SUMS` | `github.com` | digests for every artifact in the release |
| `GET /releases/download/<tag>/SHA256SUMS.minisig` | `github.com` | the detached signature over that file |

Nothing else. No analytics endpoint, no install counter, no identifier of any
kind. The scripts send a User-Agent naming the tool and nothing more.

`install.sh` uses `curl --proto '=https' --tlsv1.2` (or `wget`); `install.ps1`
uses `Invoke-WebRequest`. Neither disables certificate validation, and neither
offers a flag to.

---

## What it verifies, and in what order

Order is the whole design. Each step is only worth doing because the one before
it passed.

1. **The signature over `SHA256SUMS`**, against a minisign public key **pinned
   in the installer's own source**. Not fetched — pinned. A key downloaded
   alongside the thing it authenticates proves nothing.
2. **The binary's SHA-256**, against the file just proven to be ours.
3. Only then is anything written to the install directory.

**Either failure aborts, having installed nothing.** There is no `--force`, no
`--skip-verify`, and no fallback to "checksum only" when no signature tool is
present — that fallback would prove the download was not corrupted in transit
and nothing whatsoever about who produced it. If `minisign` is missing, the
installer stops and tells you how to install it, or how to verify by hand.

The pin is reviewable because the installers **are** this repository's files:
`raw.githubusercontent.com/ArachnidGs/forensic/main/install.sh` serves
`install.sh` from `main`. There is no separate download host that could serve
something else, and no CDN cache between the two — the bytes you fetch are the
bytes in the commit, and `git log install.sh` is the audit trail for the key
pin.

Pin a tag rather than `main` if your policy requires a fixed artifact:
`raw.githubusercontent.com/ArachnidGs/forensic/v0.1.0/install.sh`.

### Current status

No release key has been generated yet, so both installers **fail closed** and
`self update` refuses to run. See [release/README.md](release/README.md).

---

## What it does with privileges

**The installer never elevates.** It runs entirely as your user, installs to a
directory your user owns, and edits a file your user owns.

There is exactly one privileged operation anywhere near it, and it is optional:

```
sudo setcap cap_net_raw,cap_net_admin=eip ~/.local/bin/arachnid-cli
```

That grants live packet capture without running the whole tool as root. The
installer prints the command, asks, and runs it **only** on an explicit `y` at
an interactive terminal. A piped install (`curl … | sh`) has no terminal to
answer from, so it prints the command and moves on rather than blocking or
assuming consent.

`/usr/local/bin` is used on macOS **only when it is already writable**. The
installer never acquires root to make it so; it falls back to `~/.local/bin`.

Npcap is never installed for you. It is third-party kernel driver software, and
your trust chain for a kernel driver should stay with its vendor. The installer
prints the official download link.

---

## What it writes

| Path | What | Removed by `self uninstall` |
|---|---|---|
| `~/.local/bin/arachnid-cli`, `/usr/local/bin/arachnid-cli`, or `%LOCALAPPDATA%\arachnid-forensic\bin\arachnid-cli.exe` | the binary | yes |
| one shell profile | two lines: a marker comment and one PATH line | yes |
| `$XDG_STATE_HOME/arachnid/update-check` | a timestamp, written by the binary, not the installer | no — delete it yourself |

The shell profile edit is **marked**, and uninstall matches on that marker
rather than on the path. If you had already added the same directory to PATH
yourself, your line survives; only the installer's own is removed.

Nothing else is touched. Evidence containers, certificates and recovery output
live wherever you put them and are never the installer's business.

---

## The update check

This is the only thing in the suite that reaches the network without being asked
to, so it is specified rather than described.

### What it does

One `GET https://api.github.com/repos/ArachnidGs/forensic/releases/latest`. If
the tag is newer than the running version, one line to **stderr**:

```
A newer version (0.2.0) is available. Run 'arachnid-cli self update' to upgrade.
```

Then the command you actually ran proceeds, unchanged, with its own exit code.

### What constrains it

| Constraint | Why it is there |
|---|---|
| **Interactive terminals only** — skipped unless stderr is a TTY | A SOAR playbook, a cron job, a CI pipeline and every scripted evidence run make **no network call at all**. That is also where a delay would actually hurt |
| **Once every 24 hours**, tracked by a timestamp file | Twenty commands make one request, not twenty |
| **500 ms hard cap** | An unreachable network costs half a second once a day, not a hang |
| **Silent on every failure** | Offline, air-gapped, DNS blackholed, proxy refusing, rate-limited: no message, no delay past the cap, no change to the exit code |
| **stderr, never stdout** | stdout carries `--json` output and rendered reports. A version notice in one would corrupt an evidence artifact |
| **The timestamp is written before the request** | An unreachable network does not retry on every command |
| **It only ever checks** | Nothing is downloaded, nothing is replaced. See below |

### What it sends

The URL, and a `User-Agent: arachnid-cli/<version>` header. That is the whole
request. No machine identifier, no hostname, no username, no usage counters, no
case identifiers, and nothing whatsoever from any collection, capture, recovery
or erasure.

Your IP address and the User-Agent are visible to GitHub, as with any HTTPS
request to them. If that is unacceptable in your environment, turn it off — and
note that in a scripted or air-gapped environment it never ran in the first
place.

### Turning it off

Both work, both are honoured silently — there is no nagging about the flag that
stops the nagging:

```bash
arachnid-cli --no-update-check <command>     # this run
export ARACHNID_NO_UPDATE_CHECK=1            # permanently
```

`arachnid-cli doctor` reports which state you are in, so an operator can confirm
it rather than assume it.

### Why it exists at all, in a tool that otherwise never phones home

Because the honest answer to "does this tool phone home" should be a precise
description a reviewer can verify, rather than silence. A forensic tool running
a version behind a fixed integrity bug is a real problem, and an operator who
never learns a fix exists is worse served than one told once a day, in one line,
on stderr, with two ways to switch it off.

If your policy is that the binary makes no outbound connection, ever: set
`ARACHNID_NO_UPDATE_CHECK=1` in the environment your operators use, or block
`api.github.com` — the check fails silently and nothing else changes.

---

## `self update`

Different in kind from the check: you asked for it, so it is allowed to block,
download, and replace the binary.

It follows exactly the installer's flow — signature over `SHA256SUMS`, then the
artifact's digest, then replace — with one difference in its favour: it verifies
the signature **itself**, using the release key embedded at build time and the
Ed25519 implementation already in the binary for the evidence custody chain. It
needs no external `minisign`.

- A build with **no embedded release key refuses to update**, rather than
  falling back to checksum-only.
- The new binary is written beside the old one and renamed over it, so an
  interrupted update leaves the working binary in place rather than a
  half-written one.
- `--dry-run` performs every download and both verifications and installs
  nothing.

**Nothing updates automatically, ever.** Silently replacing a forensic tool's
binary would break the "the same binary processed this evidence" claim that
chain-of-custody rests on. If a container was produced by 0.1.0, 0.1.0 is what
should still be on the machine when someone asks.

---

## What a reviewer should check

Before allowlisting this in a managed environment:

1. **The pinned key.** Compare `PUBKEY` in `install.sh`, `$PubKey` in
   `install.ps1`, and `release/minisign.pub` — all three must be the same value,
   and it must be the project's published key.
2. **That verification is not optional.** Search both installers for a bypass.
   There is no `--force` and no `--skip-verify`; if a fork has added one, that
   is your answer.
3. **The network surface.** `strings` on the binary shows exactly one outbound
   URL, `api.github.com/repos/ArachnidGs/forensic/releases/latest`. Anything
   else in a build claiming to be this one is not.
4. **The disable path works.** Set `ARACHNID_NO_UPDATE_CHECK=1`, run
   `arachnid-cli doctor`, and confirm it reports the check as disabled.
5. **Reproducibility.** Release binaries are built by the workflow in
   `.github/workflows/release.yml` from a tagged commit, with the build hash
   stamped into the binary. `arachnid-cli version` prints it; compare it against
   the tag you reviewed.
6. **The behavioural disclosure.**
   [docs/SOC-ALLOWLISTING.md](docs/SOC-ALLOWLISTING.md) covers what the binary
   does once installed, including §5 on network behaviour and §4b on Recover's
   raw device reads.

---

## Residual risks we do not claim to solve

Stating these is cheaper than having them found later.

- **A compromised release key signs valid-looking releases.** Nothing in the
  chain survives that. Mitigation is key custody, not code: the secret key
  lives outside this repository and outside CI except as an encrypted secret.
- **A compromised GitHub account can publish a release** and, with the key,
  sign it. The pinned key limits this to whoever holds the key.
- **The first install trusts the installer you fetched.** That is why the
  inspect-then-run path is documented first, and why the scripts are in version
  control: you can diff what you were served against what is committed.
- **TLS interception in a managed environment** means your proxy sees, and
  could alter, the download. The signature check catches alteration; it does
  not hide the fetch from the proxy.
- **`api.github.com` learns your IP** when the update check runs. Disable the
  check if that matters.
- **No reproducible-build guarantee for `arachnid-cli` yet.** The existing
  `scripts/build-release.sh` produces byte-identical `arachnid-core` builds, and
  the release workflow does not yet do the same for `arachnid-cli`. Until it
  does, you can verify the signature and the digest, but you cannot independently
  rebuild the artifact and compare. This is a known gap, not a claim.
