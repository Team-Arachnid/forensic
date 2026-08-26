# Release keys and signing

Every release artifact is verified twice before anything runs it: a SHA-256
digest, and a signature over the file those digests live in. This directory
documents the key half of that, because it is the one part a maintainer has to
set up by hand and the one part nobody can automate away.

## The trust anchor

The chain is short on purpose:

```
install.sh / install.ps1        pin the public key in their own source
        │                       (and you are asked to read them first)
        ▼
SHA256SUMS.minisig  ──verifies──►  SHA256SUMS
                                        │
                                        ▼
                                   the binary's SHA-256
```

Everything reduces to one question: **is the key pinned in the installer the
project's real key?** The installers are served straight from this repository —
`raw.githubusercontent.com/ArachnidGs/forensic/main/install.sh` — so there is no
separate download host that could serve a different pin, and `git log install.sh`
is the audit trail for every change to it.

`arachnid-cli self update` verifies the same signature with the same key,
embedded at build time, so an update is checked the same way a first install is.

## Status

**No release key has been generated yet.** Until one is:

- `install.sh` and `install.ps1` fail closed with an explanation. They do not
  fall back to "checksum only" — a checksum fetched over the same channel as
  the artifact proves the download was not corrupted, and nothing at all about
  where it came from.
- `arachnid-cli self update` refuses to run and says why.
- The release workflow fails rather than publishing unsigned artifacts.

Failing closed is the intended behaviour, not an oversight. Fix it by doing the
following once.

## Generating the key

```bash
minisign -G -p release/minisign.pub -s ~/.arachnid/release.key
```

Keep the secret key off this machine and out of this repository. `.gitignore`
already excludes `*.key`; that is a safety net, not a plan.

## Pinning the public key

The public key goes in four places, all of them the same value:

| Where | What to set |
|---|---|
| `release/minisign.pub` | the file `minisign -G` wrote (commit it) |
| `install.sh` | `PUBKEY=` — the base64 key line, not the whole file |
| `install.ps1` | `$PubKey =` — the same line |
| GitHub → repository **variables** → `MINISIGN_PUBKEY` | the same line, so the release workflow can embed it in the binary and self-check its own signature |

The secret key and its password go in GitHub → repository **secrets**:

| Secret | What |
|---|---|
| `MINISIGN_SECRET_KEY` | the contents of `~/.arachnid/release.key` |
| `MINISIGN_PASSWORD` | the password protecting it |

## Signing mode

Releases are signed in minisign's **legacy** mode — `minisign -S`, without
`-H`. That produces a plain Ed25519 signature over the file itself, which
`arachnid-cli` verifies with `ed25519-dalek`, a crate already in the dependency
tree for the evidence custody chain.

The prehashed mode (`-H`) signs a BLAKE2b digest instead. Accepting it would
mean adding a second hash implementation to the binary to check something we
also control the signing of. `arachnid-cli` refuses a prehashed signature rather
than ignoring the difference, so a release accidentally signed with `-H` fails
loudly at verification instead of quietly verifying nothing.

## Rotating the key

Rotation is a release, not a patch: the new public key has to reach users
through a build they already trust.

1. Generate the new key and pin it everywhere above.
2. Cut a release signed with the **old** key, whose binary embeds the **new**
   public key. Existing installs can verify that release, and afterwards trust
   the new key.
3. Sign the release after that with the new key.

Skipping step 2 strands everyone who installed before the rotation: their
binary refuses every subsequent update, correctly, because it is signed by a
key they have no reason to trust.

## Verifying a release by hand

No installer, no `self update` — the path for an air-gapped or policy-restricted
environment:

```bash
minisign -Vm SHA256SUMS -P "$(cat release/minisign.pub | tail -n1)"
sha256sum -c SHA256SUMS --ignore-missing
```

Both must pass. The first says the digests are ours; the second says the binary
matches them.
