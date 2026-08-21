# Certificate of Data Erasure

**Certificate ID:** `ccf8c85e2d552faf44ba1042e91a01bd`

Issued by arachnid-sanitize 0.1.0 on forensics-lab-01 (windows/x86_64).

## Device

| Field | Value |
|---|---|
| Model | SAMSUNG MZ7LH480HAHQ-00005 |
| Serial number | `S4EVNF0M123456` |
| Capacity | 4.0 MiB (4194304 bytes) |
| Interface | SATA |
| Removable | no |
| OS path at wipe time | `/dev/sdb` |

## Erasure

| Field | Value |
|---|---|
| Method requested | DoD 5220.22-M (3-pass) |
| What actually ran | software overwrite, 3 pass(es), written and verified |
| Passes | 3 |
| Started (UTC) | 2026-08-28T08:49:51.9805502Z |
| Finished (UTC) | 2026-08-28T08:49:52.0275373Z |
| Duration | 0.0 s |
| Bytes written | 12.0 MiB |

### Pass sequence

1. fixed 0x00
2. fixed 0xFF
3. random seed fca94b482e284dbf9d135dfe53d4d77b5857b59e6e033bb4d10ca40d8f5c5129

A random pass is generated from the seed recorded above, so its content can be recomputed and independently re-checked at any offset.

## Verification

**PASSED** — 34 region(s) sampled, 1.5 MiB read back (37.5000% of the device), every sampled byte matched the expected pattern.

## Attestation

**Operator:** analyst@forensics-lab

**Signing key (Ed25519):** `d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a`

**Previous register entry:** `0000000000000000000000000000000000000000000000000000000000000000`

This certificate is signed and chained into an append-only register. Verify it with `arachnid-sanitize cert --verify`. The signature proves the certificate has not been altered; it proves origin only against a key fingerprint recorded out of band.
