---
# Empty on purpose. Jekyll only renders a file that carries a front-matter
# block, and the layout itself comes from the defaults in _config.yml — so
# nothing here has to be repeated per page, and scripts/publish-wiki.sh
# strips this block again before the page reaches the GitHub wiki.
---
# 15 · File Recovery (Arachnid Recover)

[← Secure Erasure](14-Secure-Erasure.md) · [Home](Home.md)

`arachnid-recover` recovers files from a disk image or an attached device, by
parsing filesystem metadata and by carving raw sectors. It is read-only against
its source, like Core and unlike Sanitize. It is also reachable as screen `8` in
`arachnid-tui`.

---

## Contents

- [Where Recover sits](#where-recover-sits)
- [Read-only, structurally](#read-only-structurally)
- [Two passes, two kinds of claim](#two-passes-two-kinds-of-claim)
- [Supported filesystems](#supported-filesystems)
- [Carved file types](#carved-file-types)
- [Confidence scoring](#confidence-scoring)
- [CLI reference](#cli-reference)
- [Export and chain of custody](#export-and-chain-of-custody)
- [The safety rails](#the-safety-rails)
- [The TUI Recover screen](#the-tui-recover-screen)
- [Exit codes](#exit-codes)
- [Results schema](#results-schema)
- [Not in scope](#not-in-scope)

---

## Where Recover sits

```
   Core                    Recover                  Sanitize
   acquire evidence   →    extract files from it  →  destroy the media
   (read-only)             (read-only)               (destroys data)
```

Recover reads what Core acquired — or a drive directly, before it goes to
Sanitize — and turns it back into files. Its own output is a container in Core's
format, so a recovery export verifies with `arachnid-core verify`, unchanged.

There is one implementation of hashing, signing and verification in this suite,
and Recover uses it rather than carrying a second.

---

## Read-only, structurally

Every parser and the carver read through one trait:

```rust
pub trait Source: Send {
    fn size(&self) -> u64;
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize>;
    fn label(&self) -> String;
}
```

There is no `write_at`. Not one that returns an error, not one behind a flag —
the method does not exist, so no code path in the crate can write to the media
under examination, and adding one means editing
`crates/arachnid-recover-core/src/source.rs`. Device handles are opened
`.read(true)` and never `.write(true)`, so the kernel refuses a write even if
one were somehow issued.

This is the exact inverse of `arachnid_sanitize_core::target::WipeTarget`, whose
entire purpose is to write. The two traits must never converge.

---

## Two passes, two kinds of claim

**Filesystem-aware recovery** parses the volume's own metadata. A file recovered
this way comes back with its original name, path and timestamps, because the
filesystem is telling you what it was.

**Raw carving** scans sectors for file signatures. It works where no filesystem
is left to parse — a reformatted volume, a partition table that no longer reads,
an APFS container — and it recovers content *without identity*: no name, no
path, no timestamp, because none of those live in a file's own bytes.

| | Filesystem pass | Carving pass |
|---|---|---|
| Reads | NTFS MFT, ext4 inodes and journal | raw sectors |
| Recovers | content, name, path, timestamps | content only |
| Needs a filesystem | yes | no |
| Confidence ceiling | `High` | `Low` |

Both are real recovery. They are not the same claim, and nothing in this module
presents them as one.

---

## Supported filesystems

### NTFS

An NTFS delete does not erase the file record. It clears the in-use bit in the
record header and frees the clusters in `$Bitmap`; the record itself — name,
parent, timestamps, and the run list pointing at the data — stays where it was
until something reuses the slot.

Parsed:

- boot sector geometry, including the negative encodings for sectors-per-cluster
  and MFT record size
- the MFT, read through `$MFT`'s own run list rather than walked forward blindly
- the update sequence array on every record. A record whose sector-tail numbers
  do not match is a **torn write** and is skipped, not repaired over: half a
  record from before a crash and half from after is not a file
- `$STANDARD_INFORMATION` timestamps and `$FILE_NAME`, preferring the Win32 name
  over the 8.3 alias
- `$DATA` run lists, resident and non-resident, including sparse runs
- path reconstruction from parent references — **including through deleted
  directory records**, which is what lets a deleted file keep its full path

Not parsed:

- NTFS-compressed `$DATA`. The clusters are located, the file is capped at
  `Medium`, and the reason is stated on the result. It is not exported as though
  the raw clusters were its contents.
- EFS-encrypted `$DATA`. Reported as encrypted; see [Not in scope](#not-in-scope).
- Alternate data streams. Skipped rather than exported under the file's own name.
- The first 16 records (`$MFT`, `$LogFile`, `$Bitmap`, …). They are NTFS's own
  metadata, not user data, and recovering them would bury the results.

### ext4

ext4 unlinks a file by clearing its directory entry, setting `i_dtime`, dropping
`i_links_count` to zero and freeing its blocks. Unlike ext3, it does **not** zero
the extent tree in the inode, so the inode usually still says exactly which
blocks held the file.

Parsed:

- superblock, group descriptors (32- and 64-byte), inode tables
- extent trees, following index nodes to their leaves, with uninitialized
  (preallocated) extents reported rather than exported as data
- directory entries **and the deleted entries in their slack**. An unlink extends
  the preceding entry's `rec_len` over the old record rather than erasing it, so
  the old name is still there. Candidates containing control characters or `/`
  are rejected — slack is mostly stale bytes, and a "name" of control characters
  would invent a filename
- the **jbd2 journal**, walked for descriptor blocks whose tags name an
  inode-table block. An older copy of an inode found there recovers a file the
  live table has already forgotten — at `Medium` at best, because a journalled
  inode is by definition a superseded snapshot

Not parsed, and each named individually in the results rather than skipped
silently: ext2/ext3 indirect block maps, inline data, inline directories.

### APFS

Identified, not recovered. The container superblock is parsed for block
geometry, and volume superblocks are located to report each volume's name, file
and directory counts, last-modified time and encryption state.

Per-file recovery is **not implemented in this version**. Recovering a file from
APFS means resolving virtual object IDs through the container object map,
walking the volume's file-system B-tree for inode and directory records, then
following extent records through the extent-reference tree — with snapshots and
clones changing what "the file" even refers to.

The scan says so explicitly:

```
Filesystems
  apfs at offset 0 — 0 entries
    unsupported: APFS per-file recovery is not implemented in this build …
                 Run the raw carving pass against this container to recover
                 file content.
    note: APFS container: 244190646 block(s) of 4096 bytes, 1 volume(s) found
    note: volume 0 "Macintosh HD": 412883 file(s), 98214 director(y/ies) …
```

An empty result set with an explicit "not implemented" is worth more than one
that reads as "there was nothing there". Carving works on an APFS container and
is the supported route today.

---

## Carved file types

`jpg` · `png` · `pdf` · `zip` · `mp4` · `txt`

A carved ZIP is reported as `docx`, `xlsx` or `pptx` when its member layout says
so, so an analyst does not have to open every archive to find the documents.

**Where the file ends.** Where the format has its own terminator, the end is
found structurally rather than guessed:

| Type | How the end is found |
|---|---|
| `jpg` | the `FFD9` end-of-image marker |
| `png` | `IEND` plus its fixed CRC — the last eight bytes of every valid PNG |
| `pdf` | `%%EOF` |
| `zip` | the end-of-central-directory record, plus its declared comment length |
| `mp4` | walking the box chain and summing the declared box lengths. A box whose type is not four printable characters ends the walk |
| `txt` | nothing. Plain text has no terminator, so the length is where printable bytes stopped — which is stated on the result, not implied away |

`txt` is off by default. On a real volume it matches every log fragment and
string table on the disk and buries everything else.

**Nested signatures.** A JPEG's EXIF thumbnail is itself a JPEG. Ranges already
claimed by a carved file are skipped, so one photo produces one result rather
than two.

**Fragmentation.** Files are carved as contiguous runs. A file whose terminator
is not found within the type's size cap is reported with `footer_found: false`
and flagged likely-incomplete. This build does **not** reassemble a fragmented
file from non-adjacent runs: bi-fragment gap carving and its relatives guess, and
in evidence a plausible-looking wrong reconstruction is worse than an honest
partial one.

---

## Confidence scoring

Every result carries a label **and** the checks behind it, because `High` and
`Low` look identical once they are files in a folder.

| Label | Means | Reached when |
|---|---|---|
| `High` | filesystem metadata intact, every allocated byte read back | a **live** entry, a complete run list or extent tree, every extent readable, nothing compressed or encrypted |
| `Medium` | filesystem metadata found, something about the data is in doubt | deleted; or the allocation is short of the declared size; or an extent will not read; or the data is compressed or encrypted; or the inode came from the journal |
| `Low` | raw-carved: structurally valid, completeness unverified | every carved result, without exception |

### The rule that does the most work

**A deleted file never scores `High`.** Its clusters or blocks are free, so a
clean read proves the bytes are readable — not that they are still *that file's*
bytes. That distinction is the difference between evidence and a coincidence,
and no amount of clean reading closes it.

### The rationale is stored, not just the label

Each result lists every check that ran, whether it passed, and what was actually
observed:

```
ntfs-000019  <unknown>/orphan.txt
  method      NTFS MFT
  type        txt
  size        45 bytes
  deleted     true
  modified    2026-03-01T12:00:00Z
  extents     1
    offset 98304            45 bytes

  confidence  Medium
  MFT record intact and every extent reads back, but the record is deleted: the clusters are free and may since have been reallocated to another file

  checks
    [  ] mft_entry_in_use           record is marked deleted; its clusters are free and may have been reallocated
    [ok] run_list_complete          1 run(s) decoded to the declared end of the file
    [ok] allocation_covers_size     45 byte(s) mapped for a 45 byte file
    [ok] extents_readable           1 extent(s) sampled and readable
```

Three of four checks passed. The one that did not is the one that matters.

Note the path: this file kept its own name but not its directory, because the
parent directory's MFT record has been reused. It reports `<unknown>` rather
than inventing a plausible path.

Checks currently emitted: `mft_entry_in_use` · `run_list_complete` ·
`allocation_covers_size` · `no_sparse_holes` · `extents_within_source` ·
`extents_readable` · `data_resident` · `data_uncompressed` · `data_unencrypted` ·
`sparse_flag` · `inode_linked` · `extents_cover_size` · `extent_tree_intact` ·
`name_from_live_directory` · `inode_is_current` · `signature_matched` ·
`footer_found` · `within_size_cap` · `original_metadata` ·
`contiguity_verified` · `printable_run`.

---

## CLI reference

The examples below run against the synthetic images checked into
`test-fixtures/`, so they reproduce exactly from a clean checkout.

### `scan`

Filesystem-aware recovery, optionally plus carving.

```bash
arachnid-recover scan \
  --input test-fixtures/ntfs-deleted.img \
  --carve-pass --carve-types jpg,png,pdf,zip \
  --output ./rec \
  --include-live
```

```
Scanning test-fixtures/ntfs-deleted.img (131072 bytes)…
Arachnid Recover — scan summary
===============================

Source      test-fixtures/ntfs-deleted.img
Size        131072 bytes
Operator    analyst-7@linux
Started     2026-08-29T09:16:35.32200519Z
Finished    2026-08-29T09:16:35.331266775Z
Passes      filesystem + raw carving

Filesystems
  ntfs at offset 0 — 3 entries

Results     5 file(s)
  High    1
  Medium  2
  Low     2

High   filesystem metadata intact, every allocated byte read back
Medium filesystem metadata found, data partly overwritten or truncated
Low    raw-carved: structurally valid, completeness unverified

Results index: ./rec/results.json
Summary:       ./rec/summary.txt

Nothing has been written to the source. To write the recovered files out:
  arachnid-recover export -i ./rec/results.json -o <DIR> --confidence high,medium
```

| Flag | Does |
|---|---|
| `-i`, `--input` | image file, or a device path (`/dev/sdb`, `\\.\PhysicalDrive2`) |
| `-o`, `--output` | where `results.json` and `summary.txt` go |
| `--filesystem-pass` | on by default; accepted so a scripted run can state its intent |
| `--no-filesystem-pass` | skip it. `carve` is the shorter way to say the same thing |
| `--carve-pass` | **adds** carving to the filesystem pass; does not replace it |
| `--carve-types` | comma-separated. Default: every type except `txt` |
| `--include-live` | also report files the filesystem still considers live. Off by default: live files are readable through the OS, and including them buries the deleted ones |
| `--operator` | identity recorded in the results |

### `carve`

Signature carving alone, for media with no filesystem left to parse.

```bash
arachnid-recover carve -i /dev/sdb --carve-types jpg,pdf,docx -o ./rec-carved
```

### `list-results`

```bash
arachnid-recover list-results --input ./rec/results.json
```

```
ID             CONF     TYPE           SIZE  METHOD       NAME / PATH
ntfs-000017    High     pdf              37  NTFS MFT     Cases/quarterly.pdf
ntfs-000018    Medium   jpg             206  NTFS MFT     Cases/evidence-photo.jpg
ntfs-000019    Medium   txt              45  NTFS MFT     <unknown>/orphan.txt
carve-000000   Low      jpg             206  carved       carve-000000-at-90112.jpg
carve-000001   Low      pdf              36  carved       carve-000001-at-81920.pdf

5 of 5 result(s). Use --detail <ID> for the scoring rationale.
```

`ntfs-000018` and `carve-000000` are **the same 206 bytes on disk**, found twice.
The filesystem pass knows it was `Cases/evidence-photo.jpg`; the carver knows
only that a JPEG starts at offset 90112. That is the whole point of the two
passes, visible in one table.

| Flag | Does |
|---|---|
| `--confidence` | keep only these levels: `high`, `medium`, `low` |
| `--type` | keep only these file types |
| `--detail <ID>` | print the full scoring rationale for one result |

### `export`

```bash
arachnid-recover export -i ./rec/results.json -o ./rec/exported --confidence high,medium
```

```
Exported 3 file(s) to ./rec/exported
Chain of custody: ./rec/exported/custody.log
Signing key SHA-256: 9d54b3f24faaba5ac128560f12e42627d61b9be66dd7df31ec1f6d06fd48b672

Record that fingerprint out of band. Re-check the export at any time with:
  arachnid-core verify ./rec/exported
```

| Flag | Does |
|---|---|
| `--confidence` / `--type` | which results to write |
| `--id` | export these result ids only; overrides the filters |
| `--source` | read from this image instead of the one recorded in the results, for when the image has moved |
| `--operator` | defaults to the operator recorded in the results |

---

## Export and chain of custody

An export is not a folder of loose files. Every exported file is hashed as it is
written and its digest goes into the same signed, hash-chained custody log a
triage collection uses:

```
./rec/exported/
  manifest.json
  custody.log
  artifacts/
    results.json                        the index this export was selected from
    export-summary.txt
    recovered/Cases/quarterly.pdf       filesystem-recovered: original structure
    recovered/Cases/evidence-photo.jpg
    recovered/_unknown_/orphan.txt      path was unrecoverable, and it says so
    carved/carve-000000-at-90112.jpg    carved: flat, named after where it was found
```

Filesystem-recovered files keep their directory structure under `recovered/`.
Carved files go flat into `carved/`, because they have no structure to keep and
mixing them would imply one.

The results index goes in **first**, so the custody log records what the export
was selected *from* before it records what came out.

```bash
arachnid-core verify ./rec/exported
```

```
VERIFIED: every artifact matches the signed custody log.
This confirms the container is internally consistent. It is only proof of
origin if the key fingerprint above matches the one recorded at collection.
```

### Paths are hostile input

An original path comes out of the filesystem under examination, which on a
compromised host is attacker-controlled. A path of
`../../../../etc/cron.d/backdoor` must land inside the output directory or
nowhere. Every component is reduced before it becomes a path:

- `..`, `.`, empty components and absolute roots are dropped — not popped, which
  would let a crafted path climb out one component at a time
- Windows drive prefixes (`C:`) are dropped
- a NUL byte refuses the whole path outright
- reserved characters become `_`; control bytes are removed; Windows reserved
  device names (`CON`, `NUL`, `LPT1`, …) are prefixed; components are capped at
  200 characters
- a path that reduces to nothing is reported as skipped, never written

### Short files are kept

When the media will not return a file's whole allocation, what was read is still
written and the shortfall is recorded in `export-summary.txt`. A partial document
is evidence; deleting it for being incomplete would destroy what the recovery
found.

---

## The safety rails

**1. Never writes to the source.** Structural — see
[Read-only, structurally](#read-only-structurally).

**2. Recovery output must not land on the device being recovered from.** This is
the mistake that quietly destroys a case: every byte written there lands in the
unallocated space the recovery is reading out of. On Linux this is proven from
`/proc/mounts` and refused:

```
REFUSED: the output directory /mnt/case/out is on /dev/sdb1, mounted at
/mnt/case, which is part of the device being recovered from. Writing there
would overwrite the unallocated space this recovery reads out of. Choose an
output directory on different media.
```

On other platforms it cannot be proven cheaply, so the risk is stated loudly
instead. Refusing on a guess would block legitimate work; staying silent would
let a real one through.

**3. An image that does not match the scan is refused at export.** If the source
is a different size than the results recorded, every offset in the index would
point at the wrong bytes.

**4. Encrypted files are reported, not attacked.** See
[Not in scope](#not-in-scope).

---

## The TUI Recover screen

Screen `8` in `arachnid-tui`. Five steps, in order:

1. **Source** — an image path, a device from the read-only device list (the same
   enumeration Sanitize uses, opened without write access), or an artifact out
   of a prior Core evidence container.
2. **Configuration** — which passes, which carve types, whether to include live
   files, and where the results index goes.
3. **Progress** — phase, filesystems found, files found, and a carving progress
   bar. Runs on its own thread and **survives navigating away**: carving a full
   disk is an hours-long read.
4. **Results** — a filterable table. `c` cycles the confidence filter, `t`
   cycles the file types actually present.
5. **Export** — an output directory and a confidence threshold, defaulting to
   `Medium` and better.

| Key | Does |
|---|---|
| `j` / `k` | move |
| `Enter` | select, or edit a field |
| `Space` | toggle a pass or a carve type |
| `r` | reload the device list, or re-read a container's artifact list |
| `s` | start the scan |
| `c` / `t` | filter results by confidence / type |
| `e` | export |
| `x` | cancel a running scan |

The results browser shows the confidence label on every row **and** the checks
behind the selected row in a pane beside it — not behind a drill-down. A
recovered file looks identical in a folder whether the filesystem handed over
its name or a carver found its bytes, so the screen never shows the file without
the claim.

The container source reads artifact names out of the custody log with
`read_log`, which deliberately does **not** verify signatures. It is a file
picker; presenting it as though the log had been checked would be a lie.
Verification is screen `5`'s job, on the same path.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success |
| `1` | runtime error |
| `2` | usage error |
| `3` | refused by a safety rail |
| `4` | completed, but something was skipped or unsupported |

`4` is not a failure. The scan finished and left something out — an unsupported
filesystem feature, an extent that would not read, a cancelled pass — and the
results index names each one:

```bash
arachnid-recover scan -i "$IMAGE" -o "$REC" --carve-pass
case $? in
  0) echo "scan complete" ;;
  3) echo "REFUSED — check the output directory is not on the source"; exit 3 ;;
  4) jq -r '.filesystems[].unsupported[]?, .problems[]?' "$REC/results.json" ;;
  *) echo "scan failed"; exit 1 ;;
esac
```

---

## Results schema

`results.json` carries its own `schema_version`, moving independently of the
container format. A worked sample — regenerated from the checked-in fixtures
rather than hand-written, so it cannot drift from real output — lives at
`schema/samples/recovery-results.json` and
`schema/samples/recovery-summary.txt`.

Top level: `schema_version` · `tool` · `tool_version` · `source` ·
`source_size` · `started_utc` · `finished_utc` · `operator` ·
`filesystem_pass` · `carve_pass` · `carve_types` · `filesystems` · `files` ·
`problems`.

Each entry in `files`: `id` · `method` · `original_path` (absent for carved
results — it does not exist, and none is invented) · `export_name` ·
`file_type` · `size` · `extents` · `created_utc` / `modified_utc` /
`accessed_utc` · `deleted` · `encrypted` · `rationale`.

Each entry in `filesystems`: `kind` · `offset` · `entries` · `unsupported` ·
`notes`.

Regenerate the sample after changing a parser or the schema:

```bash
cargo test -p arachnid-recover-core --test fixture -- --ignored
```

---

## Not in scope

- **No decryption, key recovery, password guessing or brute force.**
  EFS-encrypted `$DATA`, ext4 per-file encryption and FileVault volumes are
  identified and reported as encrypted, and recovery stops there. Nothing in
  this module attempts to get at the plaintext, and nothing will be added that
  does.
- **No write-back to source media, under any circumstance.**
- **No network or remote recovery.** Local operator, local image or device — the
  same threat model as the rest of the suite.
- **No proprietary or undocumented filesystems.** NTFS, ext4, and best-effort
  APFS identification. A filesystem this build does not parse is reported as
  unidentified, not partially supported.
- **No partition table parsing.** Filesystems are probed at three fixed offsets:
  0, 1 MiB, and 63 sectors. Those cover a bare partition image and both
  mainstream alignment conventions. An image whose volumes start elsewhere needs
  the partition imaged directly, or the carving pass, which needs no filesystem.

---

[← Secure Erasure](14-Secure-Erasure.md) · [Home](Home.md)
