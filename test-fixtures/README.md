# Recovery test fixtures

Small synthetic filesystem images for the `arachnid-recover-core` parser tests.

| File | What it is |
|---|---|
| `ntfs-deleted.img` | 1 MiB NTFS volume: one live file, one deleted file with an intact run list, one deleted file whose parent directory record is gone |
| `ext4-deleted.img` | 128 KiB ext4 volume: one live file, and a deleted file whose name survives only in directory slack |

**No real data.** Both images are built byte by byte by
`crates/arachnid-recover-core/tests/common/mod.rs`, so they contain nothing but
the structures under test. Never replace them with a capture of real media: even
a scratch disk carries filenames, timestamps and slack from the machine that
made it.

Regenerate after changing a parser or the on-disk layout the builders write:

```bash
cargo test -p arachnid-recover-core --test fixture -- --ignored
```

That also rewrites `schema/samples/recovery-results.json` and
`schema/samples/recovery-summary.txt`, which are the reference for what a scan
emits.
