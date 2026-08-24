//! Regenerates the checked-in fixtures: the synthetic filesystem images in
//! `test-fixtures/`, and the sample results export in `schema/samples/`.
//!
//! Ignored by default: it writes into the repository, which a normal `cargo
//! test` run must not do. Run it deliberately after changing an on-disk parser
//! or the results schema:
//!
//! ```text
//! cargo test -p arachnid-recover-core --test fixture -- --ignored
//! ```
//!
//! The fixtures are generated rather than hand-written so they cannot drift from
//! what the code actually reads and emits. A sample that no longer matches real
//! output is worse than none, because it is what a reviewer reads instead of
//! running the tool.
//!
//! Nothing here is derived from real media. See `common/mod.rs`.

mod common;

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;

use arachnid_recover_core::source::MemorySource;
use arachnid_recover_core::{carve, scan, Progress, ScanOptions};

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is <repo>/crates/arachnid-recover-core.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("repository root")
        .to_path_buf()
}

#[test]
#[ignore = "writes into the repository; run explicitly with --ignored"]
fn regenerate_fixtures() {
    let root = repo_root();
    let fixtures = root.join("test-fixtures");
    std::fs::create_dir_all(&fixtures).expect("create test-fixtures");

    let ntfs = common::ntfs::image();
    let ext4 = common::ext4::image();
    std::fs::write(fixtures.join("ntfs-deleted.img"), &ntfs).expect("write NTFS fixture");
    std::fs::write(fixtures.join("ext4-deleted.img"), &ext4).expect("write ext4 fixture");
    std::fs::write(fixtures.join("README.md"), FIXTURE_README).expect("write fixture README");

    // The sample results export: a scan of the NTFS fixture with both passes, so
    // the sample shows every confidence label and both recovery methods.
    let mut source = MemorySource::new(ntfs, "test-fixtures/ntfs-deleted.img");
    let options = ScanOptions {
        filesystem_pass: true,
        carve_pass: true,
        carve_types: carve::default_types(),
        deleted_only: false,
        operator: "sample-operator@lab".into(),
    };
    let mut results = scan(
        &mut source,
        &options,
        &Progress::default(),
        &AtomicBool::new(false),
    )
    .expect("scan the fixture");

    // Timestamps are the only part of the output that changes per run. Pinning
    // them keeps the checked-in sample's diff to what actually changed.
    results.started_utc = "2026-03-01T12:00:00Z".into();
    results.finished_utc = "2026-03-01T12:00:04Z".into();
    results.tool_version = env!("CARGO_PKG_VERSION").into();

    let samples = root.join("schema").join("samples");
    std::fs::create_dir_all(&samples).expect("create schema/samples");
    std::fs::write(
        samples.join("recovery-results.json"),
        serde_json::to_vec_pretty(&results).expect("serialize results"),
    )
    .expect("write the sample results");
    std::fs::write(samples.join("recovery-summary.txt"), results.summary())
        .expect("write the sample summary");

    let (high, medium, low) = results.counts();
    println!(
        "regenerated: {} result(s) — {high} High, {medium} Medium, {low} Low",
        results.files.len()
    );
    assert!(high > 0 && medium > 0 && low > 0, "the sample must show every label");
}

const FIXTURE_README: &str = "\
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
";
