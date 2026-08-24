//! End-to-end tests against the synthetic images in `common`.
//!
//! These run the real parsers over real on-disk structures — boot sector to run
//! list to exported bytes — rather than over hand-fed slices. A test that passes
//! here means the parser can read a filesystem, not just a struct.

mod common;

use std::sync::atomic::AtomicBool;

use arachnid_recover_core::results::{Confidence, Method};
use arachnid_recover_core::source::MemorySource;
use arachnid_recover_core::{export, scan, Progress, ScanOptions};

fn ntfs_scan(deleted_only: bool) -> arachnid_recover_core::ScanResults {
    let mut source = MemorySource::new(common::ntfs::image(), "ntfs-fixture.img");
    let options = ScanOptions {
        filesystem_pass: true,
        carve_pass: false,
        deleted_only,
        operator: "tester@ci".into(),
        ..Default::default()
    };
    scan(&mut source, &options, &Progress::default(), &AtomicBool::new(false)).unwrap()
}

fn ext4_scan(deleted_only: bool) -> arachnid_recover_core::ScanResults {
    let mut source = MemorySource::new(common::ext4::image(), "ext4-fixture.img");
    let options = ScanOptions {
        filesystem_pass: true,
        carve_pass: false,
        deleted_only,
        operator: "tester@ci".into(),
        ..Default::default()
    };
    scan(&mut source, &options, &Progress::default(), &AtomicBool::new(false)).unwrap()
}

// ---------------------------------------------------------------------------
// NTFS
// ---------------------------------------------------------------------------

#[test]
fn ntfs_is_identified_and_the_deleted_file_recovered_with_its_path() {
    let r = ntfs_scan(true);
    assert_eq!(r.filesystems.len(), 1, "{:?}", r.problems);
    assert_eq!(r.filesystems[0].kind, "ntfs");

    let deleted = r
        .files
        .iter()
        .find(|f| f.export_name == "evidence-photo.jpg")
        .expect("the deleted file");
    assert_eq!(deleted.method, Method::NtfsMft);
    assert!(deleted.deleted);
    // The whole point of the metadata path: the original path comes back.
    assert_eq!(deleted.original_path.as_deref(), Some("Cases/evidence-photo.jpg"));
    assert_eq!(deleted.file_type, "jpg");
    assert_eq!(deleted.modified_utc.as_deref(), Some("2026-03-01T12:00:00Z"));
    assert_eq!(deleted.extents.len(), 1);
    assert_eq!(
        deleted.extents[0].offset,
        (common::ntfs::LCN_DELETED * common::ntfs::CLUSTER) as u64
    );
}

/// A deleted file's clusters are free. Whatever reads back from them, the
/// recovery cannot prove they are still that file's bytes — so it must not
/// claim High.
#[test]
fn a_deleted_ntfs_file_never_scores_high() {
    let r = ntfs_scan(true);
    for f in &r.files {
        assert!(f.deleted);
        assert_eq!(
            f.confidence(),
            Confidence::Medium,
            "{} scored {}",
            f.id,
            f.confidence().label()
        );
        assert!(
            f.rationale
                .checks
                .iter()
                .any(|c| c.check == "mft_entry_in_use" && !c.passed),
            "{} does not say why it is not High",
            f.id
        );
    }
}

/// A live file with a complete run list that reads back cleanly is the only
/// thing that earns High. Without this, the label is unreachable and means
/// nothing.
#[test]
fn a_live_intact_ntfs_file_scores_high() {
    let r = ntfs_scan(false);
    let live = r
        .files
        .iter()
        .find(|f| f.export_name == "quarterly.pdf")
        .expect("the live file");
    assert!(!live.deleted);
    assert_eq!(live.confidence(), Confidence::High);
    assert_eq!(live.original_path.as_deref(), Some("Cases/quarterly.pdf"));
    assert!(live.rationale.summary.contains("read back cleanly"));
}

/// When the parent directory's record is gone the path cannot be rebuilt.
/// Reporting `<unknown>` is the honest answer; inventing a path is not.
#[test]
fn an_unrebuildable_path_says_so_rather_than_inventing_one() {
    let r = ntfs_scan(true);
    let orphan = r
        .files
        .iter()
        .find(|f| f.export_name == "orphan.txt")
        .expect("the orphaned file");
    assert_eq!(orphan.original_path.as_deref(), Some("<unknown>/orphan.txt"));
}

/// NTFS's own metadata files are not user data; recovering them as files would
/// bury the results an analyst is looking for.
#[test]
fn ntfs_metadata_files_are_not_reported_as_recovered_files() {
    let r = ntfs_scan(false);
    assert!(
        !r.files.iter().any(|f| f.export_name.starts_with('$')),
        "a $-prefixed metadata file was reported: {:?}",
        r.files.iter().map(|f| &f.export_name).collect::<Vec<_>>()
    );
}

// ---------------------------------------------------------------------------
// ext4
// ---------------------------------------------------------------------------

#[test]
fn ext4_is_identified_and_the_deleted_file_keeps_its_name_from_slack() {
    let r = ext4_scan(true);
    assert_eq!(r.filesystems.len(), 1, "{:?}", r.problems);
    assert_eq!(r.filesystems[0].kind, "ext4");

    let deleted = r
        .files
        .iter()
        .find(|f| f.export_name == "evidence-photo.jpg")
        .expect("the deleted file");
    assert_eq!(deleted.method, Method::Ext4Inode);
    assert!(deleted.deleted);
    assert_eq!(deleted.confidence(), Confidence::Medium);
    assert_eq!(deleted.extents.len(), 1);
    assert_eq!(
        deleted.extents[0].offset,
        (common::ext4::DELETED_DATA_BLOCK * common::ext4::BLOCK) as u64
    );
    // The name came out of a deleted directory entry, and the rationale must
    // say so — it is weaker evidence than a live entry.
    assert!(
        deleted
            .rationale
            .checks
            .iter()
            .any(|c| c.check == "name_from_live_directory" && !c.passed),
        "the slack-recovered name is not flagged"
    );
}

#[test]
fn a_live_intact_ext4_file_scores_high() {
    let r = ext4_scan(false);
    let live = r
        .files
        .iter()
        .find(|f| f.export_name == "live.txt")
        .expect("the live file");
    assert_eq!(live.confidence(), Confidence::High);
    assert_eq!(live.original_path.as_deref(), Some("live.txt"));
    assert_eq!(live.modified_utc.as_deref(), Some("2026-03-01T12:00:00Z"));
}

/// The fixture has no journal, which is a real condition on a damaged image.
/// It must become a note, not a failed scan.
#[test]
fn a_missing_journal_is_a_note_not_a_failure() {
    let r = ext4_scan(true);
    assert!(
        r.filesystems[0]
            .notes
            .iter()
            .any(|n| n.contains("journal pass did not run")),
        "{:?}",
        r.filesystems[0].notes
    );
    // And the inode-table results still came back.
    assert!(!r.files.is_empty());
}

// ---------------------------------------------------------------------------
// Confidence coverage
// ---------------------------------------------------------------------------

/// Every label must be reachable, and every one must be justified by a check
/// that actually ran. A label nothing can produce is a label that means nothing.
#[test]
fn every_confidence_label_is_reachable_and_justified() {
    let mut seen = std::collections::BTreeSet::new();

    for r in [ntfs_scan(false), ext4_scan(false)] {
        for f in &r.files {
            seen.insert(f.confidence());
            assert!(
                !f.rationale.checks.is_empty(),
                "{} carries a label with no checks behind it",
                f.id
            );
            assert!(
                !f.rationale.summary.is_empty(),
                "{} has no summary",
                f.id
            );
            // High means nothing failed; anything less must name a failure.
            match f.confidence() {
                Confidence::High => assert!(
                    f.rationale.checks.iter().all(|c| c.passed),
                    "{} is High with a failing check",
                    f.id
                ),
                _ => assert!(
                    f.rationale.checks.iter().any(|c| !c.passed),
                    "{} is {} but every check passed",
                    f.id,
                    f.confidence().label()
                ),
            }
        }
    }

    // Low comes from the carving pass.
    let mut source = MemorySource::new(common::ntfs::image(), "ntfs-fixture.img");
    let carved = scan(
        &mut source,
        &ScanOptions {
            filesystem_pass: false,
            carve_pass: true,
            carve_types: vec!["jpg".into(), "pdf".into()],
            ..Default::default()
        },
        &Progress::default(),
        &AtomicBool::new(false),
    )
    .unwrap();
    assert!(!carved.files.is_empty(), "the carver found nothing to score");
    for f in &carved.files {
        seen.insert(f.confidence());
    }

    assert_eq!(
        seen,
        [Confidence::Low, Confidence::Medium, Confidence::High]
            .into_iter()
            .collect(),
        "not every confidence label is reachable"
    );
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/// The bytes that come out have to be the bytes that were on the media, and the
/// container they land in has to verify.
#[test]
fn exported_files_are_the_real_bytes_and_the_container_verifies() {
    let image = common::ntfs::image();
    let results = ntfs_scan(false);
    let mut source = MemorySource::new(image.clone(), "ntfs-fixture.img");

    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("export");
    let selected: Vec<_> = results.files.iter().collect();
    let report = export::export(&mut source, &results, &selected, &out, "tester@ci").unwrap();

    assert_eq!(report.exported.len(), selected.len());
    assert!(report.skipped.is_empty(), "{:?}", report.skipped);

    let live = report
        .exported
        .iter()
        .find(|e| e.path.ends_with("quarterly.pdf"))
        .expect("the live file was exported");
    let written = std::fs::read(out.join("artifacts").join(&live.path)).unwrap();
    let expected = &image[common::ntfs::LCN_LIVE * common::ntfs::CLUSTER
        ..common::ntfs::LCN_LIVE * common::ntfs::CLUSTER + written.len()];
    assert_eq!(written, expected, "exported bytes differ from the media");

    // And the export is evidence, not loose files: the same verifier the rest
    // of the suite uses must pass over it.
    let v = arachnid_evidence::verify(&out).unwrap();
    assert!(v.ok(), "custody problems: {:?}", v.problems);
}

/// Filesystem results keep their directory structure; carved results are flat
/// and must not be given one they never had.
#[test]
fn carved_and_recovered_files_land_in_separate_trees() {
    let results = ntfs_scan(false);
    let mut source = MemorySource::new(common::ntfs::image(), "ntfs-fixture.img");
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("export");
    let selected: Vec<_> = results.files.iter().collect();
    let report = export::export(&mut source, &results, &selected, &out, "tester@ci").unwrap();

    assert!(report
        .exported
        .iter()
        .all(|e| e.path.starts_with("recovered/")));
    assert!(out.join("artifacts/recovered/Cases/quarterly.pdf").is_file());
}

/// The carving pass finds the same photo through its bytes alone. The two
/// methods must produce different claims about the same file: one keeps the
/// name, the other cannot.
#[test]
fn carving_finds_the_same_file_without_its_identity() {
    let mut source = MemorySource::new(common::ntfs::image(), "ntfs-fixture.img");
    let r = scan(
        &mut source,
        &ScanOptions {
            filesystem_pass: false,
            carve_pass: true,
            carve_types: vec!["jpg".into()],
            ..Default::default()
        },
        &Progress::default(),
        &AtomicBool::new(false),
    )
    .unwrap();

    let jpg = r.files.iter().find(|f| f.file_type == "jpg").expect("a jpeg");
    assert_eq!(jpg.method, Method::SignatureCarve);
    assert_eq!(jpg.confidence(), Confidence::Low);
    assert!(jpg.original_path.is_none());
    assert!(jpg.created_utc.is_none());
    assert_eq!(
        jpg.extents[0].offset,
        (common::ntfs::LCN_DELETED * common::ntfs::CLUSTER) as u64,
        "the carver found the deleted photo's clusters"
    );
}
