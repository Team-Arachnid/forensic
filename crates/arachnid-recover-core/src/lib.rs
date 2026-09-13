//! Arachnid Recover — file carving and recovery.
//!
//! Part of the Arachnid Forensic suite, and the middle of its three modules:
//! **Core** acquires evidence, **Recover** extracts files from what was acquired
//! (or from a drive before it is sanitized), **Sanitize** destroys data once the
//! case is closed.
//!
//! Like Core and unlike Sanitize, this crate is read-only against its target,
//! and the read-only guarantee is structural rather than advisory: [`Source`]
//! has no write method, so there is no code path here that could write to the
//! media under examination even by mistake. See [`source`].
//!
//! # Two passes, two kinds of claim
//!
//! **Filesystem-aware recovery** parses the volume's own metadata — the NTFS
//! MFT, ext4 inode tables and journal — and recovers files with their original
//! names, paths and timestamps. This is the higher-confidence path, because the
//! filesystem is telling you what the file was.
//!
//! **Raw carving** scans sectors for file signatures and reconstructs by header
//! and footer. It works where no filesystem is left to parse, and it recovers
//! content without identity: a carved file has no name, no path and no
//! timestamp, and is never presented as though it had.
//!
//! Every result carries a [`Confidence`] label *and* the [`Rationale`] behind
//! it, because "High" and "Low" look identical once they are files in a folder.
//!
//! # Artifacts
//!
//! Both passes hand back files. What an investigation usually wants is one of
//! three answers — who was called, what was browsed, what the machine logged —
//! so results that are a call log, browser history or a system log are labelled
//! as such and can be selected with a single `--type` filter. See [`artifacts`].
//!
//! # Order of operations
//!
//! ```no_run
//! # use arachnid_recover_core::*;
//! # fn main() -> anyhow::Result<()> {
//! let mut source = source::ImageSource::open(std::path::Path::new("disk.img"))?;
//! let options = ScanOptions {
//!     filesystem_pass: true,
//!     carve_pass: true,
//!     carve_types: carve::default_types(),
//!     operator: "analyst@lab".into(),
//!     ..Default::default()
//! };
//! let results = scan(&mut source, &options, &Progress::default(), &Default::default())?;
//! println!("{}", results.summary());
//! # Ok(())
//! # }
//! ```

pub mod apfs;
pub mod artifacts;
pub mod carve;
pub mod deep;
pub mod export;
pub mod ext4;
pub mod ntfs;
pub mod results;
pub mod source;
pub mod vss;

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

pub use deep::{DeepOptions, DeepReport, Depth};
pub use results::{
    Check, Confidence, Content, Extent, FilesystemReport, Method, Rationale, RecoveredFile,
    ScanResults, SCHEMA_VERSION,
};
pub use source::Source;

/// Offsets probed for a filesystem when the source is a whole disk rather than a
/// bare partition.
///
/// A partition table would say exactly where the volumes are, and parsing MBR
/// and GPT is the correct answer if this list ever proves too narrow. It is not
/// yet: 2048 sectors is the alignment every mainstream partitioner has used
/// since 2009, 63 sectors is what everything before it used, and 0 covers an
/// image of a bare partition, which is what a Core acquisition produces.
// ponytail: fixed probe offsets, parse the GPT/MBR partition table if a real
// image ever turns up whose volumes start somewhere else.
const PROBE_OFFSETS: [u64; 3] = [0, 1024 * 1024, 63 * 512];

/// What a scan was asked to do.
#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub filesystem_pass: bool,
    pub carve_pass: bool,
    /// Types the carving pass looks for. Ignored when `carve_pass` is false.
    pub carve_types: Vec<String>,
    /// Restrict the filesystem pass to entries the filesystem has marked
    /// deleted. On by default: live files are readable through the OS, and a
    /// scan that returns every file on the volume buries the ones that matter.
    pub deleted_only: bool,
    /// How hard to look. `Deep` adds everything in [`deep`], costs hours rather
    /// than minutes, and is never the default.
    pub depth: Depth,
    /// Which deep techniques run. Ignored unless `depth` is `Deep`.
    pub deep: DeepOptions,
    pub operator: String,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            filesystem_pass: true,
            carve_pass: false,
            carve_types: carve::default_types(),
            deleted_only: true,
            depth: Depth::Standard,
            deep: DeepOptions::default(),
            operator: default_operator(),
        }
    }
}

/// Live progress for a running scan.
#[derive(Default)]
pub struct Progress {
    /// Which phase is running, for a front end to label: `0` idle, `1`
    /// filesystem, `2` carving, `3` done, `4` the deep techniques.
    pub phase: std::sync::atomic::AtomicU8,
    pub filesystems_found: std::sync::atomic::AtomicU64,
    pub files_found: std::sync::atomic::AtomicU64,
    pub carve: carve::Progress,
}

impl Progress {
    pub fn phase_label(&self) -> &'static str {
        match self.phase.load(Ordering::Relaxed) {
            1 => "parsing filesystem metadata",
            2 => "carving raw sectors",
            3 => "done",
            4 => "mining journals, snapshots and slack space",
            _ => "starting",
        }
    }
}

/// Run a scan.
///
/// Neither pass can fail the other: a filesystem that will not parse is recorded
/// as a problem and the carving pass still runs, because carving is exactly what
/// a broken filesystem calls for.
pub fn scan(
    source: &mut dyn Source,
    options: &ScanOptions,
    progress: &Progress,
    cancel: &AtomicBool,
) -> Result<ScanResults> {
    resume(source, options, progress, cancel, None)
}

/// Names of the two stages a scan can be resumed at the boundary of.
const STAGE_FILESYSTEM: &str = "filesystem";
const STAGE_CARVE: &str = "carve";

/// Run a scan, keeping what an earlier cancelled run of the same scan finished.
///
/// A deep scan of a large drive runs for hours, and an operator who has to stop
/// one should not lose the four hours of journal mining because the carving pass
/// had another two to go. Each of the two stages is either done or not; a stage
/// that was interrupted part way is re-run from the start rather than continued
/// from the middle, because a half-finished carve has no record of where it
/// stopped that could be trusted.
///
/// `previous` is ignored unless it fingerprints to the same media. Reusing one
/// image's results against another would put offsets from one drive into the
/// results of a second, which is the one failure mode this module cannot allow.
pub fn resume(
    source: &mut dyn Source,
    options: &ScanOptions,
    progress: &Progress,
    cancel: &AtomicBool,
    previous: Option<&ScanResults>,
) -> Result<ScanResults> {
    let started = arachnid_evidence::now_utc();
    let mut filesystems = Vec::new();
    let mut files = Vec::new();
    let mut problems = Vec::new();

    // Taken before any pass runs, so it identifies the media the offsets below
    // are relative to. A failure here is recorded rather than fatal: a scan of
    // damaged media is still worth having, and the export-time check reports an
    // absent fingerprint as "not verified" rather than as a match.
    let source_fingerprint = match source::fingerprint(source) {
        Ok(fp) => fp,
        Err(e) => {
            problems.push(format!(
                "could not fingerprint the source ({e:#}); an export from these results cannot \
                 confirm it is reading the same media"
            ));
            String::new()
        }
    };

    // A resume is only a resume of the same media. Anything else is a new scan
    // that happens to have been pointed at an old index.
    let previous = previous.filter(|p| {
        !p.source_fingerprint.is_empty() && p.source_fingerprint == source_fingerprint
    });
    let finished = |stage: &str| {
        previous.is_some_and(|p| {
            p.deep
                .as_ref()
                .is_some_and(|d| d.completed.iter().any(|c| c == stage))
        })
    };

    let deep_on = options.depth.is_deep();
    let mut report = DeepReport {
        techniques: options
            .deep
            .techniques()
            .iter()
            .map(|t| t.to_string())
            .collect(),
        completed: Vec::new(),
        advisories: if deep_on {
            deep::advisories(source, &options.deep)
        } else {
            Vec::new()
        },
        notes: Vec::new(),
    };

    // Slack space is the tail of a cluster a *live* file still holds, so the
    // filesystem pass has to see live files even when the operator only wants
    // deleted ones. They are dropped again below, once their slack has been
    // taken: asking for more thorough work should never quietly change what the
    // results contain.
    let want_slack = deep_on && options.deep.slack_space;
    let pass_deleted_only = options.deleted_only && !want_slack;

    if options.filesystem_pass {
        if finished(STAGE_FILESYSTEM) {
            let p = previous.expect("finished() is false without a previous scan");
            filesystems.extend(p.filesystems.iter().cloned());
            files.extend(p.files.iter().filter(|f| !f.method.is_carved()).cloned());
            report
                .notes
                .push(format!("resumed: the {STAGE_FILESYSTEM} stage was already complete"));
        } else {
            progress.phase.store(1, Ordering::Relaxed);
            for offset in PROBE_OFFSETS {
                if offset >= source.size() || cancel.load(Ordering::Relaxed) {
                    continue;
                }
                let deep = deep_on.then_some(&options.deep);
                match identify(source, offset, pass_deleted_only, deep, progress, cancel) {
                    Ok(Some(mut found)) => {
                        progress.filesystems_found.fetch_add(1, Ordering::Relaxed);
                        progress
                            .files_found
                            .fetch_add(found.files.len() as u64, Ordering::Relaxed);
                        report.notes.append(&mut found.deep_notes);
                        filesystems.push(found.report);
                        files.append(&mut found.files);
                    }
                    Ok(None) => {}
                    Err(e) => problems.push(format!("filesystem pass at offset {offset}: {e:#}")),
                }
            }
            if filesystems.is_empty() {
                problems.push(
                    "no NTFS, ext4 or APFS filesystem was found at any probed offset. If this is \
                     a whole-disk image with an unusual partition layout, image the partition \
                     itself, or run the carving pass, which needs no filesystem."
                        .into(),
                );
            }
            // Live files were only ever read so their slack could be taken.
            if want_slack && options.deleted_only {
                files.retain(|f| f.deleted || f.content != Content::Full);
            }
            // Recovering the same file twice — once per probe offset on a source
            // where two probes landed on the same volume — would double every
            // count an analyst reports.
            files.sort_by(|a, b| a.id.cmp(&b.id));
            files.dedup_by(|a, b| a.id == b.id);
            if !cancel.load(Ordering::Relaxed) {
                report.completed.push(STAGE_FILESYSTEM.into());
            }
        }
    }

    if options.carve_pass {
        if finished(STAGE_CARVE) {
            let p = previous.expect("finished() is false without a previous scan");
            files.extend(p.files.iter().filter(|f| f.method.is_carved()).cloned());
            report
                .notes
                .push(format!("resumed: the {STAGE_CARVE} stage was already complete"));
        } else if !cancel.load(Ordering::Relaxed) {
            progress.phase.store(2, Ordering::Relaxed);
            match carve::carve(source, &options.carve_types, &progress.carve, cancel) {
                Ok(carved) => {
                    progress
                        .files_found
                        .fetch_add(carved.len() as u64, Ordering::Relaxed);
                    // Carved ids are assigned by position within the carve pass,
                    // so they cannot collide with the filesystem pass's.
                    files.extend(carved);
                    if !cancel.load(Ordering::Relaxed) {
                        report.completed.push(STAGE_CARVE.into());
                    }
                }
                Err(e) => problems.push(format!("carving pass: {e:#}")),
            }
        }
    }

    // After both passes, so one rule covers every parser and the carver alike.
    // The carver has already labelled what it identified from content; this is
    // the path-based half, and it is the only half a filesystem result can use.
    for file in &mut files {
        artifacts::classify(file);
    }

    if cancel.load(Ordering::Relaxed) {
        problems.push(format!(
            "the scan was cancelled; results cover only the part of the source that was read.{}",
            if report.completed.is_empty() {
                String::new()
            } else {
                format!(
                    " Completed stage(s): {}. Re-running this scan with --resume against this \
                     results file will keep them and continue.",
                    report.completed.join(", ")
                )
            }
        ));
    }
    progress.phase.store(3, Ordering::Relaxed);

    Ok(ScanResults {
        schema_version: SCHEMA_VERSION.into(),
        tool: "arachnid-recover".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        source: source.label(),
        source_size: source.size(),
        source_fingerprint,
        started_utc: started,
        finished_utc: arachnid_evidence::now_utc(),
        operator: options.operator.clone(),
        filesystem_pass: options.filesystem_pass,
        carve_pass: options.carve_pass,
        depth: options.depth.label().into(),
        deep: deep_on.then_some(report),
        carve_types: if options.carve_pass {
            options.carve_types.clone()
        } else {
            Vec::new()
        },
        filesystems,
        files,
        problems,
    })
}

struct Identified {
    report: FilesystemReport,
    files: Vec<RecoveredFile>,
    /// What the deep techniques did on this volume, for the scan-level report.
    deep_notes: Vec<String>,
}

/// Identify whatever filesystem is at `offset` and recover from it.
///
/// `deep` is `Some` only in deep mode, and each technique it names runs against
/// the filesystem that owns it: the NTFS journals and shadow copies against
/// NTFS, the backup superblocks against ext, slack space against both.
fn identify(
    source: &mut dyn Source,
    offset: u64,
    deleted_only: bool,
    deep: Option<&DeepOptions>,
    progress: &Progress,
    cancel: &AtomicBool,
) -> Result<Option<Identified>> {
    if let Some(geometry) = ntfs::probe(source, offset)? {
        tracing::info!(offset, "NTFS volume identified");
        let scan = ntfs::recover(source, &geometry, deleted_only)?;
        let mut files = scan.files;
        let mut deep_notes = Vec::new();

        if let Some(d) = deep {
            progress.phase.store(4, Ordering::Relaxed);
            if d.journal_mining && !cancel.load(Ordering::Relaxed) {
                match ntfs::mine_journals(source, &geometry, cancel) {
                    Ok((mut found, notes)) => {
                        deep_notes.extend(notes);
                        files.append(&mut found);
                    }
                    Err(e) => deep_notes.push(format!("journal mining did not run: {e:#}")),
                }
            }
            if d.shadow_copies && !cancel.load(Ordering::Relaxed) {
                match vss::recover(source, offset) {
                    Ok((mut found, notes)) => {
                        deep_notes.extend(notes);
                        files.append(&mut found);
                    }
                    Err(e) => deep_notes.push(format!("shadow copies not enumerated: {e:#}")),
                }
            }
            if d.backup_metadata && !cancel.load(Ordering::Relaxed) {
                match ntfs::backup_metadata(source, &geometry) {
                    Ok((mut found, notes)) => {
                        deep_notes.extend(notes);
                        files.append(&mut found);
                    }
                    Err(e) => deep_notes.push(format!("backup metadata not read: {e:#}")),
                }
            }
            if d.slack_space && !cancel.load(Ordering::Relaxed) {
                let (mut found, note) =
                    deep::slack_space(source, &files, geometry.cluster_size(), cancel);
                deep_notes.push(note);
                files.append(&mut found);
            }
        }

        return Ok(Some(Identified {
            report: FilesystemReport {
                kind: "ntfs".into(),
                offset,
                entries: files.len() as u64,
                unsupported: scan.unsupported,
                notes: scan.notes,
            },
            files,
            deep_notes,
        }));
    }

    if let Some(sb) = ext4::probe(source, offset)? {
        tracing::info!(offset, "ext4 volume identified");
        let scan = ext4::recover(source, &sb, deleted_only, deep.is_some())?;
        let mut files = scan.files;
        let mut deep_notes = Vec::new();

        if let Some(d) = deep {
            progress.phase.store(4, Ordering::Relaxed);
            if d.backup_metadata && !cancel.load(Ordering::Relaxed) {
                let (mut found, notes) = ext4::backup_superblocks(source, &sb);
                deep_notes.extend(notes);
                files.append(&mut found);
            }
            if d.slack_space && !cancel.load(Ordering::Relaxed) {
                let (mut found, note) = deep::slack_space(source, &files, sb.block_size, cancel);
                deep_notes.push(note);
                files.append(&mut found);
            }
            if d.shadow_copies {
                deep_notes.push(
                    "shadow copies: not applicable to ext4 — Volume Shadow Copy is an NTFS \
                     feature, and LVM or Btrfs snapshots are outside this volume"
                        .into(),
                );
            }
        }

        return Ok(Some(Identified {
            report: FilesystemReport {
                kind: "ext4".into(),
                offset,
                entries: files.len() as u64,
                unsupported: scan.unsupported,
                notes: scan.notes,
            },
            files,
            deep_notes,
        }));
    }

    if let Some(container) = apfs::probe(source, offset)? {
        tracing::info!(offset, "APFS container identified");
        let (unsupported, notes) = apfs::report(&container);
        // Deliberately no files. See the module docs: an empty result set with
        // an explicit "not implemented" beats one that reads as "nothing here".
        return Ok(Some(Identified {
            report: FilesystemReport {
                kind: "apfs".into(),
                offset,
                entries: 0,
                unsupported,
                notes,
            },
            files: Vec::new(),
            deep_notes: match deep {
                Some(_) => vec![
                    "deep techniques: none ran on the APFS container — this build does not walk \
                     an APFS tree, so there is no file list to take slack from and no journal it \
                     can read"
                        .into(),
                ],
                None => Vec::new(),
            },
        }));
    }

    Ok(None)
}

/// Same rule the rest of the suite uses, so a container written by Recover
/// records the operator the way Core and Sanitize do.
pub fn default_operator() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());
    format!("{user}@{}", std::env::consts::OS)
}

/// Load a results index written by an earlier scan.
pub fn load_results(path: &std::path::Path) -> Result<ScanResults> {
    use anyhow::Context;
    let bytes =
        std::fs::read(path).with_context(|| format!("read results index {}", path.display()))?;
    let results: ScanResults = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse results index {}", path.display()))?;
    if results.schema_version != SCHEMA_VERSION {
        tracing::warn!(
            found = %results.schema_version,
            expected = SCHEMA_VERSION,
            "results index was written by a different schema version"
        );
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use source::MemorySource;

    /// A source with nothing on it must say so, and must not claim a filesystem.
    #[test]
    fn an_empty_source_reports_no_filesystem_rather_than_failing() {
        let mut s = MemorySource::new(vec![0u8; 4096], "empty");
        let r = scan(
            &mut s,
            &ScanOptions::default(),
            &Progress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert!(r.files.is_empty());
        assert!(r.filesystems.is_empty());
        assert!(r.problems[0].contains("no NTFS, ext4 or APFS"));
    }

    /// The carving pass must run on a source with no parseable filesystem: that
    /// is the case it exists for.
    #[test]
    fn carving_runs_even_when_no_filesystem_parses() {
        let mut img = vec![0u8; 2048];
        img.extend([0xFF, 0xD8, 0xFF, 0xE0]);
        img.extend(std::iter::repeat_n(0x41, 100));
        img.extend([0xFF, 0xD9]);
        let mut s = MemorySource::new(img, "junk");

        let options = ScanOptions {
            filesystem_pass: true,
            carve_pass: true,
            carve_types: vec!["jpg".into()],
            ..Default::default()
        };
        let r = scan(
            &mut s,
            &options,
            &Progress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].confidence(), Confidence::Low);
        assert_eq!(r.counts(), (0, 0, 1));
    }

    /// The point of the artifact label: on a volume with no filesystem left to
    /// parse, an analyst can still ask for the browser history by name.
    #[test]
    fn a_carved_history_database_is_selectable_by_artifact_class() {
        let mut img = vec![0u8; 512];
        img.extend(carve::test_sqlite_db(
            4,
            b"CREATE TABLE visits(id INTEGER, visit_duration INTEGER)",
        ));
        let mut s = MemorySource::new(img, "reformatted");

        let options = ScanOptions {
            filesystem_pass: false,
            carve_pass: true,
            carve_types: vec!["sqlite".into()],
            ..Default::default()
        };
        let r = scan(
            &mut s,
            &options,
            &Progress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();

        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].artifact.as_deref(), Some("browser-history"));
        assert_eq!(r.filter(&[], &["browser-history".into()]).count(), 1);
        // The container type still selects it too; one list covers both.
        assert_eq!(r.filter(&[], &["sqlite".into()]).count(), 1);
        assert_eq!(r.filter(&[], &["call-log".into()]).count(), 0);
        assert!(r.summary().contains("browser-history"));
    }

    #[test]
    fn results_round_trip_through_json() {
        let mut img = vec![0u8; 512];
        img.extend([0xFF, 0xD8, 0xFF, 0xE0]);
        img.extend(std::iter::repeat_n(0x41, 50));
        img.extend([0xFF, 0xD9]);
        let mut s = MemorySource::new(img, "junk");
        let options = ScanOptions {
            filesystem_pass: false,
            carve_pass: true,
            carve_types: vec!["jpg".into()],
            ..Default::default()
        };
        let r = scan(
            &mut s,
            &options,
            &Progress::default(),
            &AtomicBool::new(false),
        )
        .unwrap();

        let json = serde_json::to_vec_pretty(&r).unwrap();
        let back: ScanResults = serde_json::from_slice(&json).unwrap();
        assert_eq!(back.files.len(), r.files.len());
        assert_eq!(back.schema_version, SCHEMA_VERSION);
        assert_eq!(
            back.files[0].rationale.checks.len(),
            r.files[0].rationale.checks.len()
        );
    }

    #[test]
    fn cancellation_is_recorded_rather_than_silently_truncating() {
        let mut s = MemorySource::new(vec![0u8; 4096], "x");
        let cancel = AtomicBool::new(true);
        let r = scan(
            &mut s,
            &ScanOptions::default(),
            &Progress::default(),
            &cancel,
        )
        .unwrap();
        assert!(r.problems.iter().any(|p| p.contains("cancelled")));
    }
}
