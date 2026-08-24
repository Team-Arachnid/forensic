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
pub mod carve;
pub mod export;
pub mod ext4;
pub mod ntfs;
pub mod results;
pub mod source;

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;

pub use results::{
    Check, Confidence, Extent, FilesystemReport, Method, Rationale, RecoveredFile, ScanResults,
    SCHEMA_VERSION,
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
    pub operator: String,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            filesystem_pass: true,
            carve_pass: false,
            carve_types: carve::default_types(),
            deleted_only: true,
            operator: default_operator(),
        }
    }
}

/// Live progress for a running scan.
#[derive(Default)]
pub struct Progress {
    /// Which phase is running, for a front end to label: `0` idle, `1`
    /// filesystem, `2` carving, `3` done.
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
    let started = arachnid_evidence::now_utc();
    let mut filesystems = Vec::new();
    let mut files = Vec::new();
    let mut problems = Vec::new();

    if options.filesystem_pass {
        progress.phase.store(1, Ordering::Relaxed);
        for offset in PROBE_OFFSETS {
            if offset >= source.size() || cancel.load(Ordering::Relaxed) {
                continue;
            }
            match identify(source, offset, options.deleted_only) {
                Ok(Some((report, mut found))) => {
                    progress.filesystems_found.fetch_add(1, Ordering::Relaxed);
                    progress
                        .files_found
                        .fetch_add(found.len() as u64, Ordering::Relaxed);
                    filesystems.push(report);
                    files.append(&mut found);
                }
                Ok(None) => {}
                Err(e) => problems.push(format!("filesystem pass at offset {offset}: {e:#}")),
            }
        }
        if filesystems.is_empty() {
            problems.push(
                "no NTFS, ext4 or APFS filesystem was found at any probed offset. If this is a \
                 whole-disk image with an unusual partition layout, image the partition itself, \
                 or run the carving pass, which needs no filesystem."
                    .into(),
            );
        }
        // Recovering the same file twice — once per probe offset on a source
        // where two probes landed on the same volume — would double every count
        // an analyst reports.
        files.sort_by(|a, b| a.id.cmp(&b.id));
        files.dedup_by(|a, b| a.id == b.id);
    }

    if options.carve_pass && !cancel.load(Ordering::Relaxed) {
        progress.phase.store(2, Ordering::Relaxed);
        match carve::carve(source, &options.carve_types, &progress.carve, cancel) {
            Ok(carved) => {
                progress
                    .files_found
                    .fetch_add(carved.len() as u64, Ordering::Relaxed);
                // Carved ids are assigned by position within the carve pass, so
                // they cannot collide with the filesystem pass's.
                files.extend(carved);
            }
            Err(e) => problems.push(format!("carving pass: {e:#}")),
        }
    }

    if cancel.load(Ordering::Relaxed) {
        problems.push(
            "the scan was cancelled; results cover only the part of the source that was read"
                .into(),
        );
    }
    progress.phase.store(3, Ordering::Relaxed);

    Ok(ScanResults {
        schema_version: SCHEMA_VERSION.into(),
        tool: "arachnid-recover".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),
        source: source.label(),
        source_size: source.size(),
        started_utc: started,
        finished_utc: arachnid_evidence::now_utc(),
        operator: options.operator.clone(),
        filesystem_pass: options.filesystem_pass,
        carve_pass: options.carve_pass,
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

type Identified = (FilesystemReport, Vec<RecoveredFile>);

/// Identify whatever filesystem is at `offset` and recover from it.
fn identify(source: &mut dyn Source, offset: u64, deleted_only: bool) -> Result<Option<Identified>> {
    if let Some(geometry) = ntfs::probe(source, offset)? {
        tracing::info!(offset, "NTFS volume identified");
        let scan = ntfs::recover(source, &geometry, deleted_only)?;
        return Ok(Some((
            FilesystemReport {
                kind: "ntfs".into(),
                offset,
                entries: scan.files.len() as u64,
                unsupported: scan.unsupported,
                notes: scan.notes,
            },
            scan.files,
        )));
    }

    if let Some(sb) = ext4::probe(source, offset)? {
        tracing::info!(offset, "ext4 volume identified");
        let scan = ext4::recover(source, &sb, deleted_only)?;
        return Ok(Some((
            FilesystemReport {
                kind: "ext4".into(),
                offset,
                entries: scan.files.len() as u64,
                unsupported: scan.unsupported,
                notes: scan.notes,
            },
            scan.files,
        )));
    }

    if let Some(container) = apfs::probe(source, offset)? {
        tracing::info!(offset, "APFS container identified");
        let (unsupported, notes) = apfs::report(&container);
        // Deliberately no files. See the module docs: an empty result set with
        // an explicit "not implemented" beats one that reads as "nothing here".
        return Ok(Some((
            FilesystemReport {
                kind: "apfs".into(),
                offset,
                entries: 0,
                unsupported,
                notes,
            },
            Vec::new(),
        )));
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
        let r = scan(&mut s, &options, &Progress::default(), &AtomicBool::new(false)).unwrap();
        assert_eq!(r.files.len(), 1);
        assert_eq!(r.files[0].confidence(), Confidence::Low);
        assert_eq!(r.counts(), (0, 0, 1));
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
        let r = scan(&mut s, &options, &Progress::default(), &AtomicBool::new(false)).unwrap();

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
        let r = scan(&mut s, &ScanOptions::default(), &Progress::default(), &cancel).unwrap();
        assert!(r.problems.iter().any(|p| p.contains("cancelled")));
    }
}
