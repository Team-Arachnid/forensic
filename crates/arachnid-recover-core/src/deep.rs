//! Deep scan: the places older data survives that a standard scan does not look.
//!
//! The standard scan reads what the live filesystem still describes and carves
//! what is left in unallocated space. That is the right default, and on most
//! media it is also most of what there is. It misses five kinds of place where
//! genuinely older material can still be sitting:
//!
//! - **Journals and logs.** A filesystem records what it is about to do before
//!   it does it. Long after a file's data is gone, the record that a file of
//!   that name existed at that time can still be in `$UsnJrnl`, `$LogFile` or
//!   the jbd2 journal. See [`crate::ntfs::mine_journals`].
//! - **Snapshots.** A Volume Shadow Copy is a whole second view of the volume,
//!   dated. See [`crate::vss`].
//! - **Backup metadata.** ext2/3/4 keep superblock copies in later block
//!   groups and NTFS keeps `$MFTMirr` and a backup boot sector; a copy can
//!   describe a state the primary has moved past.
//! - **Slack space.** The tail of the last cluster of a live file is not
//!   cleared when a smaller file takes the cluster over, so a remnant of the
//!   previous occupant can sit there untouched for years. See [`slack_space`].
//! - **Hidden areas.** An HPA or DCO takes capacity out of the view the OS
//!   gets. See [`hidden_area`].
//!
//! # What this cannot do
//!
//! Nothing here recovers overwritten data. There is no technique in this module,
//! or anywhere else, that reads back a byte the drive has written something else
//! over. What a deep scan does is exhaust the places where old data can still
//! *be*, and then say what it found — including saying that it found nothing
//! older than the standard scan already had, which on a drive that has been in
//! use since the deletion is the expected answer and not a fault in the tool.
//!
//! Deep scan is read-only against its source in exactly the way the standard
//! scan is: everything here goes through [`crate::source::Source`], which has no
//! write method. That includes the hidden-area check, which is done by reading
//! and comparing on-disk structures rather than by issuing any drive command.

use std::sync::atomic::AtomicBool;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::results::{Check, Confidence, Content, Extent, Method, Rationale, RecoveredFile};
use crate::source::{u32le, u64le, Source};

/// How hard a scan looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Depth {
    /// Filesystem metadata and common-signature carving.
    #[default]
    Standard,
    /// Everything the standard scan does, plus the techniques in this module.
    /// Substantially slower; see [`estimate`].
    Deep,
}

impl Depth {
    pub fn label(self) -> &'static str {
        match self {
            Depth::Standard => "standard",
            Depth::Deep => "deep",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "standard" | "normal" => Some(Depth::Standard),
            "deep" => Some(Depth::Deep),
            _ => None,
        }
    }

    pub fn is_deep(self) -> bool {
        self == Depth::Deep
    }
}

/// Which deep techniques are switched on.
///
/// Everything except `hpa_dco` is on when deep mode is, because each is just
/// another place to read and the operator asked for a thorough scan. `hpa_dco`
/// is separate and off: a hidden area is unusual enough that looking for one
/// should be a decision, not a side effect of picking a depth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeepOptions {
    pub journal_mining: bool,
    pub shadow_copies: bool,
    pub backup_metadata: bool,
    pub slack_space: bool,
    pub expanded_signatures: bool,
    pub hpa_dco: bool,
}

impl Default for DeepOptions {
    fn default() -> Self {
        DeepOptions {
            journal_mining: true,
            shadow_copies: true,
            backup_metadata: true,
            slack_space: true,
            expanded_signatures: true,
            hpa_dco: false,
        }
    }
}

impl DeepOptions {
    /// Every technique named, for a front end to list what a deep scan will do
    /// before it starts doing it for the next three hours.
    pub fn techniques(&self) -> Vec<&'static str> {
        let mut t = Vec::new();
        if self.journal_mining {
            t.push("journal mining");
        }
        if self.shadow_copies {
            t.push("shadow copies");
        }
        if self.backup_metadata {
            t.push("backup metadata");
        }
        if self.slack_space {
            t.push("slack space");
        }
        if self.expanded_signatures {
            t.push("expanded signatures");
        }
        if self.hpa_dco {
            t.push("HPA/DCO detection");
        }
        t
    }
}

/// Something about the media that changes what a scan of it can be expected to
/// find. Reported before the scan runs, not after it has spent four hours.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Advisory {
    /// `trim`, `wiped`, `hidden-area`.
    pub kind: String,
    pub detail: String,
}

impl Advisory {
    fn new(kind: &str, detail: impl Into<String>) -> Self {
        Advisory {
            kind: kind.into(),
            detail: detail.into(),
        }
    }
}

/// What the deep techniques did, recorded in the results index alongside what
/// they found.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeepReport {
    /// Techniques the operator asked for.
    pub techniques: Vec<String>,
    /// Stages that finished. A resumed scan skips these and keeps the results
    /// they produced; see [`crate::resume`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub advisories: Vec<Advisory>,
    /// One line per technique per volume: what it walked and what came back.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

impl DeepReport {
    pub fn summary_section(&self) -> String {
        let mut s = String::from("\nDeep scan\n");
        s.push_str(&format!("  techniques  {}\n", self.techniques.join(", ")));
        for note in &self.notes {
            s.push_str(&format!("  {note}\n"));
        }
        if !self.advisories.is_empty() {
            s.push_str("\n  What this media allows\n");
            for a in &self.advisories {
                s.push_str(&format!("  [{}] {}\n", a.kind, a.detail));
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// How long this is going to take
// ---------------------------------------------------------------------------

/// Bytes per second assumed when estimating a scan, unless the operator has
/// measured their own rig and said otherwise.
///
/// Deliberately pessimistic: an estimate that comes in early is a good
/// surprise, and one that comes in late is the operator standing over a machine
/// they were told would be finished.
// ponytail: a fixed rate with an override, not a calibration pass. Real
// throughput depends on the bus, the media and how fragmented the volume is; if
// the estimate proves consistently wrong on a class of hardware, measure the
// first gigabyte and extrapolate from that instead.
const ASSUMED_MB_PER_SEC: f64 = 60.0;

/// Roughly how many passes' worth of reading each depth costs. A deep scan
/// re-reads the volume for journal records, walks every live file's last
/// cluster, and carves with a signature set about twice the size.
const DEEP_PASS_FACTOR: f64 = 2.5;

/// How long a scan of `size` bytes is likely to take.
///
/// Set `ARACHNID_SCAN_MBPS` to the throughput actually seen on the rig in use
/// to replace the built-in assumption.
pub fn estimate(size: u64, depth: Depth) -> Duration {
    let mbps = std::env::var("ARACHNID_SCAN_MBPS")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(ASSUMED_MB_PER_SEC);
    let factor = if depth.is_deep() {
        DEEP_PASS_FACTOR
    } else {
        1.0
    };
    let seconds = (size as f64 / (mbps * 1024.0 * 1024.0)) * factor;
    Duration::from_secs_f64(seconds.clamp(0.0, 60.0 * 60.0 * 24.0 * 30.0))
}

/// `2h 14m`, `47s` — an estimate rendered at the precision it deserves.
pub fn human_duration(d: Duration) -> String {
    let secs = d.as_secs();
    match secs {
        0..=90 => format!("{secs}s"),
        91..=5400 => format!("{}m", secs.div_ceil(60)),
        _ => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
    }
}

// ---------------------------------------------------------------------------
// What the media itself says about its recoverability
// ---------------------------------------------------------------------------

/// Everything worth telling the operator before a long scan starts.
///
/// `hpa_dco` is honoured here rather than assumed: the hidden-area check is the
/// one an operator opts into.
pub fn advisories(source: &mut dyn Source, options: &DeepOptions) -> Vec<Advisory> {
    let mut out = Vec::new();
    if let Some(a) = trim_status(&source.label()) {
        out.push(a);
    }
    if let Some(a) = wipe_signature(source) {
        out.push(a);
    }
    if options.hpa_dco {
        match hidden_area(source) {
            Ok(Some(a)) => out.push(a),
            Ok(None) => out.push(Advisory::new(
                "hidden-area",
                "no HPA or DCO is visible from the partition and volume structures on this \
                 source. An area hidden before the drive was partitioned leaves no trace in them \
                 and would need an ATA IDENTIFY DEVICE command, which this build does not issue.",
            )),
            Err(e) => out.push(Advisory::new(
                "hidden-area",
                format!("the hidden-area check could not complete: {e:#}"),
            )),
        }
    }
    out
}

/// Turn what the OS reports about a block device into advice, or into nothing.
///
/// Split out from the sysfs reading so the decision is testable without a
/// drive: the rule is what matters and the rule is what can be got wrong.
pub fn trim_advice(rotational: Option<bool>, discard_granularity: Option<u64>) -> Option<Advisory> {
    match (rotational, discard_granularity) {
        // Solid state, and the kernel has a discard granularity for it: TRIM is
        // available and, on any normally-configured system, in use.
        (Some(false), Some(g)) if g > 0 => Some(Advisory::new(
            "trim",
            format!(
                "this is a solid-state device and TRIM is active on it (discard granularity {g} \
                 bytes). When a file is deleted on a TRIM-active SSD the controller is told it \
                 may erase those blocks, and it generally does so within seconds — so reads of \
                 unallocated space return zeroes no matter how deeply they are scanned. Metadata \
                 techniques (journals, snapshots, backup superblocks) can still find evidence \
                 that a file existed; carving unallocated space very likely cannot find the file \
                 itself. Weigh that before spending hours on a deep scan of this device."
            ),
        )),
        (Some(false), _) => Some(Advisory::new(
            "trim",
            "this is a solid-state device. TRIM status could not be read, but if it is enabled — \
             the default on every current OS — deleted data in unallocated space is likely to \
             have been erased by the controller already, whatever the scan depth.",
        )),
        // Rotational, or unknown. A spinning disk does not erase on delete;
        // there is nothing to warn about.
        _ => None,
    }
}

/// Read the kernel's view of a block device, on the one platform that publishes
/// it as plain files.
#[cfg(target_os = "linux")]
fn trim_status(label: &str) -> Option<Advisory> {
    // /dev/sdb3 -> sdb; /dev/nvme0n1p2 -> nvme0n1.
    let name = label.strip_prefix("/dev/")?;
    let base = sysfs_base(name);
    let read = |leaf: &str| std::fs::read_to_string(format!("/sys/block/{base}/{leaf}")).ok();
    let rotational = read("queue/rotational").and_then(|v| match v.trim() {
        "0" => Some(false),
        "1" => Some(true),
        _ => None,
    });
    let granularity = read("queue/discard_granularity").and_then(|v| v.trim().parse::<u64>().ok());
    trim_advice(rotational, granularity)
}

/// Strip a partition suffix to get the whole-device name sysfs is keyed on.
#[cfg(target_os = "linux")]
fn sysfs_base(name: &str) -> String {
    // nvme0n1p2 and mmcblk0p1 separate the partition number with a "p"; sda3
    // does not.
    if let Some((head, tail)) = name.rsplit_once('p') {
        if !tail.is_empty()
            && tail.bytes().all(|b| b.is_ascii_digit())
            && head.ends_with(|c: char| c.is_ascii_digit())
        {
            return head.to_string();
        }
    }
    name.trim_end_matches(|c: char| c.is_ascii_digit()).to_string()
}

/// Elsewhere there is no cheap read-only way to ask, and guessing from a device
/// path would produce a warning that is wrong as often as it is right.
#[cfg(not(target_os = "linux"))]
fn trim_status(label: &str) -> Option<Advisory> {
    if !label.starts_with(r"\\.\") && !label.starts_with(r"\\?\") {
        // An image file. Whatever TRIM did, it did before the image was taken,
        // and the image is what it is.
        return None;
    }
    Some(Advisory::new(
        "trim",
        "this platform does not expose the device's TRIM status to a read-only handle, so it \
         could not be checked. If the target is a solid-state drive with TRIM enabled — the \
         default — deleted data in unallocated space has most likely been erased by the \
         controller already, and no scan depth will bring it back. The metadata techniques \
         (journals, snapshots, backup superblocks) are not affected in the same way.",
    ))
}

/// Windows sampled when asking whether the media has already been erased.
const WIPE_SAMPLES: usize = 32;
const WIPE_SAMPLE_BYTES: usize = 4096;

/// Report media that looks like it has already been securely erased.
///
/// A drive filled edge to edge with one repeated byte has had a wipe run over
/// it, and the right thing to tell the operator is that the data is gone —
/// correctly gone — rather than to spend four hours confirming it. This module
/// makes no attempt to undo a wipe, an encryption, or any other
/// data-destruction feature the drive has already had applied.
pub fn wipe_signature(source: &mut dyn Source) -> Option<Advisory> {
    let size = source.size();
    if size < (WIPE_SAMPLE_BYTES * WIPE_SAMPLES) as u64 {
        return None;
    }
    let step = size / WIPE_SAMPLES as u64;
    let mut fill: Option<u8> = None;
    let mut buf = vec![0u8; WIPE_SAMPLE_BYTES];
    for i in 0..WIPE_SAMPLES {
        let n = source.read_at(i as u64 * step, &mut buf).ok()?;
        if n < WIPE_SAMPLE_BYTES {
            return None;
        }
        let first = buf[0];
        if buf.iter().any(|b| *b != first) {
            return None;
        }
        match fill {
            None => fill = Some(first),
            Some(f) if f == first => {}
            Some(_) => return None,
        }
    }
    let byte = fill?;
    Some(Advisory::new(
        "wiped",
        format!(
            "every one of {WIPE_SAMPLES} samples taken across this source is filled with \
             0x{byte:02X} and nothing else. That is what media looks like after a secure erase or \
             a full overwrite. The data that was here has been destroyed, correctly, and no \
             recovery technique returns it — this tool does not attempt to defeat an erasure that \
             has already been applied. A scan will still run if the negative result is wanted on \
             the record."
        ),
    ))
}

// ---------------------------------------------------------------------------
// Hidden areas (HPA / DCO)
// ---------------------------------------------------------------------------

const SECTOR: u64 = 512;

/// Look for capacity the OS cannot see, by comparing what the on-disk
/// structures say the drive is against what the drive hands back.
///
/// This is a read-only check and issues no drive command of any kind. It finds
/// a hidden area configured *after* the drive was partitioned, which is the
/// usual case for a recovery partition and for data deliberately tucked away:
/// the GPT's own backup header, or an MBR partition's declared end, points past
/// the last sector the drive will admit to having.
///
/// It cannot find an area hidden before the drive was ever partitioned. Nothing
/// on the visible part of such a drive refers to the hidden part, so the only
/// way to see it is to ask the drive its native capacity with an ATA IDENTIFY
/// DEVICE command. This build issues no ATA commands, and says so rather than
/// leaving the operator to read a clean result as a clean drive.
pub fn hidden_area(source: &mut dyn Source) -> Result<Option<Advisory>> {
    let size = source.size();
    if size < 2 * SECTOR {
        return Ok(None);
    }
    let mut claimed: Vec<(u64, &'static str)> = Vec::new();

    // GPT: the primary header names the LBA its own backup copy sits at, which
    // is the last sector of the drive as the partitioner saw it.
    let header = source.read_exact_at(SECTOR, SECTOR as usize)?;
    if &header[0..8] == b"EFI PART" {
        if let Some(alternate) = u64le(&header, 0x20) {
            claimed.push((
                alternate.saturating_add(1).saturating_mul(SECTOR),
                "the GPT header's backup-header location",
            ));
        }
    }

    // MBR: the end of the furthest-reaching partition entry.
    let mbr = source.read_exact_at(0, SECTOR as usize)?;
    if mbr[510] == 0x55 && mbr[511] == 0xAA {
        for i in 0..4 {
            let at = 0x1BE + i * 16;
            let (Some(start), Some(sectors)) = (u32le(&mbr, at + 8), u32le(&mbr, at + 12)) else {
                continue;
            };
            if sectors == 0 {
                continue;
            }
            claimed.push((
                (start as u64 + sectors as u64) * SECTOR,
                "an MBR partition entry's declared end",
            ));
        }
    }

    // A volume that says it is larger than the drive it sits on.
    if let Some(geometry) = crate::ntfs::probe(source, 0)? {
        if geometry.total_sectors > 0 {
            claimed.push((
                geometry
                    .total_sectors
                    .saturating_mul(geometry.bytes_per_sector as u64),
                "the NTFS boot sector's sector count",
            ));
        }
    }

    let Some((end, what)) = claimed.into_iter().max_by_key(|(end, _)| *end) else {
        return Ok(None);
    };
    if end <= size {
        return Ok(None);
    }
    let hidden = end - size;
    Ok(Some(Advisory::new(
        "hidden-area",
        format!(
            "{what} puts the end of this drive at {end} bytes, but it reports {size}. {hidden} \
             bytes ({:.1} MiB) are not visible to the OS, which is what an HPA or a DCO looks \
             like. Reading that area needs an ATA command to lift the limit — which this build \
             does not issue, and which changes the drive's configuration. Take it to a \
             write-blocker and a tool that does, and record the original limit first.",
            hidden as f64 / (1024.0 * 1024.0)
        ),
    )))
}

// ---------------------------------------------------------------------------
// Slack space
// ---------------------------------------------------------------------------

/// Smallest remnant worth reporting. Below this the "file" is a handful of
/// bytes that could be anything, and every live file on the volume produces one.
const MIN_SLACK: u64 = 64;

/// Collect the unused tail of the last cluster of each file in `files`.
///
/// When a 900-byte file takes over a cluster that a 60 KiB file used to own, the
/// filesystem writes the 900 bytes and leaves the rest of the cluster exactly as
/// it was. Nothing clears it, so the remnant can sit there for as long as the
/// new file lives — which makes slack one of the few places old data survives on
/// a drive that has been in constant use since.
///
/// What comes back is a remnant, not a file: no header, no end, no name. It is
/// labelled [`Content::Fragment`] and [`Confidence::Low`], and slack that is
/// entirely zero is dropped rather than reported, because a cluster tail of
/// zeroes is the ordinary case and burying the real finds under it helps nobody.
pub fn slack_space(
    source: &mut dyn Source,
    files: &[RecoveredFile],
    cluster_size: u64,
    cancel: &AtomicBool,
) -> (Vec<RecoveredFile>, String) {
    use std::sync::atomic::Ordering::Relaxed;

    let mut out = Vec::new();
    let mut examined = 0u64;
    if cluster_size == 0 {
        return (out, "slack space: the volume declares no cluster size".into());
    }

    for file in files {
        if cancel.load(Relaxed) {
            break;
        }
        // A deleted file's clusters are free: whatever is in them is
        // unallocated space, which the carving pass already owns. Slack is
        // specifically the tail of a cluster something still holds.
        if file.deleted || file.content != Content::Full {
            continue;
        }
        let Some(last) = file.extents.last() else {
            continue;
        };
        let end = last.offset.saturating_add(last.length);
        let boundary = end.div_ceil(cluster_size) * cluster_size;
        let length = boundary - end;
        if length < MIN_SLACK || boundary > source.size() {
            continue;
        }
        examined += 1;
        let Ok(bytes) = source.read_exact_at(end, length as usize) else {
            continue;
        };
        if bytes.iter().all(|b| *b == 0) {
            continue;
        }

        let id = format!("slack-{:06}", out.len());
        out.push(RecoveredFile {
            export_name: format!("{id}-at-{end}.bin"),
            id,
            method: Method::SlackSpace,
            original_path: None,
            file_type: "bin".into(),
            size: length,
            extents: vec![Extent {
                offset: end,
                length,
            }],
            created_utc: None,
            modified_utc: None,
            accessed_utc: None,
            deleted: false,
            encrypted: None,
            artifact: None,
            content: Content::Fragment,
            timestamp_source: None,
            rationale: Rationale {
                confidence: Confidence::Low,
                summary: format!(
                    "{length} byte(s) of non-zero data in the unused tail of the last cluster of \
                     {}. This is a remnant of whatever held that cluster before, not part of the \
                     live file.",
                    file.display_name()
                ),
                checks: vec![
                    Check::pass(
                        "slack_is_non_zero",
                        format!(
                            "{length} byte(s) between the end of the file at {end} and the \
                             cluster boundary at {boundary}, and they are not all zero"
                        ),
                    ),
                    Check::fail(
                        "is_a_whole_file",
                        "a cluster tail is a fragment: it has no header, no end and no name, and \
                         there is no way to tell from it what file it came from",
                    ),
                    Check::fail(
                        "original_metadata",
                        format!(
                            "the cluster belongs to {} now. Nothing records what held it before, \
                             including when.",
                            file.display_name()
                        ),
                    ),
                ],
            },
        });
    }

    let note = format!(
        "slack space: {examined} live file(s) had a cluster tail to examine, {} held something \
         other than zeroes",
        out.len()
    );
    (out, note)
}

// ---------------------------------------------------------------------------
// Shared helpers for the metadata-only techniques
// ---------------------------------------------------------------------------

/// Build a result that is evidence of a file rather than a file.
///
/// Used by every technique that recovers a record instead of data: journal
/// entries, backup superblocks, shadow copies. They all need the same shape —
/// no extents, `Low` confidence, and a rationale that says outright that there
/// is nothing here to open.
pub(crate) fn metadata_record(
    id: String,
    method: Method,
    name: String,
    timestamp: Option<String>,
    timestamp_source: &str,
    summary: String,
    mut checks: Vec<Check>,
) -> RecoveredFile {
    checks.push(Check::fail(
        "content_recovered",
        "this is a record that a file existed, not the file. Its data is not in the record and is \
         not claimed to be recoverable from it.",
    ));
    RecoveredFile {
        file_type: crate::ntfs::extension_of(&name),
        export_name: format!("{id}.txt"),
        id,
        method,
        original_path: Some(name),
        size: 0,
        extents: Vec::new(),
        created_utc: None,
        modified_utc: timestamp.clone(),
        accessed_utc: None,
        deleted: false,
        encrypted: None,
        artifact: None,
        content: Content::MetadataOnly,
        timestamp_source: timestamp.is_some().then(|| timestamp_source.to_string()),
        rationale: Rationale {
            confidence: Confidence::Low,
            summary,
            checks,
        },
    }
}

/// Reject a timestamp that cannot be what it claims to be.
///
/// A wrong offset in a structure parser turns arbitrary bytes into a date in
/// the year 1723 or 31402, and a date like that in an oldest-first view is
/// worse than no date at all: it becomes the answer to "how far back does this
/// go". Anything outside living memory of computing, or in the future, is a
/// parse artifact and is dropped.
pub(crate) fn plausible_timestamp(rfc3339: &str) -> bool {
    let Ok(year) = rfc3339.get(0..4).unwrap_or("").parse::<i32>() else {
        return false;
    };
    let now: i32 = arachnid_evidence::now_utc()
        .get(0..4)
        .and_then(|y| y.parse().ok())
        .unwrap_or(2026);
    (1990..=now + 1).contains(&year)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;

    #[test]
    fn depth_parses_and_labels() {
        assert_eq!(Depth::parse("DEEP"), Some(Depth::Deep));
        assert_eq!(Depth::parse("standard"), Some(Depth::Standard));
        assert_eq!(Depth::parse("thorough"), None);
        assert_eq!(Depth::default().label(), "standard");
    }

    /// HPA/DCO is inside deep mode but is never switched on by choosing it.
    #[test]
    fn hidden_area_detection_is_not_bundled_into_deep_mode() {
        let d = DeepOptions::default();
        assert!(!d.hpa_dco);
        assert!(d.techniques().contains(&"journal mining"));
        assert!(!d.techniques().contains(&"HPA/DCO detection"));
    }

    /// Both halves of the TRIM warning path: a TRIM-active SSD must produce the
    /// warning, and a spinning disk must not be told its data is gone.
    #[test]
    fn trim_warns_for_a_discarding_ssd_and_stays_quiet_for_a_spinning_disk() {
        let ssd = trim_advice(Some(false), Some(512)).expect("a TRIM-active SSD must warn");
        assert_eq!(ssd.kind, "trim");
        assert!(ssd.detail.contains("TRIM is active"));
        assert!(ssd.detail.contains("unallocated"));

        assert_eq!(trim_advice(Some(true), Some(512)), None);
        assert_eq!(trim_advice(Some(true), None), None);
        assert_eq!(trim_advice(None, None), None);

        // Solid state with no readable granularity still warrants the softer
        // warning: the drive is the kind that erases on delete.
        let unknown = trim_advice(Some(false), None).unwrap();
        assert!(unknown.detail.contains("TRIM status could not be read"));
    }

    #[test]
    fn a_uniformly_filled_source_is_reported_as_already_erased() {
        let mut wiped = MemorySource::new(vec![0xFF; 1024 * 1024], "wiped");
        let a = wipe_signature(&mut wiped).expect("uniform fill must be reported");
        assert_eq!(a.kind, "wiped");
        assert!(a.detail.contains("0xFF"));

        // One region of real data anywhere in the sample set is enough to say
        // this drive was not wiped.
        let mut bytes = vec![0xFF; 1024 * 1024];
        bytes[512 * 1024] = 0x00;
        let mut used = MemorySource::new(bytes, "used");
        assert_eq!(wipe_signature(&mut used), None);
    }

    /// A GPT whose backup header sits past the last sector the drive admits to
    /// is the classic signature of an HPA set after partitioning.
    #[test]
    fn a_gpt_pointing_past_the_end_of_the_drive_is_reported_as_a_hidden_area() {
        // 2 MiB of "drive", with a GPT that thinks it has 4 MiB.
        let mut img = vec![0u8; 2 * 1024 * 1024];
        img[512..520].copy_from_slice(b"EFI PART");
        let alternate: u64 = (4 * 1024 * 1024 / 512) - 1;
        img[512 + 0x20..512 + 0x28].copy_from_slice(&alternate.to_le_bytes());
        let mut s = MemorySource::new(img, "hpa");

        let a = hidden_area(&mut s).unwrap().expect("must be detected");
        assert_eq!(a.kind, "hidden-area");
        assert!(a.detail.contains("2097152 bytes"));
        assert!(a.detail.contains("does not issue"));
    }

    #[test]
    fn a_drive_whose_structures_fit_inside_it_reports_no_hidden_area() {
        let mut img = vec![0u8; 4 * 1024 * 1024];
        img[512..520].copy_from_slice(b"EFI PART");
        let alternate: u64 = (4 * 1024 * 1024 / 512) - 1;
        img[512 + 0x20..512 + 0x28].copy_from_slice(&alternate.to_le_bytes());
        let mut s = MemorySource::new(img, "clean");
        assert_eq!(hidden_area(&mut s).unwrap(), None);
    }

    /// The whole point of slack: bytes of an older file left in a cluster a
    /// smaller, newer file now owns.
    #[test]
    fn slack_reports_a_remnant_and_ignores_a_zeroed_tail() {
        let cluster = 4096u64;
        let mut img = vec![0u8; 3 * cluster as usize];
        // The live file uses 100 bytes of cluster 0; the rest of that cluster
        // still holds the previous occupant's bytes.
        img[100..200].copy_from_slice(&[b'X'; 100]);
        let mut s = MemorySource::new(img, "slack");

        let live = RecoveredFile {
            id: "ntfs-000001".into(),
            method: Method::NtfsMft,
            original_path: Some("/notes.txt".into()),
            export_name: "notes.txt".into(),
            file_type: "txt".into(),
            size: 100,
            extents: vec![Extent {
                offset: 0,
                length: 100,
            }],
            created_utc: None,
            modified_utc: None,
            accessed_utc: None,
            deleted: false,
            encrypted: None,
            artifact: None,
            content: Content::Full,
            timestamp_source: None,
            rationale: Rationale {
                confidence: Confidence::High,
                summary: String::new(),
                checks: Vec::new(),
            },
        };
        // The same file, but deleted: its clusters are free, so that is
        // unallocated space and belongs to the carver, not to slack.
        let mut deleted = live.clone();
        deleted.id = "ntfs-000002".into();
        deleted.deleted = true;
        deleted.extents = vec![Extent {
            offset: cluster,
            length: 100,
        }];

        let (found, note) = slack_space(&mut s, &[live, deleted], cluster, &AtomicBool::new(false));
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].content, Content::Fragment);
        assert_eq!(found[0].confidence(), Confidence::Low);
        assert_eq!(found[0].extents[0].offset, 100);
        assert_eq!(found[0].extents[0].length, cluster - 100);
        assert!(found[0].rationale.summary.contains("remnant"));
        assert!(note.contains("1 live file(s)"));
    }

    #[test]
    fn a_timestamp_outside_living_memory_is_not_a_timestamp() {
        assert!(plausible_timestamp("2011-04-03T10:00:00Z"));
        assert!(!plausible_timestamp("1601-01-01T00:00:00Z"));
        assert!(!plausible_timestamp("31402-06-01T00:00:00Z"));
        assert!(!plausible_timestamp("not a date"));
    }

    #[test]
    fn the_estimate_scales_with_depth_and_renders_at_a_sane_precision() {
        let size = 500 * 1024 * 1024 * 1024;
        assert!(estimate(size, Depth::Deep) > estimate(size, Depth::Standard));
        assert_eq!(human_duration(Duration::from_secs(30)), "30s");
        assert_eq!(human_duration(Duration::from_secs(600)), "10m");
        assert_eq!(human_duration(Duration::from_secs(7200)), "2h 0m");
    }
}
