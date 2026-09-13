//! What a scan produces, and the confidence label attached to every item.
//!
//! The label is never the whole story. A `High` and a `Low` result look
//! identical once they are files in an output directory, so every item carries
//! the [`Rationale`] that produced its label: which checks ran, and what each
//! one found. An analyst deciding whether to rely on a recovered document needs
//! to read that, not the one-word summary of it.

use serde::{Deserialize, Serialize};

/// Bumped when the results JSON changes incompatibly. Parallel to
/// `arachnid_evidence::SCHEMA_VERSION`, and deliberately versioned separately:
/// the container format and the results format move independently.
pub const SCHEMA_VERSION: &str = "1.0.0";

/// How much of the original file this result is believed to be.
///
/// The ordering is meaningful and is what `--confidence` filters on: `High`
/// outranks `Medium` outranks `Low`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Raw-carved, or metadata-recovered with the data unverifiable.
    /// Structurally plausible; completeness unknown.
    Low,
    /// Filesystem metadata was found, but something about the data is in doubt:
    /// blocks reallocated, the run list truncated, the extent tree partly gone.
    Medium,
    /// Filesystem metadata intact and every byte of the file's allocation read
    /// back cleanly from media.
    High,
}

impl Confidence {
    pub fn label(self) -> &'static str {
        match self {
            Confidence::High => "High",
            Confidence::Medium => "Medium",
            Confidence::Low => "Low",
        }
    }

    /// Parse a `--confidence` token. Case-insensitive; the CLI takes a
    /// comma-separated list of these.
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "high" => Some(Confidence::High),
            "medium" | "med" => Some(Confidence::Medium),
            "low" => Some(Confidence::Low),
            _ => None,
        }
    }
}

/// How a result was found. Recovery via filesystem metadata keeps the original
/// name, path and timestamps; carving keeps none of them, and the two must never
/// be presented as the same kind of claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// Reconstructed from an NTFS MFT record.
    NtfsMft,
    /// Reconstructed from an ext4 inode found in the inode table.
    Ext4Inode,
    /// Reconstructed from an older copy of an inode found in the jbd2 journal.
    Ext4Journal,
    /// Reconstructed from an APFS filesystem tree.
    ApfsTree,
    /// Found by scanning raw sectors for a file signature. No original name,
    /// path, or timestamp exists for a result found this way.
    SignatureCarve,
    /// A USN journal record: evidence that a named file was created, written or
    /// deleted at a stated time. The file's own data is not part of the record.
    NtfsUsnJournal,
    /// A `$FILE_NAME` attribute residue found in an `$LogFile` page, from a
    /// transaction whose MFT record has since been reused.
    NtfsLogFile,
    /// An MFT record read out of `$MFTMirr` that the primary MFT no longer
    /// holds in readable form.
    NtfsMftMirror,
    /// A backup superblock in a later ext block group, recording a filesystem
    /// state the primary superblock has moved on from.
    Ext4BackupSuperblock,
    /// A Volume Shadow Copy: a point in time the volume kept a store for.
    ShadowCopy,
    /// The unused tail of a cluster still allocated to a live file, holding
    /// bytes from whatever occupied that cluster before it.
    SlackSpace,
}

impl Method {
    pub fn label(self) -> &'static str {
        match self {
            Method::NtfsMft => "NTFS MFT",
            Method::Ext4Inode => "ext4 inode",
            Method::Ext4Journal => "ext4 journal",
            Method::ApfsTree => "APFS tree",
            Method::SignatureCarve => "carved",
            Method::NtfsUsnJournal => "USN journal",
            Method::NtfsLogFile => "$LogFile",
            Method::NtfsMftMirror => "$MFTMirr",
            Method::Ext4BackupSuperblock => "ext4 backup sb",
            Method::ShadowCopy => "shadow copy",
            Method::SlackSpace => "slack space",
        }
    }

    pub fn is_carved(self) -> bool {
        matches!(self, Method::SignatureCarve)
    }

    /// True for the techniques only the deep scan runs, so a summary can say
    /// which half of the results the extra hours bought.
    pub fn is_deep(self) -> bool {
        matches!(
            self,
            Method::NtfsUsnJournal
                | Method::NtfsLogFile
                | Method::NtfsMftMirror
                | Method::Ext4BackupSuperblock
                | Method::ShadowCopy
                | Method::SlackSpace
        )
    }
}

/// How much of a file a result actually is.
///
/// The deep scan recovers three different things and they are not
/// interchangeable: a file, a record that a file once existed, and a remnant of
/// a file left in space something else now owns. Exporting the second as a
/// zero-byte file or the third under a full filename would misrepresent both,
/// so the distinction is carried on every result rather than inferred from the
/// method.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    /// The result's extents hold the file's data, as far as the media gave it
    /// back.
    #[default]
    Full,
    /// Evidence that a file existed, with a name and a time — and no data. A
    /// journal record, a backup superblock, a snapshot. There is nothing to
    /// export, and nothing is exported.
    MetadataOnly,
    /// A remnant: real bytes off the media that are part of some file, with no
    /// header, no end and no name.
    Fragment,
}

impl Content {
    pub fn label(self) -> &'static str {
        match self {
            Content::Full => "content",
            Content::MetadataOnly => "metadata-only",
            Content::Fragment => "fragment",
        }
    }
}

/// One check that ran, and what it found. The unit the confidence label is
/// justified in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    /// What was tested, e.g. `data_runs_readable`, `footer_found`.
    pub check: String,
    /// Whether the check was satisfied. `false` is not necessarily a failure of
    /// recovery — it is a reason the label is not higher.
    pub passed: bool,
    /// What was actually observed. Never a restatement of `check`.
    pub detail: String,
}

impl Check {
    pub fn pass(check: &str, detail: impl Into<String>) -> Self {
        Check {
            check: check.into(),
            passed: true,
            detail: detail.into(),
        }
    }

    pub fn fail(check: &str, detail: impl Into<String>) -> Self {
        Check {
            check: check.into(),
            passed: false,
            detail: detail.into(),
        }
    }
}

/// Why a result carries the label it does.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rationale {
    pub confidence: Confidence,
    /// One line an analyst can read without expanding the checks.
    pub summary: String,
    pub checks: Vec<Check>,
}

/// A contiguous run of bytes on the source that holds part of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Extent {
    pub offset: u64,
    pub length: u64,
}

/// One recoverable file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveredFile {
    /// Stable within one results file: `ntfs-000042`, `carve-000007`.
    pub id: String,
    pub method: Method,
    /// Original name where the filesystem still held one; `None` for carved
    /// results, which have no name and must not be given a fabricated one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_path: Option<String>,
    /// The name this file is exported under. For a carved result this is
    /// generated from the id and offset and is explicitly not an original name.
    pub export_name: String,
    /// Lowercase extension without the dot: `jpg`, `pdf`, `docx`.
    pub file_type: String,
    pub size: u64,
    /// Where the content lives on the source, in order.
    pub extents: Vec<Extent>,
    /// RFC 3339 UTC, from filesystem metadata. Empty for carved results.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified_utc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accessed_utc: Option<String>,
    /// True when the filesystem had marked this entry deleted.
    pub deleted: bool,
    /// Set when the file is encrypted at rest. Recovery stops here by design:
    /// the suite implements no key recovery, guessing or brute force.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<String>,
    /// The artifact class this file was identified as — `call-log`,
    /// `browser-history`, `system-log` — where one was. See
    /// [`crate::artifacts`]. Absent means "not one of them, or not identifiable
    /// as one", never "checked and ruled out".
    ///
    /// Defaulted so an index written before this field existed still loads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    /// Whether this result is a file, a record that a file existed, or a
    /// remnant. Defaulted so an index written before the deep scan existed
    /// still loads, and loads as what it was: full content.
    #[serde(default, skip_serializing_if = "Content::is_full")]
    pub content: Content,
    /// Where the timestamps on this result came from, in words — the filesystem
    /// record, a journal entry, a snapshot, or the file's own embedded
    /// metadata. Absent when the result carries no timestamp at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_source: Option<String>,
    pub rationale: Rationale,
}

impl Content {
    /// Serde skip predicate: the default needs no room in the index.
    fn is_full(&self) -> bool {
        *self == Content::Full
    }
}

impl RecoveredFile {
    pub fn confidence(&self) -> Confidence {
        self.rationale.confidence
    }

    /// The oldest timestamp established for this result, and therefore the one
    /// that answers "how far back does this go".
    ///
    /// The oldest rather than the newest on purpose: a file created in 2011 and
    /// last written in 2024 is evidence reaching back to 2011. All four fields
    /// are RFC 3339 UTC with a `Z` suffix, written by the formatters at the
    /// bottom of this file, so comparing them as strings is comparing them as
    /// instants.
    pub fn derived_timestamp(&self) -> Option<&str> {
        [
            self.created_utc.as_deref(),
            self.modified_utc.as_deref(),
            self.accessed_utc.as_deref(),
        ]
        .into_iter()
        .flatten()
        .min()
    }

    /// Display name: the original path where one survives, the generated export
    /// name otherwise.
    pub fn display_name(&self) -> &str {
        self.original_path.as_deref().unwrap_or(&self.export_name)
    }

    /// True when `t` names this file's container type (`jpg`, `sqlite`) or the
    /// artifact class it was identified as (`browser-history`). One `--type`
    /// list selects on either, because an analyst after the call log does not
    /// care which database engine it is stored in.
    pub fn matches_type(&self, t: &str) -> bool {
        t.eq_ignore_ascii_case(&self.file_type)
            || self
                .artifact
                .as_deref()
                .is_some_and(|a| t.eq_ignore_ascii_case(a))
    }
}

/// A filesystem the scan looked at, and how far it got.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilesystemReport {
    /// `ntfs`, `ext4`, `apfs`, or `none`.
    pub kind: String,
    /// Byte offset of the filesystem within the source.
    pub offset: u64,
    /// Recovered entries attributed to this filesystem.
    pub entries: u64,
    /// Features present that this build does not parse. Named individually: a
    /// scan that quietly skipped half a volume is worse than one that refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unsupported: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// A whole scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    pub schema_version: String,
    pub tool: String,
    pub tool_version: String,
    /// The image path or device path that was read.
    pub source: String,
    pub source_size: u64,
    /// Identity of the media this scan read; see
    /// [`crate::source::fingerprint`]. An export checks it before writing a
    /// single byte, because every offset in `files` is meaningless against a
    /// different source.
    ///
    /// Defaulted rather than required so an index written before this field
    /// existed still loads; a consumer that finds it empty must say the check
    /// did not run rather than treat it as passed.
    #[serde(default)]
    pub source_fingerprint: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub operator: String,
    pub filesystem_pass: bool,
    pub carve_pass: bool,
    /// `standard` or `deep`. Defaulted so an index written before the deep scan
    /// existed loads as what it was.
    #[serde(default = "standard_depth")]
    pub depth: String,
    /// Present only on a deep scan: which extra techniques ran, what they found
    /// and what the media said about its own recoverability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deep: Option<crate::deep::DeepReport>,
    /// File types the carver was asked for, in the order given.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub carve_types: Vec<String>,
    pub filesystems: Vec<FilesystemReport>,
    pub files: Vec<RecoveredFile>,
    /// Anything that stopped part of the scan. A scan with problems still
    /// reports every file it did find.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
}

fn standard_depth() -> String {
    "standard".into()
}

impl ScanResults {
    /// Everything that could be dated, oldest first.
    ///
    /// This is the deep scan's headline view. A result with no establishable
    /// timestamp — most carved files — is absent rather than sorted to one end:
    /// "undated" is not a date, and putting it first would make the oldest item
    /// on the list something that is not the oldest item.
    pub fn by_age(&self) -> Vec<&RecoveredFile> {
        let mut dated: Vec<&RecoveredFile> = self
            .files
            .iter()
            .filter(|f| f.derived_timestamp().is_some())
            .collect();
        dated.sort_by(|a, b| {
            a.derived_timestamp()
                .cmp(&b.derived_timestamp())
                .then_with(|| a.id.cmp(&b.id))
        });
        dated
    }

    /// The oldest dated result, if anything could be dated at all.
    pub fn oldest(&self) -> Option<&RecoveredFile> {
        self.by_age().into_iter().next()
    }

    /// The one line that answers "how far back can this go", with the technique
    /// that produced the answer — or says plainly that nothing here can be
    /// dated, which on a heavily-used drive is an ordinary outcome and not a
    /// failure.
    pub fn oldest_line(&self) -> String {
        match self.oldest() {
            Some(f) => format!(
                "Oldest recoverable item found: {}, via {} ({}).",
                f.derived_timestamp().unwrap_or("unknown"),
                f.timestamp_source
                    .as_deref()
                    .unwrap_or_else(|| f.method.label()),
                f.content.label()
            ),
            None => "Oldest recoverable item found: none — nothing recovered here carries a \
                     timestamp that can be established."
                .into(),
        }
    }

    /// Counts by what a result actually is: files, records of files, remnants.
    pub fn content_counts(&self) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for f in &self.files {
            match f.content {
                Content::Full => c.0 += 1,
                Content::MetadataOnly => c.1 += 1,
                Content::Fragment => c.2 += 1,
            }
        }
        c
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        let mut c = (0, 0, 0);
        for f in &self.files {
            match f.confidence() {
                Confidence::High => c.0 += 1,
                Confidence::Medium => c.1 += 1,
                Confidence::Low => c.2 += 1,
            }
        }
        c
    }

    /// Filter by confidence set and type set. An empty set means "any", so the
    /// CLI can pass through whatever the operator did or did not specify.
    pub fn filter<'a>(
        &'a self,
        confidence: &'a [Confidence],
        types: &'a [String],
    ) -> impl Iterator<Item = &'a RecoveredFile> {
        self.files.iter().filter(move |f| {
            (confidence.is_empty() || confidence.contains(&f.confidence()))
                && (types.is_empty() || types.iter().any(|t| f.matches_type(t)))
        })
    }

    /// The human-readable summary that ships beside the JSON.
    pub fn summary(&self) -> String {
        let (high, medium, low) = self.counts();
        let mut s = String::new();
        s.push_str("Arachnid Recover — scan summary\n");
        s.push_str("===============================\n\n");
        s.push_str(&format!("Source      {}\n", self.source));
        s.push_str(&format!("Size        {} bytes\n", self.source_size));
        s.push_str(&format!("Operator    {}\n", self.operator));
        s.push_str(&format!("Started     {}\n", self.started_utc));
        s.push_str(&format!("Finished    {}\n", self.finished_utc));
        s.push_str(&format!(
            "Passes      {}{}{}\n",
            if self.filesystem_pass {
                "filesystem"
            } else {
                ""
            },
            if self.filesystem_pass && self.carve_pass {
                " + "
            } else {
                ""
            },
            if self.carve_pass { "raw carving" } else { "" }
        ));
        s.push_str(&format!("Depth       {}\n\n", self.depth));

        s.push_str("Filesystems\n");
        if self.filesystems.is_empty() {
            s.push_str("  none identified\n");
        }
        for fs in &self.filesystems {
            s.push_str(&format!(
                "  {} at offset {} — {} entr{}\n",
                fs.kind,
                fs.offset,
                fs.entries,
                if fs.entries == 1 { "y" } else { "ies" }
            ));
            for u in &fs.unsupported {
                s.push_str(&format!("    unsupported: {u}\n"));
            }
            for n in &fs.notes {
                s.push_str(&format!("    note: {n}\n"));
            }
        }

        s.push_str(&format!(
            "\nResults     {} file(s)\n  High    {high}\n  Medium  {medium}\n  Low     {low}\n",
            self.files.len()
        ));
        s.push_str(
            "\nHigh   filesystem metadata intact, every allocated byte read back\n\
             Medium filesystem metadata found, data partly overwritten or truncated\n\
             Low    raw-carved: structurally valid, completeness unverified\n",
        );

        let (full, metadata_only, fragments) = self.content_counts();
        if metadata_only > 0 || fragments > 0 {
            s.push_str(&format!(
                "\nWhat the results are\n  \
                 content        {full} — file data, recovered\n  \
                 metadata-only  {metadata_only} — a record that a file existed, with no data\n  \
                 fragment       {fragments} — a remnant in space another file now owns\n"
            ));
        }

        if let Some(deep) = &self.deep {
            s.push_str(&deep.summary_section());
        }

        s.push_str(&format!("\n{}\n", self.oldest_line()));
        if self.oldest().is_some() {
            s.push_str("  full list, oldest first: arachnid-recover list-results --oldest-first\n");
        }

        let artifacts: Vec<(&str, usize)> = crate::artifacts::CLASSES
            .iter()
            .map(|class| {
                let n = self
                    .files
                    .iter()
                    .filter(|f| f.artifact.as_deref() == Some(*class))
                    .count();
                (*class, n)
            })
            .filter(|(_, n)| *n > 0)
            .collect();
        if !artifacts.is_empty() {
            s.push_str("\nArtifacts identified\n");
            for (class, n) in artifacts {
                s.push_str(&format!("  {class:<16} {n}\n"));
            }
            s.push_str("  list one class with: arachnid-recover list-results --type <class>\n");
        }

        let encrypted: Vec<_> = self
            .files
            .iter()
            .filter(|f| f.encrypted.is_some())
            .collect();
        if !encrypted.is_empty() {
            s.push_str(&format!(
                "\n{} file(s) are encrypted at rest and are reported, not decrypted:\n",
                encrypted.len()
            ));
            for f in encrypted.iter().take(10) {
                s.push_str(&format!(
                    "  {} — {}\n",
                    f.display_name(),
                    f.encrypted.as_deref().unwrap_or("encrypted")
                ));
            }
        }

        if !self.problems.is_empty() {
            s.push_str("\nProblems\n");
            for p in &self.problems {
                s.push_str(&format!("  {p}\n"));
            }
        }
        s
    }
}

/// Windows FILETIME (100 ns ticks since 1601-01-01 UTC) as RFC 3339.
///
/// Zero means "not set" throughout NTFS, so it maps to `None` rather than to
/// the year 1601 — a timestamp of 1601 on a recovered file is a parser artifact
/// that an analyst would have to learn to discount.
pub fn filetime_to_rfc3339(ticks: u64) -> Option<String> {
    if ticks == 0 {
        return None;
    }
    // 1601-01-01 to 1970-01-01, in 100 ns ticks.
    const EPOCH_DELTA: u64 = 116_444_736_000_000_000;
    let unix_100ns = ticks.checked_sub(EPOCH_DELTA)?;
    let secs = i64::try_from(unix_100ns / 10_000_000).ok()?;
    let nanos = (unix_100ns % 10_000_000) as u32 * 100;
    unix_to_rfc3339(secs, nanos)
}

/// Unix seconds as RFC 3339, for ext4 and APFS.
pub fn unix_to_rfc3339(secs: i64, nanos: u32) -> Option<String> {
    use time::format_description::well_known::Rfc3339;
    use time::OffsetDateTime;
    let t =
        OffsetDateTime::from_unix_timestamp(secs).ok()? + time::Duration::nanoseconds(nanos as i64);
    t.format(&Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confidence_orders_high_above_low() {
        assert!(Confidence::High > Confidence::Medium);
        assert!(Confidence::Medium > Confidence::Low);
        assert_eq!(Confidence::parse("HIGH"), Some(Confidence::High));
        assert_eq!(Confidence::parse("nope"), None);
    }

    #[test]
    fn filetime_zero_is_not_a_timestamp() {
        assert_eq!(filetime_to_rfc3339(0), None);
        // 2026-08-29T00:00:00Z
        let t = filetime_to_rfc3339(116_444_736_000_000_000 + 1_787_961_600 * 10_000_000);
        assert_eq!(t.as_deref(), Some("2026-08-29T00:00:00Z"));
    }

    #[test]
    fn unix_epoch_formats() {
        assert_eq!(
            unix_to_rfc3339(0, 0).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
    }
}
