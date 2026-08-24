//! Signature-based raw carving: the filesystem-agnostic fallback.
//!
//! Carving finds files by their contents alone. It works when the filesystem is
//! gone — a reformatted volume, a partition table that no longer parses, an APFS
//! container this build cannot walk — and it is the only pass that runs on
//! unallocated space nothing points at any more.
//!
//! What it cannot do is give a file back its identity. A carved result has no
//! original name, no path, no timestamp and no owner, because none of those live
//! in the file's own bytes. Everything carved is therefore labelled `Low` and
//! named after where it was found, never after what it might have been called.
//!
//! **Fragmentation.** Files are carved as contiguous runs. Where the format
//! allows it — a JPEG's `FFD9`, a PDF's `%%EOF`, a ZIP's end-of-central-
//! directory, an MP4's box chain — the end is found structurally rather than
//! guessed, which is what keeps a carved file from running into whatever
//! followed it on disk. Where the terminator is missing, the result is reported
//! as `footer_found: false` and explicitly flagged likely-incomplete. This build
//! does not attempt to reassemble a fragmented file from non-adjacent runs:
//! bi-fragment gap carving and its relatives guess, and a plausible-looking
//! wrong reconstruction is worse in evidence than an honest partial one.

use std::collections::BTreeMap;

use anyhow::Result;

use crate::results::{Check, Confidence, Extent, Method, Rationale, RecoveredFile};
use crate::source::Source;

/// Bytes read per pass. Large enough that the per-read overhead disappears,
/// small enough to stay off the stack and out of a memory-constrained box.
const CHUNK: usize = 4 * 1024 * 1024;

/// The longest header any signature matches on, and therefore how much of the
/// previous chunk each chunk keeps so a signature spanning a chunk boundary is
/// still found.
const MAX_HEADER: usize = 16;

/// Shortest run of printable bytes that counts as a recovered text block. Below
/// this every ASCII string in every binary on the volume becomes a "file".
const MIN_TEXT: usize = 512;

/// Longest text block carved in one piece.
const MAX_TEXT: u64 = 1024 * 1024;

/// How a file type's end is found.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Terminator {
    /// Search forward for a byte sequence; the file ends after it.
    Footer(&'static [u8]),
    /// Walk the MP4/QuickTime box chain and sum the box lengths.
    Mp4Boxes,
    /// Find the ZIP end-of-central-directory record.
    ZipEocd,
    /// Run of printable bytes.
    PrintableRun,
}

struct Signature {
    /// Type name as it appears in `--carve-types` and in results.
    name: &'static str,
    /// Bytes that must appear at the start of the file.
    header: &'static [u8],
    /// Offset within the file at which `header` sits. Non-zero for MP4, whose
    /// `ftyp` follows a four-byte length.
    header_at: usize,
    terminator: Terminator,
    /// Nothing of this type is carved longer than this. A cap that is hit is
    /// reported, not hidden: it means the real file was longer, or the header
    /// was a false positive.
    max_size: u64,
}

/// Every type the carver knows. The `--carve-types` list is matched against
/// `name`, and `docx`/`xlsx`/`pptx` are refinements of `zip` decided after the
/// archive is carved, not separate signatures.
const SIGNATURES: &[Signature] = &[
    Signature {
        name: "jpg",
        header: &[0xFF, 0xD8, 0xFF],
        header_at: 0,
        terminator: Terminator::Footer(&[0xFF, 0xD9]),
        max_size: 64 * 1024 * 1024,
    },
    Signature {
        name: "png",
        header: &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A],
        header_at: 0,
        // IEND plus its fixed CRC: the last eight bytes of every valid PNG.
        terminator: Terminator::Footer(&[b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82]),
        max_size: 256 * 1024 * 1024,
    },
    Signature {
        name: "pdf",
        header: b"%PDF-",
        header_at: 0,
        terminator: Terminator::Footer(b"%%EOF"),
        max_size: 512 * 1024 * 1024,
    },
    Signature {
        name: "zip",
        header: &[b'P', b'K', 0x03, 0x04],
        header_at: 0,
        terminator: Terminator::ZipEocd,
        max_size: 512 * 1024 * 1024,
    },
    Signature {
        name: "mp4",
        header: b"ftyp",
        header_at: 4,
        terminator: Terminator::Mp4Boxes,
        max_size: 4 * 1024 * 1024 * 1024,
    },
    Signature {
        name: "txt",
        header: &[],
        header_at: 0,
        terminator: Terminator::PrintableRun,
        max_size: MAX_TEXT,
    },
];

/// Every type name the carver can be asked for, for `--help` and the TUI's
/// type picker.
pub fn known_types() -> Vec<&'static str> {
    SIGNATURES.iter().map(|s| s.name).collect()
}

/// The default set: everything except `txt`, which on a real volume matches
/// enough log fragments and string tables to bury the rest of the results.
pub fn default_types() -> Vec<String> {
    SIGNATURES
        .iter()
        .filter(|s| s.name != "txt")
        .map(|s| s.name.to_string())
        .collect()
}

/// Progress a carving pass publishes, so a front end can show it moving without
/// the engine knowing anything about a front end.
#[derive(Default)]
pub struct Progress {
    pub bytes_scanned: std::sync::atomic::AtomicU64,
    pub bytes_total: std::sync::atomic::AtomicU64,
    pub files_found: std::sync::atomic::AtomicU64,
}

impl Progress {
    pub fn fraction(&self) -> f64 {
        use std::sync::atomic::Ordering::Relaxed;
        let total = self.bytes_total.load(Relaxed);
        if total == 0 {
            return 0.0;
        }
        self.bytes_scanned.load(Relaxed) as f64 / total as f64
    }
}

/// Carve `source` for the named types.
///
/// `cancel` is checked once per chunk, so a scan of a large device stops within
/// one chunk of the operator asking rather than at the end of the volume.
pub fn carve(
    source: &mut dyn Source,
    types: &[String],
    progress: &Progress,
    cancel: &std::sync::atomic::AtomicBool,
) -> Result<Vec<RecoveredFile>> {
    use std::sync::atomic::Ordering::Relaxed;

    let wanted: Vec<&Signature> = SIGNATURES
        .iter()
        .filter(|s| types.iter().any(|t| t.eq_ignore_ascii_case(s.name)))
        .collect();
    if wanted.is_empty() {
        return Ok(Vec::new());
    }

    let size = source.size();
    progress.bytes_total.store(size, Relaxed);

    // Ranges already claimed by a carved file, so a JPEG's embedded EXIF
    // thumbnail does not become a second result and a ZIP's members do not each
    // become one. Keyed by start offset; values are end offsets.
    let mut claimed: BTreeMap<u64, u64> = BTreeMap::new();
    let mut out: Vec<RecoveredFile> = Vec::new();

    let mut base = 0u64;
    let mut buf = vec![0u8; CHUNK + MAX_HEADER];
    while base < size {
        if cancel.load(Relaxed) {
            break;
        }
        // Each chunk re-reads MAX_HEADER bytes of the previous one so a
        // signature straddling the boundary is still matched.
        let read_from = base.saturating_sub(MAX_HEADER as u64);
        let lead = (base - read_from) as usize;
        let n = source.read_at(read_from, &mut buf)?;
        if n == 0 {
            break;
        }
        let window = &buf[..n];

        for sig in &wanted {
            if sig.terminator == Terminator::PrintableRun {
                continue;
            }
            let mut i = 0usize;
            while let Some(found) = find(&window[i..], sig.header) {
                let at_window = i + found;
                let start_window = match at_window.checked_sub(sig.header_at) {
                    Some(s) => s,
                    None => {
                        i = at_window + 1;
                        continue;
                    }
                };
                let start = read_from + start_window as u64;
                i = at_window + 1;

                // Only act on hits that begin inside this chunk proper; the
                // overlap belongs to the previous one and was handled there.
                if start < base {
                    continue;
                }
                if is_claimed(&claimed, start) {
                    continue;
                }
                if let Some(file) = carve_one(source, sig, start, &mut out)? {
                    claimed.insert(start, start + file.size);
                    progress.files_found.fetch_add(1, Relaxed);
                    out.push(file);
                }
            }
        }

        if wanted.iter().any(|s| s.terminator == Terminator::PrintableRun) {
            carve_text(window, read_from, base, &claimed, &mut out, progress);
        }

        base += CHUNK as u64;
        progress.bytes_scanned.store(base.min(size), Relaxed);
        let _ = lead;
    }

    progress.bytes_scanned.store(size, Relaxed);
    Ok(out)
}

fn is_claimed(claimed: &BTreeMap<u64, u64>, at: u64) -> bool {
    claimed
        .range(..=at)
        .next_back()
        .is_some_and(|(_, end)| at < *end)
}

/// Reconstruct one file from its header, by whichever terminator its format
/// supports.
fn carve_one(
    source: &mut dyn Source,
    sig: &Signature,
    start: u64,
    existing: &mut [RecoveredFile],
) -> Result<Option<RecoveredFile>> {
    let budget = sig.max_size.min(source.size().saturating_sub(start));
    if budget == 0 {
        return Ok(None);
    }

    let (length, footer_found, note) = match sig.terminator {
        Terminator::Footer(footer) => match scan_for_footer(source, start, budget, footer)? {
            Some(end) => (end, true, None),
            None => (
                budget,
                false,
                Some(format!(
                    "no {} terminator within {budget} bytes: the file is fragmented, truncated, \
                     or the header was a false positive",
                    sig.name
                )),
            ),
        },
        Terminator::Mp4Boxes => match mp4_length(source, start, budget)? {
            Some(len) => (len, true, None),
            None => return Ok(None),
        },
        Terminator::ZipEocd => match zip_length(source, start, budget)? {
            Some(len) => (len, true, None),
            None => (
                budget,
                false,
                Some("no ZIP end-of-central-directory record found; the archive is truncated or fragmented".into()),
            ),
        },
        Terminator::PrintableRun => return Ok(None),
    };

    if length == 0 {
        return Ok(None);
    }

    // ZIP-based Office documents are a ZIP with a known member layout. Read
    // enough of the archive to tell which, so results say "docx" rather than
    // leaving an analyst to open every zip.
    let mut file_type = sig.name.to_string();
    if sig.name == "zip" {
        let head = source.read_exact_at(start, length.min(64 * 1024) as usize)?;
        if let Some(office) = office_type(&head) {
            file_type = office.into();
        }
    }

    let index = existing.len();
    let mut checks = vec![
        Check::pass(
            "signature_matched",
            format!(
                "{} header found at offset {start}",
                sig.name.to_ascii_uppercase()
            ),
        ),
        if footer_found {
            Check::pass(
                "footer_found",
                format!("the format's own terminator was found {length} bytes in"),
            )
        } else {
            Check::fail(
                "footer_found",
                note.clone()
                    .unwrap_or_else(|| "no terminator found".into()),
            )
        },
    ];
    checks.push(if length >= sig.max_size {
        Check::fail(
            "within_size_cap",
            format!(
                "the carve hit the {} byte cap for this type; the real file is longer, or this \
                 was not a file",
                sig.max_size
            ),
        )
    } else {
        Check::pass("within_size_cap", format!("{length} bytes, under the type cap"))
    });
    checks.push(Check::fail(
        "original_metadata",
        "carved from raw sectors: there is no original filename, path, owner or timestamp for \
         this file, and none has been invented",
    ));
    checks.push(Check::fail(
        "contiguity_verified",
        "carving assumes the file is contiguous on the media; if it was fragmented, the bytes \
         after the first fragment belong to something else",
    ));

    let summary = if footer_found {
        format!(
            "raw-carved {file_type}: header and the format's own terminator both present, so the \
             extent is structurally bounded — but completeness is unverified and no original \
             metadata exists"
        )
    } else {
        format!(
            "raw-carved {file_type}: header present, no terminator found, so the length is a cap \
             rather than the file's real end — likely incomplete"
        )
    };

    Ok(Some(RecoveredFile {
        id: format!("carve-{index:06}"),
        method: Method::SignatureCarve,
        // Deliberately None. A carved file has no original path and must never
        // be given one that looks like it came from the filesystem.
        original_path: None,
        export_name: format!("carve-{index:06}-at-{start}.{file_type}"),
        file_type,
        size: length,
        extents: vec![Extent {
            offset: start,
            length,
        }],
        created_utc: None,
        modified_utc: None,
        accessed_utc: None,
        // A carved file is found in space the filesystem no longer describes.
        // Whether it was ever deleted is not knowable from its bytes.
        deleted: false,
        encrypted: None,
        rationale: Rationale {
            confidence: Confidence::Low,
            summary,
            checks,
        },
    }))
}

/// Stream forward from `start` looking for `footer`, returning the length of the
/// file including it.
fn scan_for_footer(
    source: &mut dyn Source,
    start: u64,
    budget: u64,
    footer: &[u8],
) -> Result<Option<u64>> {
    let overlap = footer.len().saturating_sub(1);
    let mut buf = vec![0u8; CHUNK + overlap];
    let mut at = start;
    // Bytes carried over from the previous read. `buf[0]` is always at source
    // offset `at - carry`, which is what turns a match index into an offset.
    let mut carry = 0usize;
    while at < start + budget {
        let room = buf.len() - carry;
        let left = (start + budget - at) as usize;
        let n = source.read_at(at, &mut buf[carry..carry + room.min(left)])?;
        if n == 0 {
            return Ok(None);
        }
        let filled = carry + n;
        if let Some(found) = find(&buf[..filled], footer) {
            let footer_at = (at - carry as u64) + found as u64;
            return Ok(Some(footer_at + footer.len() as u64 - start));
        }
        // Keep the last `overlap` bytes so a footer straddling the read is found.
        at += n as u64;
        carry = overlap.min(filled);
        buf.copy_within(filled - carry..filled, 0);
    }
    Ok(None)
}

/// Sum an MP4/QuickTime box chain to the real end of the file.
///
/// Structural rather than signature-based: a `.mp4` has no footer, but every
/// box declares its own length, so walking the chain gives an exact end instead
/// of a guess. A box with an impossible length ends the walk, and what was
/// walked so far is the file.
fn mp4_length(source: &mut dyn Source, start: u64, budget: u64) -> Result<Option<u64>> {
    let mut at = 0u64;
    let mut boxes = 0;
    while at + 8 <= budget {
        let header = source.read_exact_at(start + at, 8)?;
        let size32 = u32::from_be_bytes(header[0..4].try_into().expect("8 bytes read")) as u64;
        // A box type must be four printable characters; anything else means the
        // chain has run off the end of the file into unrelated data.
        if !header[4..8].iter().all(|b| b.is_ascii_graphic()) {
            break;
        }
        let size = match size32 {
            // 1 means a 64-bit length follows the type.
            1 => {
                let ext = source.read_exact_at(start + at + 8, 8)?;
                u64::from_be_bytes(ext.try_into().expect("8 bytes read"))
            }
            // 0 means "to the end of the file".
            0 => budget - at,
            n => n,
        };
        if size < 8 || at + size > budget {
            break;
        }
        at += size;
        boxes += 1;
    }
    // One box is a stray `ftyp`, not a video.
    Ok((boxes >= 2 && at > 0).then_some(at))
}

/// Find a ZIP's end-of-central-directory record and return the archive length.
fn zip_length(source: &mut dyn Source, start: u64, budget: u64) -> Result<Option<u64>> {
    const EOCD: &[u8] = &[b'P', b'K', 0x05, 0x06];
    let Some(end) = scan_for_footer(source, start, budget, EOCD)? else {
        return Ok(None);
    };
    // EOCD is 22 bytes plus a variable comment whose length is the last field.
    let record = source.read_exact_at(start + end - 4, 22.min(budget - end + 4) as usize)?;
    let comment = crate::source::u16le(&record, 20).unwrap_or(0) as u64;
    Ok(Some((end - 4 + 22 + comment).min(budget)))
}

/// Which OOXML type a carved ZIP is, from the member names in its local file
/// headers.
fn office_type(head: &[u8]) -> Option<&'static str> {
    if find(head, b"word/").is_some() {
        Some("docx")
    } else if find(head, b"xl/").is_some() {
        Some("xlsx")
    } else if find(head, b"ppt/").is_some() {
        Some("pptx")
    } else {
        None
    }
}

/// Carve runs of printable text.
///
/// Only what lies in this chunk: a text block is not a format with a header, so
/// there is nothing to seek forward from, and a run that crosses a chunk
/// boundary is reported as two blocks rather than being stitched with a guess.
fn carve_text(
    window: &[u8],
    read_from: u64,
    base: u64,
    claimed: &BTreeMap<u64, u64>,
    out: &mut Vec<RecoveredFile>,
    progress: &Progress,
) {
    let mut run_start: Option<usize> = None;
    for i in 0..=window.len() {
        let printable = window
            .get(i)
            .is_some_and(|b| b.is_ascii_graphic() || matches!(b, b' ' | b'\t' | b'\n' | b'\r'));
        match (printable, run_start) {
            (true, None) => run_start = Some(i),
            (false, Some(s)) => {
                let len = i - s;
                let start = read_from + s as u64;
                if len >= MIN_TEXT
                    && (len as u64) <= MAX_TEXT
                    && start >= base
                    && !is_claimed(claimed, start)
                {
                    let index = out.len();
                    out.push(text_result(index, start, len as u64));
                    progress
                        .files_found
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                run_start = None;
            }
            _ => {}
        }
    }
}

fn text_result(index: usize, start: u64, length: u64) -> RecoveredFile {
    RecoveredFile {
        id: format!("carve-{index:06}"),
        method: Method::SignatureCarve,
        original_path: None,
        export_name: format!("carve-{index:06}-at-{start}.txt"),
        file_type: "txt".into(),
        size: length,
        extents: vec![Extent {
            offset: start,
            length,
        }],
        created_utc: None,
        modified_utc: None,
        accessed_utc: None,
        deleted: false,
        encrypted: None,
        rationale: Rationale {
            confidence: Confidence::Low,
            summary: format!(
                "raw-carved text: a {length}-byte run of printable bytes. Text has no header or \
                 footer, so the boundaries are where printable bytes started and stopped, not \
                 where a file did"
            ),
            checks: vec![
                Check::pass(
                    "printable_run",
                    format!("{length} consecutive printable bytes at offset {start}"),
                ),
                Check::fail(
                    "footer_found",
                    "plain text has no terminator; the end of the run is not known to be the end \
                     of a file",
                ),
                Check::fail(
                    "original_metadata",
                    "carved from raw sectors: no filename, path or timestamp exists for this block",
                ),
            ],
        },
    }
}

/// Naive substring search. O(n·m) worst case, and the right choice here: the
/// needles are 2-8 bytes, so the constant factor of a Boyer-Moore table costs
/// more than it saves on a haystack read straight off a disk.
// ponytail: naive search, switch to memchr-style skipping if profiling ever
// shows the scan is CPU-bound rather than I/O-bound.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;
    use std::sync::atomic::AtomicBool;

    fn carve_all(bytes: Vec<u8>, types: &[&str]) -> Vec<RecoveredFile> {
        let mut s = MemorySource::new(bytes, "test");
        let types: Vec<String> = types.iter().map(|t| t.to_string()).collect();
        carve(&mut s, &types, &Progress::default(), &AtomicBool::new(false)).unwrap()
    }

    #[test]
    fn a_jpeg_between_two_slabs_of_noise_is_carved_exactly() {
        let mut img = vec![0u8; 1000];
        let jpeg: Vec<u8> = [0xFF, 0xD8, 0xFF, 0xE0]
            .into_iter()
            .chain(std::iter::repeat_n(0x41, 200))
            .chain([0xFF, 0xD9])
            .collect();
        let at = img.len();
        img.extend_from_slice(&jpeg);
        img.extend(std::iter::repeat_n(0u8, 1000));

        let found = carve_all(img, &["jpg"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].extents[0].offset, at as u64);
        assert_eq!(found[0].size, jpeg.len() as u64);
        assert_eq!(found[0].confidence(), Confidence::Low);
        // The name must not look like it came from a filesystem.
        assert!(found[0].original_path.is_none());
        assert!(found[0].export_name.contains(&at.to_string()));
    }

    /// A header with no footer must still be reported — and must say plainly
    /// that its length is a cap, not the file's end.
    #[test]
    fn a_headerless_tail_is_reported_as_incomplete() {
        let mut img = vec![0xFFu8, 0xD8, 0xFF, 0xE0];
        img.extend(std::iter::repeat_n(0x41, 500));
        let found = carve_all(img, &["jpg"]);
        assert_eq!(found.len(), 1);
        let footer = found[0]
            .rationale
            .checks
            .iter()
            .find(|c| c.check == "footer_found")
            .unwrap();
        assert!(!footer.passed);
        assert!(found[0].rationale.summary.contains("likely incomplete"));
    }

    /// An EXIF thumbnail is a JPEG inside a JPEG. Two results for one photo is
    /// the classic carver false positive.
    #[test]
    fn a_nested_jpeg_does_not_become_a_second_result() {
        let inner: Vec<u8> = [0xFF, 0xD8, 0xFF, 0xE1]
            .into_iter()
            .chain(std::iter::repeat_n(0x42, 50))
            .chain([0xFF, 0xD9])
            .collect();
        let mut outer = vec![0xFF, 0xD8, 0xFF, 0xE0];
        outer.extend_from_slice(&inner);
        outer.extend(std::iter::repeat_n(0x41, 100));
        outer.extend([0xFF, 0xD9]);

        let found = carve_all(outer, &["jpg"]);
        assert_eq!(found.len(), 1, "the thumbnail was carved as its own file");
    }

    #[test]
    fn a_png_is_bounded_by_iend() {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend(std::iter::repeat_n(0x00, 40));
        png.extend([b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82]);
        let len = png.len();
        png.extend(std::iter::repeat_n(0xCC, 500));

        let found = carve_all(png, &["png"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].size, len as u64);
    }

    /// The box walk is what gives MP4 an exact end without a footer.
    #[test]
    fn mp4_boxes_are_walked_to_the_real_end() {
        let mut mp4 = Vec::new();
        mp4.extend(24u32.to_be_bytes());
        mp4.extend(b"ftyp");
        mp4.extend(std::iter::repeat_n(0x00, 16));
        mp4.extend(100u32.to_be_bytes());
        mp4.extend(b"moov");
        mp4.extend(std::iter::repeat_n(0x11, 92));
        let len = mp4.len();
        // Trailing junk that is not a valid box: the walk must stop before it.
        mp4.extend(std::iter::repeat_n(0xFFu8, 200));

        let found = carve_all(mp4, &["mp4"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].size, len as u64);
    }

    /// A lone ftyp box with nothing after it is a false positive, not a video.
    #[test]
    fn a_lone_ftyp_box_is_not_a_video() {
        let mut junk = Vec::new();
        junk.extend(16u32.to_be_bytes());
        junk.extend(b"ftyp");
        junk.extend(std::iter::repeat_n(0x00, 8));
        junk.extend(std::iter::repeat_n(0xFFu8, 200));
        assert!(carve_all(junk, &["mp4"]).is_empty());
    }

    #[test]
    fn a_docx_is_recognised_as_more_than_a_zip() {
        let mut zip = vec![b'P', b'K', 0x03, 0x04];
        zip.extend(std::iter::repeat_n(0u8, 26));
        zip.extend(b"word/document.xml");
        zip.extend(std::iter::repeat_n(0u8, 100));
        zip.extend([b'P', b'K', 0x05, 0x06]);
        zip.extend(std::iter::repeat_n(0u8, 18));

        let found = carve_all(zip, &["zip"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].file_type, "docx");
        assert!(found[0].export_name.ends_with(".docx"));
    }

    /// Short strings are everywhere in binary data. The minimum run length is
    /// the only thing between a text carve and thousands of junk results.
    #[test]
    fn short_strings_are_not_carved_as_text() {
        let mut img = vec![0u8; 100];
        img.extend(b"this is far too short to be a document");
        img.extend(std::iter::repeat_n(0u8, 100));
        assert!(carve_all(img, &["txt"]).is_empty());

        let mut img = vec![0u8; 100];
        img.extend(std::iter::repeat_n(b'A', MIN_TEXT + 10));
        img.extend(std::iter::repeat_n(0u8, 100));
        let found = carve_all(img, &["txt"]);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].size, (MIN_TEXT + 10) as u64);
    }

    #[test]
    fn an_unrequested_type_is_not_carved() {
        let mut img = vec![0u8; 100];
        img.extend([0xFF, 0xD8, 0xFF, 0xE0]);
        img.extend(std::iter::repeat_n(0x41, 50));
        img.extend([0xFF, 0xD9]);
        assert!(carve_all(img.clone(), &["png"]).is_empty());
        assert_eq!(carve_all(img, &["jpg"]).len(), 1);
    }

    /// Every carved result is Low, whatever else is true of it. The label is the
    /// contract: filesystem metadata is the only thing that earns more.
    #[test]
    fn everything_carved_is_low_confidence() {
        let mut img = vec![0xFF, 0xD8, 0xFF, 0xE0];
        img.extend(std::iter::repeat_n(0x41, 50));
        img.extend([0xFF, 0xD9]);
        for f in carve_all(img, &["jpg"]) {
            assert_eq!(f.confidence(), Confidence::Low);
            assert!(f.method.is_carved());
        }
    }
}
