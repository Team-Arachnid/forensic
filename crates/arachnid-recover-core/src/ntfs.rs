//! NTFS recovery via the Master File Table.
//!
//! An NTFS delete does not erase the file record. It clears the in-use bit in
//! the record header and frees the clusters in `$Bitmap`; the record itself —
//! name, parent, timestamps, and the run list pointing at the data — stays
//! where it was until something reuses the slot. That is why this path recovers
//! more, and can say far more about what it recovered, than carving can: the
//! filename and the original path are read out of the filesystem rather than
//! invented.
//!
//! What it deliberately does not do:
//!
//! - **Decompress.** A compressed `$DATA` attribute is reported as an
//!   unsupported feature and its file is capped at `Medium`, never exported as
//!   though the raw clusters were the file's contents.
//! - **Decrypt.** An EFS-encrypted `$DATA` is reported encrypted and stops
//!   there. No key recovery of any kind exists in this crate.
//! - **Guess at reallocation.** A freed run whose clusters have since been
//!   handed to another file reads back as that other file's data. Nothing here
//!   can tell the difference, so a deleted file never scores `High` on the
//!   strength of a clean read alone; see [`crate::ntfs`]'s scoring below.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};

use crate::results::{
    filetime_to_rfc3339, Check, Confidence, Extent, Method, Rationale, RecoveredFile,
};
use crate::source::{u16le, u32le, u64le, Source};

/// Attribute type codes, of the handful this parser reads.
const ATTR_STANDARD_INFORMATION: u32 = 0x10;
const ATTR_FILE_NAME: u32 = 0x30;
const ATTR_DATA: u32 = 0x80;
const ATTR_END: u32 = 0xFFFF_FFFF;

/// `$DATA` attribute flags.
const FLAG_COMPRESSED: u16 = 0x0001;
const FLAG_ENCRYPTED: u16 = 0x4000;
const FLAG_SPARSE: u16 = 0x8000;

/// Record header flags.
const RECORD_IN_USE: u16 = 0x0001;
const RECORD_IS_DIRECTORY: u16 = 0x0002;

/// MFT record number of the root directory. Fixed by the format.
const ROOT_RECORD: u64 = 5;

/// The first 16 records are NTFS's own metadata files (`$MFT`, `$LogFile`,
/// `$Bitmap`…). They are not user data and recovering them as files would fill
/// results with noise an analyst has to learn to skip.
const FIRST_USER_RECORD: u64 = 16;

/// Cap on path reconstruction. A parent chain longer than this means the chain
/// has looped through a reused record, not that the directory is 64 deep.
const MAX_PATH_DEPTH: usize = 64;

/// Bytes read back per extent when checking a run list is readable. The check
/// is a sample, not a full read: verifying every byte of every candidate would
/// re-read the whole volume, and the head of a run is where a reallocated or
/// unreadable cluster shows first.
const PROBE_BYTES: usize = 4096;

/// NTFS geometry, from the boot sector.
#[derive(Debug, Clone, Copy)]
pub struct Geometry {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub total_sectors: u64,
    pub mft_cluster: u64,
    pub record_size: u32,
    /// Byte offset of the volume within the source.
    pub base: u64,
}

impl Geometry {
    pub fn cluster_size(&self) -> u64 {
        self.bytes_per_sector as u64 * self.sectors_per_cluster as u64
    }

    /// Byte offset of a cluster, in source coordinates.
    pub fn cluster_offset(&self, lcn: u64) -> u64 {
        self.base + lcn * self.cluster_size()
    }
}

/// Read and validate an NTFS boot sector at `base`.
///
/// Returns `Ok(None)` when there is simply no NTFS here, which is the ordinary
/// case for most offsets a scan probes; `Err` is reserved for a boot sector that
/// says NTFS and then contradicts itself.
pub fn probe(source: &mut dyn Source, base: u64) -> Result<Option<Geometry>> {
    let mut boot = [0u8; 512];
    if source.read_at(base, &mut boot)? < 512 {
        return Ok(None);
    }
    if &boot[3..11] != b"NTFS    " {
        return Ok(None);
    }

    let bytes_per_sector = u16le(&boot, 0x0B).unwrap_or(0) as u32;
    // Sector sizes outside this range are not NTFS; a garbage value here would
    // otherwise turn into a multi-terabyte read below.
    if !(256..=8192).contains(&bytes_per_sector) || !bytes_per_sector.is_power_of_two() {
        bail!("NTFS signature at offset {base} with an impossible sector size {bytes_per_sector}");
    }
    let sectors_per_cluster = match boot[0x0D] as i8 {
        // Since Windows 10, a negative value is 2^-n rather than a count.
        n if n < 0 => 1u32 << (-(n as i32) as u32).min(31),
        n => n as u32,
    };
    if sectors_per_cluster == 0 {
        bail!("NTFS at offset {base} declares zero sectors per cluster");
    }

    // Bytes per record when negative (2^-n), clusters per record when positive.
    let record_size = match boot[0x38] as i8 {
        n if n < 0 => 1u32 << (-(n as i32) as u32).min(31),
        n => n as u32 * bytes_per_sector * sectors_per_cluster,
    };
    if !(256..=65536).contains(&record_size) {
        bail!("NTFS at offset {base} declares an impossible MFT record size {record_size}");
    }

    Ok(Some(Geometry {
        bytes_per_sector,
        sectors_per_cluster,
        total_sectors: u64le(&boot, 0x28).unwrap_or(0),
        mft_cluster: u64le(&boot, 0x30).unwrap_or(0),
        record_size,
        base,
    }))
}

/// Apply the update sequence array in place.
///
/// NTFS stores a two-byte sequence number at the end of every sector of a
/// record and keeps the displaced originals in an array in the header. A record
/// whose sector-tail numbers do not all match the header's is a torn write, and
/// this reports it rather than repairing over it: half a record from before a
/// crash and half from after is not a file.
fn apply_fixups(buf: &mut [u8], bytes_per_sector: usize) -> Result<()> {
    let usa_offset = u16le(buf, 0x04).context("record too short for a fixup offset")? as usize;
    let usa_count = u16le(buf, 0x06).context("record too short for a fixup count")? as usize;
    if usa_count == 0 {
        bail!("record declares no update sequence");
    }
    let sectors = usa_count - 1;
    if usa_offset + usa_count * 2 > buf.len() || sectors * bytes_per_sector > buf.len() {
        bail!("update sequence array does not fit the record");
    }
    let expect = u16le(buf, usa_offset).expect("bounds checked above");
    for i in 0..sectors {
        let tail = (i + 1) * bytes_per_sector - 2;
        let found = u16le(buf, tail).expect("bounds checked above");
        if found != expect {
            bail!("fixup mismatch in sector {i}: torn or overwritten record");
        }
        let replacement = &buf[usa_offset + 2 + i * 2..usa_offset + 4 + i * 2].to_vec();
        buf[tail..tail + 2].copy_from_slice(replacement);
    }
    Ok(())
}

/// A decoded run list entry.
#[derive(Debug, Clone, Copy)]
struct Run {
    lcn: Option<u64>,
    clusters: u64,
}

/// Decode an NTFS run list.
///
/// Each entry is a header byte splitting into two nibbles — the byte width of
/// the length field and of the signed LCN delta — followed by those fields. A
/// zero-width delta is a sparse run: a hole, with no clusters behind it. Returns
/// what it decoded up to the first malformed entry, because a run list truncated
/// by damage still describes the beginning of the file.
fn decode_runs(bytes: &[u8]) -> (Vec<Run>, Option<String>) {
    let mut runs = Vec::new();
    let mut lcn: i64 = 0;
    let mut i = 0;
    while i < bytes.len() {
        let header = bytes[i];
        if header == 0 {
            return (runs, None);
        }
        let len_size = (header & 0x0F) as usize;
        let off_size = ((header >> 4) & 0x0F) as usize;
        if len_size == 0 || len_size > 8 || off_size > 8 {
            return (runs, Some(format!("malformed run header {header:#04x}")));
        }
        if i + 1 + len_size + off_size > bytes.len() {
            return (runs, Some("run list truncated".into()));
        }
        let mut clusters: u64 = 0;
        for (b, byte) in bytes[i + 1..i + 1 + len_size].iter().enumerate() {
            clusters |= (*byte as u64) << (8 * b);
        }
        i += 1 + len_size;

        if off_size == 0 {
            // Sparse: no LCN, and the current LCN does not advance.
            runs.push(Run {
                lcn: None,
                clusters,
            });
            continue;
        }
        // Sign-extend the little-endian delta from its declared width.
        let mut delta: i64 = 0;
        for (b, byte) in bytes[i..i + off_size].iter().enumerate() {
            delta |= (*byte as i64) << (8 * b);
        }
        let sign_bit = 1i64 << (off_size * 8 - 1);
        if delta & sign_bit != 0 {
            delta -= sign_bit << 1;
        }
        i += off_size;

        lcn += delta;
        if lcn < 0 {
            return (
                runs,
                Some("run list points before the start of the volume".into()),
            );
        }
        runs.push(Run {
            lcn: Some(lcn as u64),
            clusters,
        });
    }
    (runs, None)
}

/// One `$FILE_NAME` attribute.
struct FileName {
    parent: u64,
    name: String,
    /// 2 is the 8.3 DOS name, which is a duplicate of a longer name elsewhere on
    /// the same record and is only used when nothing better is present.
    namespace: u8,
}

/// A parsed MFT record, before path reconstruction.
struct Record {
    number: u64,
    in_use: bool,
    is_directory: bool,
    names: Vec<FileName>,
    created: Option<String>,
    modified: Option<String>,
    accessed: Option<String>,
    /// Unnamed `$DATA` only: alternate data streams are a separate concern and
    /// exporting one under the file's own name would misrepresent it.
    data: Option<DataAttr>,
}

struct DataAttr {
    resident: Option<Vec<u8>>,
    runs: Vec<Run>,
    real_size: u64,
    flags: u16,
    run_problem: Option<String>,
}

impl Record {
    /// The name to use: the Win32 or POSIX name in preference to the 8.3 alias.
    fn best_name(&self) -> Option<&FileName> {
        self.names
            .iter()
            .find(|n| n.namespace != 2)
            .or_else(|| self.names.first())
    }
}

/// Parse one MFT record from a fixed-up buffer.
fn parse_record(buf: &[u8], number: u64) -> Result<Option<Record>> {
    if &buf[0..4] != b"FILE" {
        // BAAD, or a slot never written. Not an error: most of a fresh MFT is
        // exactly this.
        return Ok(None);
    }
    let flags = u16le(buf, 0x16).context("record too short for flags")?;
    let first_attr = u16le(buf, 0x14).context("record too short for an attribute offset")? as usize;
    let used = u32le(buf, 0x18).context("record too short for a used size")? as usize;
    let limit = used.min(buf.len());

    let mut rec = Record {
        number,
        in_use: flags & RECORD_IN_USE != 0,
        is_directory: flags & RECORD_IS_DIRECTORY != 0,
        names: Vec::new(),
        created: None,
        modified: None,
        accessed: None,
        data: None,
    };

    let mut at = first_attr;
    while at + 4 <= limit {
        let attr_type = u32le(buf, at).unwrap_or(ATTR_END);
        if attr_type == ATTR_END {
            break;
        }
        let attr_len = u32le(buf, at + 4).unwrap_or(0) as usize;
        // A zero or unaligned length would loop forever; stop rather than spin.
        if attr_len < 16 || at + attr_len > limit {
            break;
        }
        let non_resident = buf[at + 8] != 0;
        let name_len = buf[at + 9] as usize;
        let attr_flags = u16le(buf, at + 0x0C).unwrap_or(0);

        match attr_type {
            ATTR_STANDARD_INFORMATION if !non_resident => {
                if let Some(v) = resident_value(buf, at, attr_len) {
                    rec.created = u64le(v, 0x00).and_then(filetime_to_rfc3339);
                    rec.modified = u64le(v, 0x08).and_then(filetime_to_rfc3339);
                    rec.accessed = u64le(v, 0x18).and_then(filetime_to_rfc3339);
                }
            }
            ATTR_FILE_NAME if !non_resident => {
                if let Some(v) = resident_value(buf, at, attr_len) {
                    if let Some(fname) = parse_file_name(v) {
                        rec.names.push(fname);
                    }
                }
            }
            // Unnamed $DATA is the file's contents. A named one is an alternate
            // data stream; skipped deliberately, see the struct comment.
            ATTR_DATA if name_len == 0 => {
                rec.data = Some(if non_resident {
                    let runs_at = u16le(buf, at + 0x20).unwrap_or(0) as usize;
                    let real_size = u64le(buf, at + 0x30).unwrap_or(0);
                    let (runs, run_problem) = if runs_at < attr_len {
                        decode_runs(&buf[at + runs_at..at + attr_len])
                    } else {
                        (
                            Vec::new(),
                            Some("run list offset past the attribute".into()),
                        )
                    };
                    DataAttr {
                        resident: None,
                        runs,
                        real_size,
                        flags: attr_flags,
                        run_problem,
                    }
                } else {
                    let value = resident_value(buf, at, attr_len).unwrap_or(&[]).to_vec();
                    DataAttr {
                        real_size: value.len() as u64,
                        resident: Some(value),
                        runs: Vec::new(),
                        flags: attr_flags,
                        run_problem: None,
                    }
                });
            }
            _ => {}
        }
        at += attr_len;
    }
    Ok(Some(rec))
}

fn resident_value(buf: &[u8], at: usize, attr_len: usize) -> Option<&[u8]> {
    let value_len = u32le(buf, at + 0x10)? as usize;
    let value_at = u16le(buf, at + 0x14)? as usize;
    if value_at + value_len > attr_len {
        return None;
    }
    buf.get(at + value_at..at + value_at + value_len)
}

fn parse_file_name(v: &[u8]) -> Option<FileName> {
    let parent = u64le(v, 0)? & 0x0000_FFFF_FFFF_FFFF;
    let chars = *v.get(0x40)? as usize;
    let namespace = *v.get(0x41)?;
    let raw = v.get(0x42..0x42 + chars * 2)?;
    // `as_chunks` over `chunks_exact`: the pair arrives as a [u8; 2] the
    // compiler already knows the length of, so there is no indexing to get
    // wrong and no remainder branch to forget.
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
        .collect();
    Some(FileName {
        parent,
        // NTFS names are UTF-16 but are not required to be well-formed; a lone
        // surrogate in a filename is a real thing on real disks and must not
        // lose the rest of the name.
        name: String::from_utf16_lossy(&units),
        namespace,
    })
}

/// Everything an NTFS pass found.
pub struct Scan {
    pub files: Vec<RecoveredFile>,
    pub unsupported: Vec<String>,
    pub notes: Vec<String>,
}

/// Parse the MFT at `geometry` and return every recoverable user file.
///
/// `deleted_only` restricts results to records whose in-use bit is clear, which
/// is the usual reason to run this: live files are readable through the OS.
pub fn recover(source: &mut dyn Source, geometry: &Geometry, deleted_only: bool) -> Result<Scan> {
    let record_size = geometry.record_size as usize;
    let sector = geometry.bytes_per_sector as usize;

    // Record 0 is $MFT itself. Its own run list is what says where the rest of
    // the table lives, so it is read from the boot sector's cluster pointer and
    // everything after it is read through the runs it declares.
    let mft_offset = geometry.cluster_offset(geometry.mft_cluster);
    let mut first = source
        .read_exact_at(mft_offset, record_size)
        .context("read the first MFT record")?;
    apply_fixups(&mut first, sector).context("apply fixups to the first MFT record")?;
    let mft_record = parse_record(&first, 0)?
        .context("the first MFT record is not a FILE record; this is not a usable NTFS volume")?;
    let mft_runs = mft_record
        .data
        .as_ref()
        .map(|d| d.runs.clone())
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| {
            // A resident or unreadable $MFT $DATA should not happen; fall back to
            // walking forward from the boot sector's pointer so a damaged volume
            // still yields the records that are there.
            vec![Run {
                lcn: Some(geometry.mft_cluster),
                clusters: u64::MAX / geometry.cluster_size().max(1),
            }]
        });

    let mut unsupported = Vec::new();
    let mut notes = Vec::new();
    let mut records: Vec<Record> = Vec::new();
    let mut number: u64 = 0;
    let mut torn = 0u64;

    'runs: for run in &mft_runs {
        let Some(lcn) = run.lcn else {
            // A sparse run inside $MFT means those record slots were never
            // allocated. Skip the numbers rather than the bytes.
            number += run.clusters * geometry.cluster_size() / record_size as u64;
            continue;
        };
        let start = geometry.cluster_offset(lcn);
        let span = run.clusters.saturating_mul(geometry.cluster_size());
        let mut at = start;
        while at + record_size as u64 <= start.saturating_add(span) {
            if at >= source.size() {
                break 'runs;
            }
            let mut buf = vec![0u8; record_size];
            if source.read_at(at, &mut buf)? < record_size {
                break 'runs;
            }
            if &buf[0..4] == b"FILE" {
                match apply_fixups(&mut buf, sector) {
                    Ok(()) => {
                        if let Some(r) = parse_record(&buf, number)? {
                            records.push(r);
                        }
                    }
                    Err(_) => torn += 1,
                }
            }
            at += record_size as u64;
            number += 1;
        }
    }

    if torn > 0 {
        notes.push(format!(
            "{torn} MFT record(s) failed their fixup check and were skipped as torn writes"
        ));
    }

    // Directory table for path reconstruction, built from every record seen —
    // including deleted directories, whose names are exactly what makes a
    // deleted file's original path recoverable.
    let dirs: HashMap<u64, (u64, String)> = records
        .iter()
        .filter(|r| r.is_directory)
        .filter_map(|r| {
            let n = r.best_name()?;
            Some((r.number, (n.parent, n.name.clone())))
        })
        .collect();

    let mut files = Vec::new();
    let mut compressed = 0u64;
    for rec in &records {
        if rec.is_directory || rec.number < FIRST_USER_RECORD {
            continue;
        }
        if deleted_only && rec.in_use {
            continue;
        }
        let Some(name) = rec.best_name() else {
            continue;
        };
        let Some(data) = &rec.data else { continue };

        if data.flags & FLAG_COMPRESSED != 0 {
            compressed += 1;
        }

        let path = build_path(&dirs, name.parent, &name.name);
        let file = assemble(source, geometry, rec, name, data, &path)?;
        files.push(file);
    }

    if compressed > 0 {
        unsupported.push(format!(
            "NTFS-compressed $DATA on {compressed} file(s): the clusters are located but not \
             decompressed, so those files are capped at Medium and export as compressed data"
        ));
    }

    Ok(Scan {
        files,
        unsupported,
        notes,
    })
}

/// Walk parent references up to the root, longest-first.
fn build_path(dirs: &HashMap<u64, (u64, String)>, parent: u64, name: &str) -> String {
    let mut parts = vec![name.to_string()];
    let mut at = parent;
    let mut depth = 0;
    while at != ROOT_RECORD && depth < MAX_PATH_DEPTH {
        let Some((next, dir_name)) = dirs.get(&at) else {
            // The parent directory's record has been reused. The file is still
            // recoverable; its full path is not, and saying so beats inventing
            // one.
            parts.push("<unknown>".into());
            break;
        };
        parts.push(dir_name.clone());
        at = *next;
        depth += 1;
    }
    parts.reverse();
    parts.join("/")
}

/// Turn a record into a result, scoring it against what the media actually
/// gives back.
fn assemble(
    source: &mut dyn Source,
    geometry: &Geometry,
    rec: &Record,
    name: &FileName,
    data: &DataAttr,
    path: &str,
) -> Result<RecoveredFile> {
    let mut checks = Vec::new();
    let deleted = !rec.in_use;

    checks.push(if deleted {
        Check::fail(
            "mft_entry_in_use",
            "record is marked deleted; its clusters are free and may have been reallocated",
        )
    } else {
        Check::pass("mft_entry_in_use", "record is live in the MFT")
    });

    let encrypted = (data.flags & FLAG_ENCRYPTED != 0).then(|| {
        "EFS-encrypted $DATA: contents are ciphertext and no key recovery is implemented"
            .to_string()
    });
    let compressed = data.flags & FLAG_COMPRESSED != 0;
    let sparse = data.flags & FLAG_SPARSE != 0;

    // Extents, in source coordinates, clipped to the declared file size so a
    // 4 KiB file in a 64 KiB allocation exports as 4 KiB.
    let mut extents = Vec::new();
    let mut remaining = data.real_size;
    let mut holes = 0u64;
    if let Some(bytes) = &data.resident {
        // Resident data lives inside the MFT record, which this parser has
        // already read. Recorded as a zero-length extent list and re-read at
        // export from the record; see `crate::export`.
        checks.push(Check::pass(
            "data_resident",
            format!(
                "{} byte(s) stored inside the MFT record itself",
                bytes.len()
            ),
        ));
    } else {
        for run in &data.runs {
            if remaining == 0 {
                break;
            }
            let span = run
                .clusters
                .saturating_mul(geometry.cluster_size())
                .min(remaining);
            match run.lcn {
                Some(lcn) => extents.push(Extent {
                    offset: geometry.cluster_offset(lcn),
                    length: span,
                }),
                None => holes += span,
            }
            remaining -= span;
        }
    }

    if let Some(p) = &data.run_problem {
        checks.push(Check::fail("run_list_complete", p.clone()));
    } else if data.resident.is_none() {
        checks.push(Check::pass(
            "run_list_complete",
            format!(
                "{} run(s) decoded to the declared end of the file",
                data.runs.len()
            ),
        ));
    }

    // Allocation short of the declared size means the run list no longer
    // describes the whole file.
    let mapped: u64 = extents.iter().map(|e| e.length).sum::<u64>() + holes;
    let covered = data.resident.is_some() || mapped >= data.real_size;
    checks.push(if covered {
        Check::pass(
            "allocation_covers_size",
            format!("{mapped} byte(s) mapped for a {} byte file", data.real_size),
        )
    } else {
        Check::fail(
            "allocation_covers_size",
            format!(
                "only {mapped} of {} byte(s) are mapped; the tail of the file is unrecoverable",
                data.real_size
            ),
        )
    });

    if holes > 0 {
        checks.push(Check::fail(
            "no_sparse_holes",
            format!("{holes} byte(s) are sparse and will export as zeroes"),
        ));
    }

    // Do the extents actually read? A run list pointing past the end of the
    // volume, or at a region the media will not return, is the common failure
    // on a damaged image and is invisible until something tries.
    let mut unreadable = 0u64;
    let mut in_range = true;
    for e in &extents {
        if e.offset + e.length > source.size() {
            in_range = false;
        }
        let probe = (e.length as usize).min(PROBE_BYTES);
        let mut buf = vec![0u8; probe];
        match source.read_at(e.offset, &mut buf) {
            Ok(n) if n == probe => {}
            _ => unreadable += 1,
        }
    }
    checks.push(if !in_range {
        Check::fail(
            "extents_within_source",
            "at least one run points past the end of the image; the image may be truncated",
        )
    } else if unreadable > 0 {
        Check::fail(
            "extents_readable",
            format!(
                "{unreadable} of {} extent(s) would not read back",
                extents.len()
            ),
        )
    } else if extents.is_empty() && data.resident.is_none() {
        Check::fail("extents_readable", "the file has no readable allocation")
    } else {
        Check::pass(
            "extents_readable",
            format!("{} extent(s) sampled and readable", extents.len()),
        )
    });

    if compressed {
        checks.push(Check::fail(
            "data_uncompressed",
            "the $DATA attribute is NTFS-compressed; this build does not decompress it",
        ));
    }
    if let Some(e) = &encrypted {
        checks.push(Check::fail("data_unencrypted", e.clone()));
    }
    if sparse {
        checks.push(Check::pass(
            "sparse_flag",
            "the file is marked sparse; unallocated ranges are legitimately empty",
        ));
    }

    // Scoring. The one rule that matters: a deleted file never reaches High.
    // Its clusters are free, so a clean read proves the bytes are readable, not
    // that they are still this file's bytes — and that distinction is the whole
    // difference between evidence and a coincidence.
    let readable = unreadable == 0 && in_range;
    let (confidence, summary) = if encrypted.is_some() {
        (
            Confidence::Medium,
            "MFT metadata intact, but the contents are EFS-encrypted and are exported as \
             ciphertext"
                .to_string(),
        )
    } else if !covered || !readable || data.run_problem.is_some() {
        (
            Confidence::Medium,
            "MFT metadata found, but the allocation is incomplete or does not read back cleanly"
                .to_string(),
        )
    } else if compressed {
        (
            Confidence::Medium,
            "MFT metadata intact and the clusters read back, but the data is compressed and this \
             build exports it undecompressed"
                .to_string(),
        )
    } else if deleted {
        (
            Confidence::Medium,
            "MFT record intact and every extent reads back, but the record is deleted: the \
             clusters are free and may since have been reallocated to another file"
                .to_string(),
        )
    } else {
        (
            Confidence::High,
            "live MFT record, complete run list, every extent read back cleanly".to_string(),
        )
    };

    let file_type = extension_of(&name.name);
    Ok(RecoveredFile {
        id: format!("ntfs-{:06}", rec.number),
        method: Method::NtfsMft,
        original_path: Some(path.to_string()),
        export_name: name.name.clone(),
        file_type,
        size: data.real_size,
        extents,
        created_utc: rec.created.clone(),
        modified_utc: rec.modified.clone(),
        accessed_utc: rec.accessed.clone(),
        deleted,
        encrypted,
        artifact: None,
        content: crate::results::Content::Full,
        timestamp_source: Some("filesystem metadata (NTFS MFT record)".into()),
        rationale: Rationale {
            confidence,
            summary,
            checks,
        },
    })
}

// ---------------------------------------------------------------------------
// Deep scan: journal mining
// ---------------------------------------------------------------------------
//
// What the MFT holds is the volume as it is now. What the journals hold is what
// the volume did — and a record of a delete survives the file's data, the file's
// MFT record, and often the reuse of both. Mining them recovers no file content
// at all; it recovers the fact that a file of a given name existed at a given
// time and what happened to it. On a drive that has been in use since, that is
// frequently the only thing left, and it is often older than anything the
// standard scan can produce.

/// Bytes read at a time when sweeping a volume for journal records.
const JOURNAL_CHUNK: usize = 4 * 1024 * 1024;

/// A USN record header is 60 bytes before the name; nothing shorter is one, and
/// a record claiming more than this is not one either.
const USN_HEADER: usize = 60;
const USN_MAX_RECORD: u32 = 1024;

/// MFT record number of `$LogFile`.
const LOGFILE_RECORD: u64 = 2;
/// MFT record number of `$MFTMirr`.
const MFTMIRR_RECORD: u64 = 1;

/// How many distinct names each mining pass will hold. A volume with a long
/// journal history can carry hundreds of thousands of them, and an unbounded map
/// is how a deep scan of a large drive turns into an out-of-memory kill three
/// hours in.
// ponytail: a flat cap that stops collecting once reached. If a case ever needs
// the whole of a very long journal, spill to a temporary index instead of
// raising this.
const MAX_JOURNAL_ENTRIES: usize = 200_000;

/// What the journals said about one name.
struct JournalEntry {
    name: String,
    /// Oldest timestamp seen for it — the answer to "how far back".
    oldest: String,
    newest: String,
    /// Union of the USN reason flags seen across every record for this name.
    reasons: u32,
    records: u32,
}

/// Mine `$UsnJrnl` and `$LogFile` for historical file operations.
///
/// Both are swept by content rather than by walking `$Extend` to the journal's
/// own data stream. That is deliberate: the interesting records are the ones
/// whose stream has since been trimmed and whose pages are now unallocated
/// space, and those are unreachable from any structure that still points at
/// anything. Every candidate is validated hard enough that a false positive has
/// to be a byte sequence that is a well-formed record, with a name and four
/// timestamps inside living memory.
///
/// Everything returned is metadata-only: there is no file content in a journal
/// record and none is claimed.
pub fn mine_journals(
    source: &mut dyn Source,
    geometry: &Geometry,
    cancel: &AtomicBool,
) -> Result<(Vec<RecoveredFile>, Vec<String>)> {
    let mut notes = Vec::new();
    let mut out = Vec::new();

    let volume = volume_extent(source, geometry);
    let usn = sweep_usn(source, volume, cancel)?;
    notes.push(format!(
        "USN journal: {} record(s) across the volume, {} distinct name(s)",
        usn.values().map(|e| e.records as u64).sum::<u64>(),
        usn.len()
    ));
    for (key, entry) in usn {
        out.push(usn_result(out.len(), key, &entry));
    }

    match system_file_extents(source, geometry, LOGFILE_RECORD) {
        Ok(extents) if !extents.is_empty() => {
            let (found, pages) = sweep_logfile(source, &extents, cancel)?;
            notes.push(format!(
                "$LogFile: {pages} log page(s) read, {} distinct file name(s) recovered from \
                 transaction records",
                found.len()
            ));
            for ((parent, name), times) in found {
                out.push(logfile_result(out.len(), parent, &name, &times));
            }
        }
        Ok(_) => notes.push("$LogFile: the record maps no data; nothing to mine".into()),
        Err(e) => notes.push(format!("$LogFile: not mined ({e:#})")),
    }

    Ok((out, notes))
}

/// The volume's own extent within the source, as far as the boot sector says.
fn volume_extent(source: &dyn Source, geometry: &Geometry) -> Extent {
    let declared = geometry
        .total_sectors
        .saturating_mul(geometry.bytes_per_sector as u64);
    let available = source.size().saturating_sub(geometry.base);
    Extent {
        offset: geometry.base,
        length: if declared == 0 {
            available
        } else {
            declared.min(available)
        },
    }
}

/// Sweep an extent for USN_RECORD_V2 structures.
///
/// Keyed by file reference and name together, because a reference is reused
/// once the record slot is and two different files can share one. Each key keeps
/// the oldest and newest times seen and the union of the reasons, so a file with
/// four hundred journal entries is one line in the results rather than four
/// hundred.
fn sweep_usn(
    source: &mut dyn Source,
    within: Extent,
    cancel: &AtomicBool,
) -> Result<BTreeMap<(u64, String), JournalEntry>> {
    let mut found: BTreeMap<(u64, String), JournalEntry> = BTreeMap::new();
    let mut buf = vec![0u8; JOURNAL_CHUNK + USN_MAX_RECORD as usize];
    let end = within.offset.saturating_add(within.length);
    let mut at = within.offset;

    while at < end {
        if cancel.load(Ordering::Relaxed) || found.len() >= MAX_JOURNAL_ENTRIES {
            break;
        }
        let want = buf.len().min((end - at) as usize);
        let n = source.read_at(at, &mut buf[..want])?;
        if n == 0 {
            break;
        }
        let window = &buf[..n];
        // Records are 8-aligned within the journal stream, and the stream
        // itself starts on a page boundary, so only 8-aligned offsets are
        // candidates. That removes seven eighths of the work and, with it,
        // seven eighths of the chances of a false positive.
        for i in (0..n.saturating_sub(USN_HEADER)).step_by(8) {
            let Some((reference, name, timestamp, reason)) = parse_usn(&window[i..]) else {
                continue;
            };
            if found.len() >= MAX_JOURNAL_ENTRIES {
                break;
            }
            let entry = found
                .entry((reference, name.clone()))
                .or_insert_with(|| JournalEntry {
                    name,
                    oldest: timestamp.clone(),
                    newest: timestamp.clone(),
                    reasons: 0,
                    records: 0,
                });
            if timestamp < entry.oldest {
                entry.oldest = timestamp.clone();
            }
            if timestamp > entry.newest {
                entry.newest = timestamp;
            }
            entry.reasons |= reason;
            entry.records += 1;
        }
        // Overlap by one maximum record so a record straddling the boundary is
        // seen whole by the next window. A window too short to overlap is the
        // last one, and advancing by all of it ends the loop rather than
        // re-reading the same bytes for ever.
        at += if n > USN_MAX_RECORD as usize {
            (n - USN_MAX_RECORD as usize) as u64
        } else {
            n as u64
        };
    }
    Ok(found)
}

/// Validate and read one USN_RECORD_V2 at the head of `b`.
fn parse_usn(b: &[u8]) -> Option<(u64, String, String, u32)> {
    let length = u32le(b, 0)?;
    if length < USN_HEADER as u32 || length > USN_MAX_RECORD || length % 8 != 0 {
        return None;
    }
    // Only version 2. Version 3 and 4 exist, carry 128-bit identifiers and a
    // different layout, and are not what a volume's $J stream is written in.
    if u16le(b, 4)? != 2 || u16le(b, 6)? != 0 {
        return None;
    }
    let name_length = u16le(b, 56)? as usize;
    let name_at = u16le(b, 58)? as usize;
    if name_at != USN_HEADER || name_length == 0 || name_length % 2 != 0 {
        return None;
    }
    if name_at + name_length > length as usize || name_at + name_length > b.len() {
        return None;
    }
    let timestamp = filetime_to_rfc3339(u64le(b, 32)?)?;
    if !crate::deep::plausible_timestamp(&timestamp) {
        return None;
    }
    let reference = u64le(b, 8)? & 0x0000_FFFF_FFFF_FFFF;
    let name = utf16_name(&b[name_at..name_at + name_length])?;
    Some((reference, name, timestamp, u32le(b, 40)?))
}

/// Decode a UTF-16LE name, or refuse it.
///
/// A name is the strongest evidence that a candidate structure really is one, so
/// the bar is deliberately high: a run of bytes that decodes to control
/// characters or path separators is not a filename and the structure around it
/// was not a record.
fn utf16_name(raw: &[u8]) -> Option<String> {
    let units: Vec<u16> = raw
        .as_chunks::<2>()
        .0
        .iter()
        .copied()
        .map(u16::from_le_bytes)
        .collect();
    let name = String::from_utf16(&units).ok()?;
    if name.is_empty() || name.chars().count() > 255 {
        return None;
    }
    if name
        .chars()
        .any(|c| c.is_control() || matches!(c, '/' | '\\' | '<' | '>' | '|' | '"' | '*' | '?'))
    {
        return None;
    }
    Some(name)
}

/// USN reason flags, in the order they read best in a sentence.
const USN_REASONS: &[(u32, &str)] = &[
    (0x0000_0100, "created"),
    (0x0000_0200, "deleted"),
    (0x0000_0001, "data overwritten"),
    (0x0000_0002, "data extended"),
    (0x0000_0004, "data truncated"),
    (0x0000_1000, "renamed (old name)"),
    (0x0000_2000, "renamed (new name)"),
    (0x0000_0800, "security changed"),
    (0x0000_8000, "basic info changed"),
    (0x8000_0000, "closed"),
];

fn describe_reasons(reasons: u32) -> String {
    let named: Vec<&str> = USN_REASONS
        .iter()
        .filter(|(bit, _)| reasons & bit != 0)
        .map(|(_, name)| *name)
        .collect();
    if named.is_empty() {
        format!("reason flags 0x{reasons:08X}")
    } else {
        named.join(", ")
    }
}

fn usn_result(index: usize, key: (u64, String), entry: &JournalEntry) -> RecoveredFile {
    let (reference, _) = key;
    let deleted = entry.reasons & 0x0000_0200 != 0;
    let mut f = crate::deep::metadata_record(
        format!("usn-{index:06}"),
        Method::NtfsUsnJournal,
        entry.name.clone(),
        Some(entry.oldest.clone()),
        "USN journal record",
        format!(
            "the USN journal records {} operation(s) on a file named {:?} (MFT reference \
             {reference}) between {} and {}: {}. {}",
            entry.records,
            entry.name,
            entry.oldest,
            entry.newest,
            describe_reasons(entry.reasons),
            if deleted {
                "The journal says it was deleted; whether its data is still on the media is a \
                 separate question this record cannot answer."
            } else {
                "The journal does not record a delete for it within the entries that survive."
            }
        ),
        vec![
            Check::pass(
                "usn_record_valid",
                format!(
                    "{} version 2 record(s) with a consistent length, name offset and timestamp",
                    entry.records
                ),
            ),
            Check::pass(
                "timestamp_from_journal",
                format!(
                    "{} is the earliest time the journal records for this name",
                    entry.oldest
                ),
            ),
            Check::fail(
                "path_reconstructed",
                "a USN record names the file and its parent's reference number, not its path. The \
                 parent's own record has usually been reused by the time the child's data is \
                 gone, so no path is claimed here.",
            ),
        ],
    );
    f.deleted = deleted;
    f.accessed_utc = Some(entry.newest.clone());
    f
}

/// The four `$FILE_NAME` timestamps, in the order the attribute stores them.
struct FileNameTimes {
    created: String,
    modified: String,
}

/// Sweep `$LogFile` pages for `$FILE_NAME` attribute residues.
///
/// NTFS logs the before and after image of every metadata change, so a
/// `$FILE_NAME` attribute written during a create, a rename or a delete sits in
/// the log independently of the MFT record it belonged to. Once that record is
/// reused the log page is the only place the old name and its timestamps still
/// exist.
fn sweep_logfile(
    source: &mut dyn Source,
    extents: &[Extent],
    cancel: &AtomicBool,
) -> Result<(BTreeMap<(u64, String), FileNameTimes>, u64)> {
    let mut found: BTreeMap<(u64, String), FileNameTimes> = BTreeMap::new();
    let mut pages = 0u64;
    let mut buf = vec![0u8; JOURNAL_CHUNK];

    for extent in extents {
        let end = extent.offset.saturating_add(extent.length);
        let mut at = extent.offset;
        while at < end {
            if cancel.load(Ordering::Relaxed) || found.len() >= MAX_JOURNAL_ENTRIES {
                break;
            }
            let want = buf.len().min((end - at) as usize);
            let n = source.read_at(at, &mut buf[..want])?;
            if n == 0 {
                break;
            }
            let window = &buf[..n];
            pages += window
                .as_chunks::<4>()
                .0
                .iter()
                .filter(|w| *w == b"RCRD" || *w == b"RSTR")
                .count() as u64;
            // $FILE_NAME attributes are 8-aligned within a log record's redo
            // and undo data, the same as everywhere else in NTFS.
            for i in (0..n.saturating_sub(0x42)).step_by(8) {
                if found.len() >= MAX_JOURNAL_ENTRIES {
                    break;
                }
                let Some((parent, name, times)) = parse_file_name_residue(&window[i..]) else {
                    continue;
                };
                let seen = found.entry((parent, name)).or_insert(FileNameTimes {
                    created: times.created.clone(),
                    modified: times.modified.clone(),
                });
                if times.created < seen.created {
                    seen.created = times.created;
                }
                if times.modified > seen.modified {
                    seen.modified = times.modified;
                }
            }
            at += n as u64;
        }
    }
    Ok((found, pages))
}

/// Validate and read a `$FILE_NAME` attribute body at the head of `b`.
///
/// Four consecutive plausible FILETIMEs, a namespace in range, and a name that
/// decodes cleanly: a run of unrelated bytes satisfying all of those at an
/// 8-byte boundary is not something that happens by accident.
fn parse_file_name_residue(b: &[u8]) -> Option<(u64, String, FileNameTimes)> {
    let namespace = *b.get(0x41)?;
    if namespace > 3 {
        return None;
    }
    let chars = *b.get(0x40)? as usize;
    if chars == 0 || 0x42 + chars * 2 > b.len() {
        return None;
    }
    let parent_raw = u64le(b, 0)?;
    // The top 16 bits are the parent's sequence number. Zero means the field was
    // never a file reference.
    if parent_raw >> 48 == 0 {
        return None;
    }
    let mut times = Vec::with_capacity(4);
    for at in [0x08, 0x10, 0x18, 0x20] {
        let t = filetime_to_rfc3339(u64le(b, at)?)?;
        if !crate::deep::plausible_timestamp(&t) {
            return None;
        }
        times.push(t);
    }
    let name = utf16_name(b.get(0x42..0x42 + chars * 2)?)?;
    Some((
        parent_raw & 0x0000_FFFF_FFFF_FFFF,
        name,
        FileNameTimes {
            created: times[0].clone(),
            modified: times[1].clone(),
        },
    ))
}

fn logfile_result(index: usize, parent: u64, name: &str, times: &FileNameTimes) -> RecoveredFile {
    let mut f = crate::deep::metadata_record(
        format!("logfile-{index:06}"),
        Method::NtfsLogFile,
        name.to_string(),
        Some(times.created.clone()),
        "$LogFile $FILE_NAME record",
        format!(
            "a transaction in $LogFile carries a $FILE_NAME attribute for {name:?} under parent \
             reference {parent}, created {} and last written {}. The MFT record it belonged to no \
             longer presents this name, so the log page is where it survives.",
            times.created, times.modified
        ),
        vec![
            Check::pass(
                "file_name_attribute_valid",
                format!(
                    "four timestamps between {} and {}, a namespace in range, and a name that \
                     decodes as UTF-16",
                    times.created, times.modified
                ),
            ),
            Check::fail(
                "path_reconstructed",
                "the attribute names one parent reference. Resolving it to a path needs that \
                 parent's MFT record, which on a volume where this residue is the last copy of \
                 the name has generally been reused.",
            ),
        ],
    );
    f.created_utc = Some(times.created.clone());
    f.modified_utc = Some(times.modified.clone());
    f
}

// ---------------------------------------------------------------------------
// Deep scan: backup and redundant metadata
// ---------------------------------------------------------------------------

/// Byte extents of a system file's unnamed `$DATA`, by MFT record number.
///
/// Records 0 to 15 are the metadata files and always live in the first run of
/// `$MFT`, so they can be read from the boot sector's pointer without walking
/// the table first.
fn system_file_extents(
    source: &mut dyn Source,
    geometry: &Geometry,
    record_number: u64,
) -> Result<Vec<Extent>> {
    let record_size = geometry.record_size as usize;
    let at = geometry.cluster_offset(geometry.mft_cluster) + record_number * record_size as u64;
    let mut buf = source
        .read_exact_at(at, record_size)
        .with_context(|| format!("read MFT record {record_number}"))?;
    apply_fixups(&mut buf, geometry.bytes_per_sector as usize)
        .with_context(|| format!("apply fixups to MFT record {record_number}"))?;
    let record = parse_record(&buf, record_number)?
        .with_context(|| format!("MFT record {record_number} is not a FILE record"))?;
    let data = record
        .data
        .as_ref()
        .with_context(|| format!("MFT record {record_number} has no unnamed $DATA"))?;

    let mut extents = Vec::new();
    let mut remaining = data.real_size;
    for run in &data.runs {
        if remaining == 0 {
            break;
        }
        let span = run
            .clusters
            .saturating_mul(geometry.cluster_size())
            .min(remaining);
        if let Some(lcn) = run.lcn {
            extents.push(Extent {
                offset: geometry.cluster_offset(lcn),
                length: span,
            });
        }
        remaining -= span;
    }
    Ok(extents)
}

/// Check NTFS's redundant copies of its own metadata: the backup boot sector at
/// the end of the volume, and `$MFTMirr`.
///
/// The mirror holds copies of the first MFT records. Where the primary copy of
/// one of those records no longer reads back as a FILE record — a torn write, a
/// bad sector, a partly overwritten table — the mirror's copy is the only
/// description of that file left, and it is reported as one.
pub fn backup_metadata(
    source: &mut dyn Source,
    geometry: &Geometry,
) -> Result<(Vec<RecoveredFile>, Vec<String>)> {
    let mut notes = Vec::new();
    let mut out = Vec::new();
    let record_size = geometry.record_size as usize;
    let sector = geometry.bytes_per_sector as usize;

    // The backup boot sector is the volume's last sector: total_sectors counts
    // everything before it.
    let backup_at = geometry.base
        + geometry
            .total_sectors
            .saturating_mul(geometry.bytes_per_sector as u64);
    match (
        source.read_exact_at(geometry.base, sector),
        source.read_exact_at(backup_at, sector),
    ) {
        (Ok(primary), Ok(backup)) if &backup[3..11] == b"NTFS    " => {
            notes.push(if primary == backup {
                "backup boot sector: present at the end of the volume and identical to the \
                 primary"
                    .into()
            } else {
                format!(
                    "backup boot sector: present at offset {backup_at} and DIFFERENT from the \
                     primary. One of the two describes a geometry this volume no longer has; the \
                     primary was used for this scan."
                )
            });
        }
        (_, Ok(_)) => notes.push(
            "backup boot sector: the volume's last sector is not an NTFS boot sector. If the \
             primary is ever damaged there is no second copy to fall back on."
                .into(),
        ),
        _ => notes.push("backup boot sector: could not be read".into()),
    }

    match system_file_extents(source, geometry, MFTMIRR_RECORD) {
        Ok(extents) => {
            let mut checked = 0u64;
            let mut rescued = 0u64;
            let mirror_records: u64 = extents.iter().map(|e| e.length).sum::<u64>()
                / record_size.max(1) as u64;
            for index in 0..mirror_records {
                let Some(at) = extent_offset(&extents, index * record_size as u64) else {
                    continue;
                };
                let Ok(mut mirror) = source.read_exact_at(at, record_size) else {
                    continue;
                };
                if apply_fixups(&mut mirror, sector).is_err() {
                    continue;
                }
                let Ok(Some(record)) = parse_record(&mirror, index) else {
                    continue;
                };
                checked += 1;

                // Is the primary copy of the same record readable?
                let primary_at =
                    geometry.cluster_offset(geometry.mft_cluster) + index * record_size as u64;
                let primary_ok = source
                    .read_exact_at(primary_at, record_size)
                    .ok()
                    .and_then(|mut b| {
                        apply_fixups(&mut b, sector).ok()?;
                        parse_record(&b, index).ok().flatten()
                    })
                    .is_some();
                if primary_ok {
                    continue;
                }
                let Some(name) = record.best_name() else {
                    continue;
                };
                rescued += 1;
                out.push(crate::deep::metadata_record(
                    format!("mftmirr-{:06}", out.len()),
                    Method::NtfsMftMirror,
                    name.name.clone(),
                    record.modified.clone(),
                    "$MFTMirr copy of the MFT record",
                    format!(
                        "MFT record {index} does not read back as a FILE record from the primary \
                         table, but $MFTMirr's copy does, and it names {:?}. The mirror is the \
                         only surviving description of this entry.",
                        name.name
                    ),
                    vec![Check::pass(
                        "mirror_record_valid",
                        "the mirror's copy passed its fixup check and parsed as a FILE record \
                         where the primary did not",
                    )],
                ));
            }
            notes.push(format!(
                "$MFTMirr: {checked} mirrored record(s) parsed, {rescued} of which the primary \
                 table no longer holds in readable form"
            ));
        }
        Err(e) => notes.push(format!("$MFTMirr: not read ({e:#})")),
    }

    Ok((out, notes))
}

/// Map a logical offset within a run of extents to a source offset.
fn extent_offset(extents: &[Extent], logical: u64) -> Option<u64> {
    let mut seen = 0u64;
    for e in extents {
        if logical < seen + e.length {
            return Some(e.offset + (logical - seen));
        }
        seen += e.length;
    }
    None
}

/// Lowercase extension, or `bin` when a name carries none. Never guessed from
/// content here: for a metadata-recovered file the name is evidence and the
/// content is not yet read.
pub fn extension_of(name: &str) -> String {
    name.rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .filter(|e| !e.is_empty() && e.len() <= 8 && e.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or_else(|| "bin".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_decode_with_signed_deltas() {
        // 0x21 0x18 0x34 0x12  -> 0x18 clusters at LCN 0x1234
        // 0x11 0x08 0xF0       -> 8 clusters at LCN 0x1234 - 16
        // 0x01 0x04            -> a 4-cluster sparse hole
        // 0x00                 -> end
        let (runs, problem) =
            decode_runs(&[0x21, 0x18, 0x34, 0x12, 0x11, 0x08, 0xF0, 0x01, 0x04, 0x00]);
        assert!(problem.is_none());
        assert_eq!(runs.len(), 3);
        assert_eq!(runs[0].lcn, Some(0x1234));
        assert_eq!(runs[0].clusters, 0x18);
        assert_eq!(runs[1].lcn, Some(0x1234 - 16));
        assert_eq!(runs[2].lcn, None);
        assert_eq!(runs[2].clusters, 4);
    }

    /// A truncated run list must yield the runs it did decode, not nothing: the
    /// head of a damaged file is still worth recovering.
    #[test]
    fn a_truncated_run_list_keeps_what_it_decoded() {
        let (runs, problem) = decode_runs(&[0x21, 0x18, 0x34, 0x12, 0x21, 0x08]);
        assert_eq!(runs.len(), 1);
        assert!(problem.as_deref().unwrap().contains("truncated"));
    }

    #[test]
    fn a_negative_run_before_the_volume_start_is_rejected() {
        let (_, problem) = decode_runs(&[0x11, 0x08, 0x80]);
        assert!(problem.as_deref().unwrap().contains("before the start"));
    }

    #[test]
    fn fixups_are_applied_and_mismatches_refused() {
        let mut buf = vec![0u8; 1024];
        buf[0..4].copy_from_slice(b"FILE");
        buf[0x04..0x06].copy_from_slice(&48u16.to_le_bytes()); // usa offset
        buf[0x06..0x08].copy_from_slice(&3u16.to_le_bytes()); // 1 + 2 sectors
        buf[48..50].copy_from_slice(&0xBEEFu16.to_le_bytes()); // sequence number
        buf[50..52].copy_from_slice(&0x1111u16.to_le_bytes()); // sector 0 original
        buf[52..54].copy_from_slice(&0x2222u16.to_le_bytes()); // sector 1 original
        buf[510..512].copy_from_slice(&0xBEEFu16.to_le_bytes());
        buf[1022..1024].copy_from_slice(&0xBEEFu16.to_le_bytes());

        let mut good = buf.clone();
        apply_fixups(&mut good, 512).unwrap();
        assert_eq!(u16le(&good, 510), Some(0x1111));
        assert_eq!(u16le(&good, 1022), Some(0x2222));

        buf[1022..1024].copy_from_slice(&0xDEADu16.to_le_bytes());
        assert!(apply_fixups(&mut buf, 512).is_err());
    }

    #[test]
    fn extensions_come_off_the_name_only() {
        assert_eq!(extension_of("report.PDF"), "pdf");
        assert_eq!(extension_of("noext"), "bin");
        assert_eq!(extension_of("archive.tar.gz"), "gz");
        // A "." in a directory-ish name must not become a 40-character type.
        assert_eq!(extension_of("x.thisisfartoolongtobeanextension"), "bin");
    }
}
