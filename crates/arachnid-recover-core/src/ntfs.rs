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

use std::collections::HashMap;

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
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
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
        rationale: Rationale {
            confidence,
            summary,
            checks,
        },
    })
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
