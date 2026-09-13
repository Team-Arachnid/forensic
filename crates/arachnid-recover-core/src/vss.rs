//! Volume Shadow Copy enumeration.
//!
//! A shadow copy is a second, dated view of a whole NTFS volume. Windows takes
//! them for System Restore, for backup software and for Previous Versions, and
//! it keeps them until the space set aside runs out — which on a lightly-used
//! volume can be months or years. A file that was modified or deleted after a
//! snapshot was taken still exists inside that snapshot, and the snapshot's own
//! creation time is a hard date rather than an inference.
//!
//! That makes the list of snapshots on a volume one of the better answers to
//! "how far back does this go", and it is what this module produces: every
//! store the volume's shadow-copy catalog records, with the point in time it
//! represents.
//!
//! # What this does not do
//!
//! It does not extract files from inside a snapshot. A store's contents are
//! reached through its block descriptors, which overlay ranges of the live
//! volume with the pre-modification copies the store holds; walking that
//! overlay is a second filesystem implementation and this build does not have
//! one. So a snapshot here is reported as a dated point in time that exists on
//! this volume, with the note that reading its contents needs a tool that
//! mounts it — not as a set of recovered files. Saying "found 6 snapshots" and
//! leaving an analyst to believe the files inside them have been recovered
//! would be the worse failure.

use anyhow::Result;

use crate::results::{Check, Method, RecoveredFile};
use crate::source::{u32le, u64le, Source};

/// Byte offset, within an NTFS volume, of the shadow-copy volume header.
const VOLUME_HEADER_OFFSET: u64 = 0x1E00;

/// The GUID every VSS on-disk record starts with:
/// `3808876b-c176-4e48-b7ae-04046e6cc752`, in the mixed-endian layout Windows
/// stores a GUID in.
const VSS_IDENTIFIER: [u8; 16] = [
    0x6b, 0x87, 0x08, 0x38, 0x76, 0xc1, 0x48, 0x4e, 0xb7, 0xae, 0x04, 0x04, 0x6e, 0x6c, 0xc7, 0x52,
];

const RECORD_TYPE_VOLUME_HEADER: u32 = 1;
const RECORD_TYPE_CATALOG: u32 = 2;

const CATALOG_BLOCK_SIZE: usize = 0x4000;
const CATALOG_ENTRIES_AT: usize = 0x80;
const CATALOG_ENTRY_SIZE: usize = 0x80;

/// Catalog entry describing a store — the kind that carries a snapshot's
/// identity and creation time.
const ENTRY_TYPE_STORE: u64 = 2;

/// Stop after this many catalog blocks. The chain is a linked list read off
/// media that may be damaged, and a loop in it would otherwise not end.
const MAX_CATALOG_BLOCKS: usize = 64;

/// One shadow copy, as the catalog records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub store_id: String,
    /// RFC 3339 UTC. `None` when the catalog entry held no timestamp that could
    /// be one — reported as unknown rather than guessed at.
    pub created_utc: Option<String>,
    pub volume_size: u64,
}

/// Enumerate the shadow copies on the NTFS volume at `base`.
///
/// Returns an empty list when there is no shadow-copy volume header, which is
/// the ordinary case: most volumes do not have one.
pub fn enumerate(source: &mut dyn Source, base: u64) -> Result<Vec<Snapshot>> {
    let Ok(header) = source.read_exact_at(base + VOLUME_HEADER_OFFSET, 512) else {
        return Ok(Vec::new());
    };
    if header[0..16] != VSS_IDENTIFIER {
        return Ok(Vec::new());
    }
    if u32le(&header, 0x14) != Some(RECORD_TYPE_VOLUME_HEADER) {
        return Ok(Vec::new());
    }
    let Some(catalog_at) = u64le(&header, 0x38).filter(|o| *o > 0) else {
        return Ok(Vec::new());
    };

    let mut snapshots = Vec::new();
    let mut at = catalog_at;
    let mut seen = Vec::new();
    for _ in 0..MAX_CATALOG_BLOCKS {
        if at == 0 || seen.contains(&at) || base + at >= source.size() {
            break;
        }
        seen.push(at);
        let Ok(block) = source.read_exact_at(base + at, CATALOG_BLOCK_SIZE) else {
            break;
        };
        if block[0..16] != VSS_IDENTIFIER || u32le(&block, 0x14) != Some(RECORD_TYPE_CATALOG) {
            break;
        }
        let mut entry_at = CATALOG_ENTRIES_AT;
        while entry_at + CATALOG_ENTRY_SIZE <= block.len() {
            let entry = &block[entry_at..entry_at + CATALOG_ENTRY_SIZE];
            if u64le(entry, 0) == Some(ENTRY_TYPE_STORE) {
                snapshots.push(Snapshot {
                    store_id: guid(&entry[0x10..0x20]),
                    created_utc: entry_timestamp(entry),
                    volume_size: u64le(entry, 0x08).unwrap_or(0),
                });
            }
            entry_at += CATALOG_ENTRY_SIZE;
        }
        at = u64le(&block, 0x28).unwrap_or(0);
    }

    // Oldest first: the list is most useful in the order that answers the
    // question it is being asked.
    snapshots.sort_by(|a, b| a.created_utc.cmp(&b.created_utc));
    Ok(snapshots)
}

/// Find the snapshot's creation time in a catalog entry.
///
/// The field sits at 0x30 in every catalog this has been read against. Rather
/// than trust that offset blindly against an on-disk format with more than one
/// version in the wild, the value is validated as a real date and, if it is not
/// one, the rest of the entry is searched for a FILETIME that is. An entry that
/// yields no plausible date yields no date: a snapshot reported without a
/// timestamp is honest, and one reported with a date read out of the wrong
/// eight bytes would become the oldest item in the results.
fn entry_timestamp(entry: &[u8]) -> Option<String> {
    let plausible = |at: usize| {
        u64le(entry, at)
            .and_then(crate::results::filetime_to_rfc3339)
            .filter(|t| crate::deep::plausible_timestamp(t))
    };
    plausible(0x30).or_else(|| (0..entry.len().saturating_sub(8)).step_by(8).find_map(plausible))
}

/// Format 16 bytes of mixed-endian GUID the way Windows displays it.
fn guid(b: &[u8]) -> String {
    if b.len() < 16 {
        return "<truncated>".into();
    }
    format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u16::from_le_bytes([b[4], b[5]]),
        u16::from_le_bytes([b[6], b[7]]),
        b[8],
        b[9],
        b[10..16].iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

/// Enumerate and turn each snapshot into a dated, metadata-only result.
pub fn recover(source: &mut dyn Source, base: u64) -> Result<(Vec<RecoveredFile>, Vec<String>)> {
    let snapshots = enumerate(source, base)?;
    if snapshots.is_empty() {
        return Ok((
            Vec::new(),
            vec!["shadow copies: no shadow-copy catalog on this volume".into()],
        ));
    }

    let dated = snapshots.iter().filter(|s| s.created_utc.is_some()).count();
    let note = format!(
        "shadow copies: {} store(s) in the catalog, {dated} with a readable creation time{}",
        snapshots.len(),
        match snapshots.iter().find_map(|s| s.created_utc.as_deref()) {
            Some(oldest) => format!(", oldest {oldest}"),
            None => String::new(),
        }
    );

    let mut out = Vec::new();
    for (i, snap) in snapshots.iter().enumerate() {
        out.push(crate::deep::metadata_record(
            format!("vss-{i:06}"),
            Method::ShadowCopy,
            format!("<shadow copy {}>", snap.store_id),
            snap.created_utc.clone(),
            "shadow copy creation time",
            format!(
                "a Volume Shadow Copy store taken {} covers this {} byte volume. Every file as it \
                 stood at that moment is inside it, including files modified or deleted since. \
                 Reading them needs a tool that mounts the snapshot — this build enumerates the \
                 catalog and does not walk a store's block descriptors, so no file has been \
                 recovered out of it here.",
                snap.created_utc.as_deref().unwrap_or("at an unrecorded time"),
                snap.volume_size
            ),
            vec![
                Check::pass(
                    "catalog_entry_valid",
                    format!("store {} is a type-2 entry in the volume's shadow-copy catalog", snap.store_id),
                ),
                if snap.created_utc.is_some() {
                    Check::pass(
                        "snapshot_time_known",
                        "the entry carries a creation time that is a real date",
                    )
                } else {
                    Check::fail(
                        "snapshot_time_known",
                        "the entry holds no value that reads as a real date, so this snapshot is \
                         reported without one rather than with a guess",
                    )
                },
                Check::fail(
                    "contents_extracted",
                    "the snapshot's files are not extracted by this build; what is recovered here \
                     is the fact that this point in time exists on this volume, and when it is",
                ),
            ],
        ));
    }
    Ok((out, vec![note]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;

    /// FILETIME for 2019-03-04T05:06:07Z, to stand in for a snapshot taken a
    /// few years before the scan.
    const SNAPSHOT_FILETIME: u64 = 116_444_736_000_000_000 + 1_551_675_967 * 10_000_000;

    fn volume_with_catalog() -> Vec<u8> {
        let catalog_at: u64 = 0x10000;
        let mut img = vec![0u8; catalog_at as usize + CATALOG_BLOCK_SIZE];

        let h = VOLUME_HEADER_OFFSET as usize;
        img[h..h + 16].copy_from_slice(&VSS_IDENTIFIER);
        img[h + 0x10..h + 0x14].copy_from_slice(&1u32.to_le_bytes());
        img[h + 0x14..h + 0x18].copy_from_slice(&RECORD_TYPE_VOLUME_HEADER.to_le_bytes());
        img[h + 0x38..h + 0x40].copy_from_slice(&catalog_at.to_le_bytes());

        let c = catalog_at as usize;
        img[c..c + 16].copy_from_slice(&VSS_IDENTIFIER);
        img[c + 0x10..c + 0x14].copy_from_slice(&1u32.to_le_bytes());
        img[c + 0x14..c + 0x18].copy_from_slice(&RECORD_TYPE_CATALOG.to_le_bytes());

        let e = c + CATALOG_ENTRIES_AT;
        img[e..e + 8].copy_from_slice(&ENTRY_TYPE_STORE.to_le_bytes());
        img[e + 0x08..e + 0x10].copy_from_slice(&(512u64 * 1024 * 1024).to_le_bytes());
        img[e + 0x10..e + 0x20].copy_from_slice(&[0xAB; 16]);
        img[e + 0x30..e + 0x38].copy_from_slice(&SNAPSHOT_FILETIME.to_le_bytes());
        img
    }

    #[test]
    fn a_volume_with_no_shadow_copies_enumerates_to_nothing() {
        let mut s = MemorySource::new(vec![0u8; 64 * 1024], "plain");
        assert!(enumerate(&mut s, 0).unwrap().is_empty());
    }

    #[test]
    fn a_catalog_entry_becomes_a_dated_snapshot() {
        let mut s = MemorySource::new(volume_with_catalog(), "vss");
        let snaps = enumerate(&mut s, 0).unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].created_utc.as_deref(), Some("2019-03-04T05:06:07Z"));
        assert_eq!(snaps[0].volume_size, 512 * 1024 * 1024);

        let (files, notes) = recover(&mut s, 0).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].method, Method::ShadowCopy);
        assert_eq!(files[0].derived_timestamp(), Some("2019-03-04T05:06:07Z"));
        assert_eq!(
            files[0].timestamp_source.as_deref(),
            Some("shadow copy creation time")
        );
        // The snapshot is a point in time, not a pile of recovered files, and
        // the result has to say so.
        assert!(files[0].rationale.summary.contains("no file has been recovered"));
        assert!(notes[0].contains("oldest 2019-03-04"));
    }

    /// A catalog entry whose timestamp field holds something that is not a date
    /// must produce a snapshot with no date, never a date from the year 1601.
    #[test]
    fn an_entry_with_no_real_date_is_reported_without_one() {
        let mut img = volume_with_catalog();
        let e = 0x10000 + CATALOG_ENTRIES_AT;
        img[e + 0x30..e + 0x38].copy_from_slice(&7u64.to_le_bytes());
        let mut s = MemorySource::new(img, "vss");
        let snaps = enumerate(&mut s, 0).unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].created_utc, None);
    }

    #[test]
    fn guids_render_the_way_windows_shows_them() {
        let b: Vec<u8> = (0u8..16).collect();
        assert_eq!(guid(&b), "03020100-0504-0706-0809-0a0b0c0d0e0f");
    }
}
