//! APFS: container and volume identification, and an explicit refusal to
//! pretend at per-file recovery.
//!
//! This is the partial module the suite says it is. Recovering a file from APFS
//! means resolving virtual object IDs through the container object map, walking
//! the volume's file-system B-tree for inode and directory records, then
//! following extent records through the extent-reference tree — with snapshots
//! and clones changing what "the file" even refers to. None of that is
//! implemented here.
//!
//! What is implemented is everything needed to *say so precisely*: the container
//! is parsed, its volumes are found and named, and each one is reported with the
//! feature flags that matter (encryption above all). An operator gets the volume
//! inventory and a clear statement that per-file recovery on this volume is not
//! available in this build, rather than an empty result set that reads like
//! "there was nothing to find".
//!
//! The raw carving pass still works on an APFS container, and is the supported
//! way to recover from one today.

use anyhow::Result;

use crate::results::unix_to_rfc3339;
use crate::source::{u32le, u64le, Source};

/// `NXSB`, at offset 0x20 of the container superblock — after the 32-byte
/// object header every APFS object carries.
const NX_MAGIC: u32 = 0x4253_584E;
/// `APSB`, at the same offset of a volume superblock.
const APSB_MAGIC: u32 = 0x4253_5041;

const OBJ_HEADER: usize = 32;

/// Volume flag: the volume is *not* encrypted. APFS states it this way round,
/// so its absence is what indicates encryption.
const APFS_FS_UNENCRYPTED: u64 = 0x0000_0001;

/// How far a volume-superblock scan will read looking for `APSB` blocks.
///
/// Volume superblocks are reachable properly only through the container object
/// map, which this build does not walk. Scanning for the magic finds them
/// without it, but on a multi-terabyte container an unbounded scan is hours of
/// I/O for an inventory. The bound is reported in the results, so a container
/// larger than this says that its inventory may be incomplete rather than
/// implying it is complete.
const SCAN_LIMIT_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Container {
    pub base: u64,
    pub block_size: u32,
    pub block_count: u64,
    pub incompatible_features: u64,
    pub max_volumes: u32,
    pub volumes: Vec<Volume>,
    /// True when the volume scan hit [`SCAN_LIMIT_BYTES`] before the end of the
    /// container.
    pub scan_truncated: bool,
}

#[derive(Debug, Clone)]
pub struct Volume {
    pub name: String,
    pub index: u32,
    pub files: u64,
    pub directories: u64,
    pub encrypted: bool,
    pub last_modified_utc: Option<String>,
}

/// Read an APFS container superblock at `base`.
pub fn probe(source: &mut dyn Source, base: u64) -> Result<Option<Container>> {
    let mut block = [0u8; 4096];
    if source.read_at(base, &mut block)? < 4096 {
        return Ok(None);
    }
    if u32le(&block, OBJ_HEADER) != Some(NX_MAGIC) {
        return Ok(None);
    }

    let block_size = u32le(&block, OBJ_HEADER + 4).unwrap_or(4096);
    // A block size that is not a sane power of two would turn the scan below
    // into a walk off the end of the source.
    if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() {
        anyhow::bail!(
            "APFS container at offset {base} declares an impossible block size {block_size}"
        );
    }

    let mut container = Container {
        base,
        block_size,
        block_count: u64le(&block, OBJ_HEADER + 8).unwrap_or(0),
        incompatible_features: u64le(&block, OBJ_HEADER + 0x20).unwrap_or(0),
        max_volumes: u32le(&block, OBJ_HEADER + 0x94).unwrap_or(0),
        volumes: Vec::new(),
        scan_truncated: false,
    };

    let (volumes, truncated) = scan_volumes(source, &container)?;
    container.volumes = volumes;
    container.scan_truncated = truncated;
    Ok(Some(container))
}

/// Find volume superblocks by their magic.
///
/// The proper route is `nx_fs_oid[]` through the container object map; those are
/// virtual OIDs, and resolving one means walking a B-tree this build does not
/// implement. Scanning for `APSB` reaches the same blocks without it. It is a
/// heuristic, and it is bounded — both facts are reported, not buried.
fn scan_volumes(source: &mut dyn Source, container: &Container) -> Result<(Vec<Volume>, bool)> {
    let block_size = container.block_size as u64;
    let limit = source.size().min(container.base + SCAN_LIMIT_BYTES).min(
        container.base
            + container
                .block_count
                .saturating_mul(block_size)
                .max(block_size),
    );
    let truncated = limit < container.base + container.block_count.saturating_mul(block_size);

    let mut volumes = Vec::new();
    let mut at = container.base;
    let mut buf = vec![0u8; block_size as usize];
    while at + block_size <= limit {
        if source.read_at(at, &mut buf)? < block_size as usize {
            break;
        }
        if u32le(&buf, OBJ_HEADER) == Some(APSB_MAGIC) {
            if let Some(v) = parse_volume(&buf) {
                // The same volume superblock is written once per checkpoint, so
                // the scan sees several copies. Keep the first of each index:
                // for an inventory, one row per volume is the answer.
                if !volumes.iter().any(|e: &Volume| e.index == v.index) {
                    volumes.push(v);
                }
            }
        }
        at += block_size;
    }
    Ok((volumes, truncated))
}

fn parse_volume(block: &[u8]) -> Option<Volume> {
    let flags = u64le(block, 0x108)?;
    let name_bytes = block.get(0x2C0..0x2C0 + 256)?;
    let name = name_bytes
        .iter()
        .take_while(|b| **b != 0)
        .copied()
        .collect::<Vec<u8>>();
    Some(Volume {
        name: String::from_utf8_lossy(&name).into_owned(),
        index: u32le(block, OBJ_HEADER + 4)?,
        files: u64le(block, 0xB8)?,
        directories: u64le(block, 0xC0)?,
        encrypted: flags & APFS_FS_UNENCRYPTED == 0,
        // APFS timestamps are nanoseconds since the Unix epoch, not seconds.
        last_modified_utc: u64le(block, 0x100).and_then(|ns| {
            unix_to_rfc3339((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as u32)
        }),
    })
}

/// What a scan should report for an APFS container.
///
/// Returns `(unsupported, notes)`. There are no recovered files: that is the
/// point of this module, and the unsupported list says so in the words an
/// analyst needs, once per volume.
pub fn report(container: &Container) -> (Vec<String>, Vec<String>) {
    let mut unsupported = vec![
        "APFS per-file recovery is not implemented in this build: resolving the object map, the \
         file-system B-tree and the extent-reference tree is out of scope for v1. The volumes \
         below were identified, but no file was recovered from them. Run the raw carving pass \
         against this container to recover file content."
            .to_string(),
    ];
    let mut notes = vec![format!(
        "APFS container: {} block(s) of {} bytes, {} volume(s) found of up to {} allowed",
        container.block_count,
        container.block_size,
        container.volumes.len(),
        container.max_volumes
    )];

    for v in &container.volumes {
        notes.push(format!(
            "volume {} \"{}\": {} file(s), {} director(y/ies), last modified {}",
            v.index,
            v.name,
            v.files,
            v.directories,
            v.last_modified_utc.as_deref().unwrap_or("unknown")
        ));
        if v.encrypted {
            unsupported.push(format!(
                "volume {} \"{}\" is encrypted (FileVault): its contents are ciphertext, and no \
                 key recovery, password guessing or brute force of any kind is implemented",
                v.index, v.name
            ));
        }
    }

    if container.volumes.is_empty() {
        notes.push(
            "no volume superblock was found by the bounded magic scan; the container may use a \
             checkpoint layout this build does not follow"
                .into(),
        );
    }
    if container.scan_truncated {
        notes.push(format!(
            "the volume scan stopped after {} MiB; volumes beyond that point are not listed",
            SCAN_LIMIT_BYTES / (1024 * 1024)
        ));
    }
    if container.incompatible_features & 0x4 != 0 {
        unsupported.push(
            "the container is a Fusion (tiered SSD + HDD) container: the two halves must be \
             imaged and examined together, which this build does not do"
                .into(),
        );
    }

    (unsupported, notes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::MemorySource;

    /// A synthetic container with one named, unencrypted volume. Enough to prove
    /// the identification path runs and the reporting says the right thing —
    /// which is all this module claims to do.
    fn container_image() -> Vec<u8> {
        let bs = 4096usize;
        let mut img = vec![0u8; bs * 4];
        img[OBJ_HEADER..OBJ_HEADER + 4].copy_from_slice(&NX_MAGIC.to_le_bytes());
        img[OBJ_HEADER + 4..OBJ_HEADER + 8].copy_from_slice(&(bs as u32).to_le_bytes());
        img[OBJ_HEADER + 8..OBJ_HEADER + 16].copy_from_slice(&4u64.to_le_bytes());
        img[OBJ_HEADER + 0x94..OBJ_HEADER + 0x98].copy_from_slice(&100u32.to_le_bytes());

        let v = bs * 2;
        img[v + OBJ_HEADER..v + OBJ_HEADER + 4].copy_from_slice(&APSB_MAGIC.to_le_bytes());
        img[v + OBJ_HEADER + 4..v + OBJ_HEADER + 8].copy_from_slice(&0u32.to_le_bytes());
        img[v + 0xB8..v + 0xC0].copy_from_slice(&42u64.to_le_bytes());
        img[v + 0xC0..v + 0xC8].copy_from_slice(&7u64.to_le_bytes());
        img[v + 0x108..v + 0x110].copy_from_slice(&APFS_FS_UNENCRYPTED.to_le_bytes());
        img[v + 0x2C0..v + 0x2C0 + 8].copy_from_slice(b"Macintos");
        img
    }

    #[test]
    fn a_container_is_identified_and_its_volume_listed() {
        let mut s = MemorySource::new(container_image(), "apfs");
        let c = probe(&mut s, 0).unwrap().expect("a container");
        assert_eq!(c.block_size, 4096);
        assert_eq!(c.volumes.len(), 1);
        assert_eq!(c.volumes[0].name, "Macintos");
        assert_eq!(c.volumes[0].files, 42);
        assert!(!c.volumes[0].encrypted);
    }

    /// The whole contract of this module: it must say out loud that it recovered
    /// nothing, rather than returning an empty list that reads as "nothing was
    /// there".
    #[test]
    fn the_report_states_that_file_recovery_is_unsupported() {
        let mut s = MemorySource::new(container_image(), "apfs");
        let c = probe(&mut s, 0).unwrap().unwrap();
        let (unsupported, notes) = report(&c);
        assert!(unsupported[0].contains("not implemented"));
        assert!(unsupported[0].contains("carving"));
        assert!(notes.iter().any(|n| n.contains("Macintos")));
    }

    #[test]
    fn an_encrypted_volume_is_called_out_and_not_attacked() {
        let mut img = container_image();
        let v = 4096 * 2;
        img[v + 0x108..v + 0x110].copy_from_slice(&0u64.to_le_bytes());
        let mut s = MemorySource::new(img, "apfs");
        let c = probe(&mut s, 0).unwrap().unwrap();
        assert!(c.volumes[0].encrypted);
        let (unsupported, _) = report(&c);
        assert!(unsupported.iter().any(|u| u.contains("no key recovery")));
    }

    #[test]
    fn a_non_apfs_source_is_not_a_container() {
        let mut s = MemorySource::new(vec![0u8; 8192], "zeroes");
        assert!(probe(&mut s, 0).unwrap().is_none());
    }
}
