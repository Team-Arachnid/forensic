//! ext4 recovery via inode tables and the jbd2 journal.
//!
//! ext4 unlinks a file by clearing its directory entry, setting `i_dtime`,
//! dropping `i_links_count` to zero and freeing its blocks. Unlike ext3, it does
//! **not** zero the extent tree in the inode, so the inode usually still says
//! exactly which blocks held the file. That is the primary recovery path here.
//!
//! When the inode itself has been reused, an older copy of the whole inode-table
//! block often survives in the journal, because ext4 journals metadata before
//! writing it. Walking jbd2's descriptor blocks turns that into a second pass
//! that can recover a file the live inode table has already forgotten — at lower
//! confidence, because a journalled inode is by definition a stale snapshot.
//!
//! Filenames come from directory entries. A deleted entry is not erased either:
//! the preceding entry's `rec_len` is simply extended over it, leaving the old
//! record intact in the slack. Scanning that slack is what lets a deleted file
//! keep its name.

use std::collections::HashMap;

use anyhow::{bail, Context, Result};

use crate::results::{
    unix_to_rfc3339, Check, Confidence, Extent, Method, Rationale, RecoveredFile,
};
use crate::source::{u16le, u32be, u32le, Source};

const SUPERBLOCK_OFFSET: u64 = 1024;
const EXT4_MAGIC: u16 = 0xEF53;

const INCOMPAT_64BIT: u32 = 0x0080;
const INCOMPAT_EXTENTS: u32 = 0x0040;
const INCOMPAT_ENCRYPT: u32 = 0x1_0000;
const INCOMPAT_CASEFOLD: u32 = 0x2_0000;

const INODE_FLAG_EXTENTS: u32 = 0x0008_0000;
const INODE_FLAG_ENCRYPT: u32 = 0x0000_0800;
const INODE_FLAG_INLINE: u32 = 0x1000_0000;

const S_IFMT: u16 = 0xF000;
const S_IFREG: u16 = 0x8000;
const S_IFDIR: u16 = 0x4000;

const EXTENT_MAGIC: u16 = 0xF30A;

/// jbd2 is big-endian on every architecture, unlike everything else in ext4.
const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
const JBD2_TAG_FLAG_ESCAPE: u16 = 0x01;
const JBD2_TAG_FLAG_SAME_UUID: u16 = 0x02;
const JBD2_TAG_FLAG_LAST: u16 = 0x08;
const JBD2_FEATURE_INCOMPAT_64BIT: u32 = 0x0010;
const JBD2_FEATURE_INCOMPAT_CSUM_V3: u32 = 0x0020;

/// Cap on extent-tree recursion. A depth over this is a corrupted or
/// deliberately looped tree, not a real file.
const MAX_EXTENT_DEPTH: u16 = 5;

/// Bytes read back per extent when scoring; see the NTFS parser for why this is
/// a sample rather than a full read.
const PROBE_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy)]
pub struct Superblock {
    pub base: u64,
    pub block_size: u64,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u32,
    pub inodes_count: u32,
    pub first_data_block: u32,
    pub desc_size: u32,
    pub feature_incompat: u32,
    pub journal_inum: u32,
}

impl Superblock {
    pub fn block_offset(&self, block: u64) -> u64 {
        self.base + block * self.block_size
    }

    pub fn groups(&self) -> u32 {
        // Derived from the inode count so a truncated image cannot make this a
        // multi-billion iteration loop over a block count it does not have.
        self.inodes_count.div_ceil(self.inodes_per_group.max(1))
    }

    fn has_64bit(&self) -> bool {
        self.feature_incompat & INCOMPAT_64BIT != 0
    }
}

/// Read and validate an ext4 superblock at `base`.
///
/// `Ok(None)` means there is no ext filesystem here; `Err` means there is one
/// and it contradicts itself.
pub fn probe(source: &mut dyn Source, base: u64) -> Result<Option<Superblock>> {
    let mut sb = [0u8; 1024];
    if source.read_at(base + SUPERBLOCK_OFFSET, &mut sb)? < 1024 {
        return Ok(None);
    }
    if u16le(&sb, 0x38) != Some(EXT4_MAGIC) {
        return Ok(None);
    }

    let log_block_size = u32le(&sb, 0x18).unwrap_or(0);
    if log_block_size > 16 {
        bail!("ext4 at offset {base} declares block size 2^{log_block_size}, which is not a real filesystem");
    }
    let block_size = 1024u64 << log_block_size;
    let rev_level = u32le(&sb, 0x4C).unwrap_or(0);
    let inode_size = if rev_level >= 1 {
        u16le(&sb, 0x58).unwrap_or(128) as u32
    } else {
        128
    };
    if !(128..=4096).contains(&inode_size) {
        bail!("ext4 at offset {base} declares an impossible inode size {inode_size}");
    }
    let inodes_per_group = u32le(&sb, 0x28).unwrap_or(0);
    if inodes_per_group == 0 {
        bail!("ext4 at offset {base} declares zero inodes per group");
    }
    let feature_incompat = u32le(&sb, 0x60).unwrap_or(0);
    let desc_size = if feature_incompat & INCOMPAT_64BIT != 0 {
        u16le(&sb, 0xFE).unwrap_or(64) as u32
    } else {
        32
    };

    Ok(Some(Superblock {
        base,
        block_size,
        blocks_per_group: u32le(&sb, 0x20).unwrap_or(0),
        inodes_per_group,
        inode_size,
        inodes_count: u32le(&sb, 0x00).unwrap_or(0),
        first_data_block: u32le(&sb, 0x14).unwrap_or(if block_size == 1024 { 1 } else { 0 }),
        desc_size,
        feature_incompat,
        journal_inum: u32le(&sb, 0xE0).unwrap_or(8),
    }))
}

/// A parsed inode, as far as recovery cares about it.
#[derive(Debug, Clone)]
struct Inode {
    number: u32,
    mode: u16,
    size: u64,
    atime: u32,
    ctime: u32,
    mtime: u32,
    dtime: u32,
    links: u16,
    flags: u32,
    /// The 60 raw bytes of `i_block`, still to be read as an extent tree.
    block: [u8; 60],
}

impl Inode {
    fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }

    fn is_directory(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    /// Deleted: unlinked and stamped with a deletion time.
    fn is_deleted(&self) -> bool {
        self.links == 0 && self.dtime != 0
    }

    /// A never-used slot: everything zero. Distinct from a deleted file, which
    /// keeps its mode, size and extents.
    fn is_empty(&self) -> bool {
        self.mode == 0 && self.size == 0 && self.ctime == 0
    }
}

fn parse_inode(buf: &[u8], number: u32) -> Option<Inode> {
    let mut block = [0u8; 60];
    block.copy_from_slice(buf.get(0x28..0x28 + 60)?);
    let size_lo = u32le(buf, 0x04)? as u64;
    let size_hi = u32le(buf, 0x6C).unwrap_or(0) as u64;
    Some(Inode {
        number,
        mode: u16le(buf, 0x00)?,
        // i_size_high is only the high 32 bits for regular files; for a
        // directory the same field is i_dir_acl, so it is masked off below by
        // only ever using this for regular files.
        size: size_lo | (size_hi << 32),
        atime: u32le(buf, 0x08)?,
        ctime: u32le(buf, 0x0C)?,
        mtime: u32le(buf, 0x10)?,
        dtime: u32le(buf, 0x14)?,
        links: u16le(buf, 0x1A)?,
        flags: u32le(buf, 0x20)?,
        block,
    })
}

/// Walk an extent tree into a flat list of (logical block, physical block,
/// length) triples, following index nodes to their leaves.
fn walk_extents(
    source: &mut dyn Source,
    sb: &Superblock,
    node: &[u8],
    depth_budget: u16,
    out: &mut Vec<(u64, u64, u64)>,
    problems: &mut Vec<String>,
) {
    if u16le(node, 0) != Some(EXTENT_MAGIC) {
        problems.push("extent node has no magic; the tree was overwritten".into());
        return;
    }
    let entries = u16le(node, 2).unwrap_or(0) as usize;
    let depth = u16le(node, 6).unwrap_or(0);
    if depth > MAX_EXTENT_DEPTH || depth_budget == 0 {
        problems.push(format!(
            "extent tree deeper than {MAX_EXTENT_DEPTH} levels; refusing to follow it"
        ));
        return;
    }

    for i in 0..entries {
        let at = 12 + i * 12;
        let Some(e) = node.get(at..at + 12) else {
            problems.push("extent node declares more entries than it holds".into());
            return;
        };
        if depth == 0 {
            let logical = u32le(e, 0).unwrap_or(0) as u64;
            let raw_len = u16le(e, 4).unwrap_or(0);
            // Over 32768 marks an uninitialized (preallocated) extent; the
            // blocks are allocated but hold no file data.
            let (len, initialized) = if raw_len > 32768 {
                (raw_len as u64 - 32768, false)
            } else {
                (raw_len as u64, true)
            };
            let physical =
                ((u16le(e, 6).unwrap_or(0) as u64) << 32) | u32le(e, 8).unwrap_or(0) as u64;
            if !initialized {
                problems.push(format!(
                    "{len} block(s) at logical block {logical} are preallocated but never written"
                ));
            }
            if len > 0 {
                out.push((logical, physical, len));
            }
        } else {
            let leaf = ((u16le(e, 8).unwrap_or(0) as u64) << 32) | u32le(e, 4).unwrap_or(0) as u64;
            let Ok(child) = source.read_exact_at(sb.block_offset(leaf), sb.block_size as usize)
            else {
                problems.push(format!("extent index points at unreadable block {leaf}"));
                continue;
            };
            walk_extents(source, sb, &child, depth_budget - 1, out, problems);
        }
    }
}

/// One directory entry found on disk, live or in the slack behind a live one.
struct DirEntry {
    inode: u32,
    name: String,
    /// True when the entry was found in slack space rather than in the live
    /// chain — i.e. it was deleted.
    orphaned: bool,
}

/// Read a directory's blocks and return every entry, including the deleted ones
/// still sitting in slack.
fn read_directory(source: &mut dyn Source, sb: &Superblock, inode: &Inode) -> Vec<DirEntry> {
    let mut out = Vec::new();
    if inode.flags & INODE_FLAG_INLINE != 0 {
        // Inline directories keep their entries inside i_block in a different
        // format. Not parsed; reported by the caller as unsupported.
        return out;
    }
    let mut extents = Vec::new();
    let mut problems = Vec::new();
    if inode.flags & INODE_FLAG_EXTENTS != 0 {
        walk_extents(
            source,
            sb,
            &inode.block,
            MAX_EXTENT_DEPTH,
            &mut extents,
            &mut problems,
        );
    }

    for (_, physical, len) in extents {
        for b in 0..len {
            let Ok(block) =
                source.read_exact_at(sb.block_offset(physical + b), sb.block_size as usize)
            else {
                continue;
            };
            parse_dir_block(&block, &mut out);
        }
    }
    out
}

/// Walk one directory block's entry chain, and the slack behind each entry.
fn parse_dir_block(block: &[u8], out: &mut Vec<DirEntry>) {
    let mut at = 0usize;
    while at + 8 <= block.len() {
        let inode = u32le(block, at).unwrap_or(0);
        let rec_len = u16le(block, at + 4).unwrap_or(0) as usize;
        let name_len = *block.get(at + 6).unwrap_or(&0) as usize;
        // rec_len is always a multiple of 4 and never smaller than a header.
        if rec_len < 8 || !rec_len.is_multiple_of(4) || at + rec_len > block.len() {
            return;
        }
        if inode != 0 && name_len > 0 && 8 + name_len <= rec_len {
            if let Some(name) = block.get(at + 8..at + 8 + name_len) {
                out.push(DirEntry {
                    inode,
                    name: String::from_utf8_lossy(name).into_owned(),
                    orphaned: false,
                });
            }
        }

        // Slack: everything between the end of this entry's name and the end of
        // its rec_len is where deleted entries survive.
        let used = (8 + name_len).next_multiple_of(4);
        let mut slack = at + used;
        while slack + 8 <= at + rec_len {
            let s_inode = u32le(block, slack).unwrap_or(0);
            let s_rec = u16le(block, slack + 4).unwrap_or(0) as usize;
            let s_name = *block.get(slack + 6).unwrap_or(&0) as usize;
            if s_inode == 0 || s_name == 0 || s_rec < 8 || slack + 8 + s_name > at + rec_len {
                break;
            }
            if let Some(name) = block.get(slack + 8..slack + 8 + s_name) {
                // Only accept something that reads like a filename. Slack is
                // mostly stale bytes, and a "name" of control characters is a
                // false positive that would pollute every recovered path.
                let text = String::from_utf8_lossy(name).into_owned();
                if text.chars().all(|c| !c.is_control() && c != '/') {
                    out.push(DirEntry {
                        inode: s_inode,
                        name: text,
                        orphaned: true,
                    });
                }
            }
            slack += (8 + s_name).next_multiple_of(4);
        }
        at += rec_len;
    }
}

/// Everything an ext4 pass found.
pub struct Scan {
    pub files: Vec<RecoveredFile>,
    pub unsupported: Vec<String>,
    pub notes: Vec<String>,
}

/// Recover files from the inode tables, then from the journal.
pub fn recover(source: &mut dyn Source, sb: &Superblock, deleted_only: bool) -> Result<Scan> {
    let mut unsupported = Vec::new();
    let mut notes = Vec::new();

    if sb.feature_incompat & INCOMPAT_ENCRYPT != 0 {
        unsupported.push(
            "the volume has the ext4 encryption feature: encrypted files are located and \
             reported, never decrypted"
                .into(),
        );
    }
    if sb.feature_incompat & INCOMPAT_CASEFOLD != 0 {
        notes.push("the volume uses case-folded filenames; names are reported as stored".into());
    }
    if sb.feature_incompat & INCOMPAT_EXTENTS == 0 {
        unsupported.push(
            "the volume predates extents (ext2/ext3 indirect block maps); only inodes that do \
             carry an extent tree are recovered"
                .into(),
        );
    }

    // Inode table location per block group.
    let gd_block = sb.first_data_block as u64 + 1;
    let groups = sb.groups();
    let mut inode_tables = Vec::with_capacity(groups as usize);
    for g in 0..groups {
        let at = sb.block_offset(gd_block) + (g as u64 * sb.desc_size as u64);
        let Ok(gd) = source.read_exact_at(at, sb.desc_size as usize) else {
            notes.push(format!(
                "group descriptor {g} is unreadable; that group was skipped"
            ));
            inode_tables.push(None);
            continue;
        };
        let lo = u32le(&gd, 0x08).unwrap_or(0) as u64;
        let hi = if sb.has_64bit() {
            u32le(&gd, 0x28).unwrap_or(0) as u64
        } else {
            0
        };
        inode_tables.push(Some(lo | (hi << 32)));
    }

    // Pass 1: every inode in every table.
    let mut inodes: HashMap<u32, Inode> = HashMap::new();
    for (g, table) in inode_tables.iter().enumerate() {
        let Some(table) = table else { continue };
        for i in 0..sb.inodes_per_group {
            let number = g as u32 * sb.inodes_per_group + i + 1;
            let at = sb.block_offset(*table) + i as u64 * sb.inode_size as u64;
            let Ok(buf) = source.read_exact_at(at, sb.inode_size as usize) else {
                continue;
            };
            let Some(inode) = parse_inode(&buf, number) else {
                continue;
            };
            if inode.is_empty() {
                continue;
            }
            inodes.insert(number, inode);
        }
    }

    // Names, from every directory reachable in the table — deleted directories
    // included, for the same reason as NTFS.
    let mut names: HashMap<u32, (String, bool)> = HashMap::new();
    let mut parents: HashMap<u32, u32> = HashMap::new();
    let mut inline_dirs = 0u64;
    let dir_numbers: Vec<u32> = inodes
        .values()
        .filter(|i| i.is_directory())
        .map(|i| i.number)
        .collect();
    for number in dir_numbers {
        let inode = inodes[&number].clone();
        if inode.flags & INODE_FLAG_INLINE != 0 {
            inline_dirs += 1;
            continue;
        }
        for e in read_directory(source, sb, &inode) {
            if e.name == "." || e.name == ".." {
                continue;
            }
            parents.insert(e.inode, number);
            // A live entry beats an orphaned one for the same inode: the live
            // name is the current truth.
            match names.get(&e.inode) {
                Some((_, false)) => {}
                _ => {
                    names.insert(e.inode, (e.name, e.orphaned));
                }
            }
        }
    }
    if inline_dirs > 0 {
        unsupported.push(format!(
            "{inline_dirs} directory/ies store their entries inline in the inode; those names \
             were not read, so files under them recover without a path"
        ));
    }

    let mut files = Vec::new();
    for inode in inodes.values() {
        if !inode.is_regular() {
            continue;
        }
        if deleted_only && !inode.is_deleted() {
            continue;
        }
        let path = build_path(&names, &parents, inode.number);
        files.push(assemble(
            source,
            sb,
            inode,
            path,
            Method::Ext4Inode,
            names
                .get(&inode.number)
                .is_some_and(|(_, orphaned)| *orphaned),
        ));
    }

    // Pass 2: the journal, for inodes the live table has already reused.
    match journal_inodes(source, sb, &inodes) {
        Ok((stale, journal_notes)) => {
            notes.extend(journal_notes);
            for inode in stale {
                if !inode.is_regular() {
                    continue;
                }
                let path = build_path(&names, &parents, inode.number);
                let mut f = assemble(source, sb, &inode, path, Method::Ext4Journal, true);
                // A journalled inode is a snapshot of metadata that has since
                // been replaced. Whatever the extents read back as, it cannot be
                // confirmed to still be this file, so the journal path is capped
                // below the live table's.
                if f.rationale.confidence > Confidence::Medium {
                    f.rationale.confidence = Confidence::Medium;
                }
                f.rationale.checks.push(Check::fail(
                    "inode_is_current",
                    "this inode was read from the journal, not the live inode table: it is a \
                     superseded snapshot and its blocks have since been reallocated at least once",
                ));
                f.rationale.summary =
                    "recovered from a journalled copy of the inode; metadata is a stale snapshot"
                        .into();
                files.push(f);
            }
        }
        Err(e) => notes.push(format!("journal pass did not run: {e:#}")),
    }

    Ok(Scan {
        files,
        unsupported,
        notes,
    })
}

fn build_path(
    names: &HashMap<u32, (String, bool)>,
    parents: &HashMap<u32, u32>,
    inode: u32,
) -> Option<String> {
    let (name, _) = names.get(&inode)?;
    let mut parts = vec![name.clone()];
    let mut at = *parents.get(&inode)?;
    let mut depth = 0;
    // Inode 2 is the root directory, fixed by the format.
    while at != 2 && depth < 64 {
        let Some((dir, _)) = names.get(&at) else {
            parts.push("<unknown>".into());
            break;
        };
        parts.push(dir.clone());
        let Some(next) = parents.get(&at) else { break };
        at = *next;
        depth += 1;
    }
    parts.reverse();
    Some(parts.join("/"))
}

/// Turn an inode into a result, scored against what the media gives back.
fn assemble(
    source: &mut dyn Source,
    sb: &Superblock,
    inode: &Inode,
    path: Option<String>,
    method: Method,
    name_from_slack: bool,
) -> RecoveredFile {
    let mut checks = Vec::new();
    let deleted = inode.is_deleted();

    checks.push(if deleted {
        Check::fail(
            "inode_linked",
            format!(
                "i_links_count is 0 and i_dtime is set ({}): the file is deleted and its blocks \
                 are free",
                unix_to_rfc3339(inode.dtime as i64, 0).unwrap_or_else(|| inode.dtime.to_string())
            ),
        )
    } else {
        Check::pass(
            "inode_linked",
            format!("{} link(s); the file is live", inode.links),
        )
    });

    let encrypted = (inode.flags & INODE_FLAG_ENCRYPT != 0).then(|| {
        "ext4 per-file encryption: contents are ciphertext and no key recovery is implemented"
            .to_string()
    });

    let mut problems = Vec::new();
    let mut triples = Vec::new();
    if inode.flags & INODE_FLAG_EXTENTS != 0 {
        walk_extents(
            source,
            sb,
            &inode.block,
            MAX_EXTENT_DEPTH,
            &mut triples,
            &mut problems,
        );
    } else if inode.flags & INODE_FLAG_INLINE != 0 {
        problems.push(
            "the file's data is stored inline in the inode, which this build does not extract"
                .into(),
        );
    } else {
        problems.push(
            "the inode carries an ext2/ext3 indirect block map rather than an extent tree; \
             this build does not follow indirect blocks"
                .into(),
        );
    }

    // Extents in logical order, clipped to the file size.
    triples.sort_by_key(|(logical, _, _)| *logical);
    let mut extents = Vec::new();
    let mut remaining = inode.size;
    for (_, physical, len) in &triples {
        if remaining == 0 {
            break;
        }
        let span = (len * sb.block_size).min(remaining);
        extents.push(Extent {
            offset: sb.block_offset(*physical),
            length: span,
        });
        remaining -= span;
    }

    let mapped: u64 = extents.iter().map(|e| e.length).sum();
    let covered = mapped >= inode.size;
    checks.push(if covered {
        Check::pass(
            "extents_cover_size",
            format!("{mapped} byte(s) mapped for a {} byte file", inode.size),
        )
    } else {
        Check::fail(
            "extents_cover_size",
            format!(
                "only {mapped} of {} byte(s) are mapped; the extent tree no longer describes the \
                 whole file",
                inode.size
            ),
        )
    });

    for p in &problems {
        checks.push(Check::fail("extent_tree_intact", p.clone()));
    }
    if problems.is_empty() && !extents.is_empty() {
        checks.push(Check::pass(
            "extent_tree_intact",
            format!("{} extent(s) read out of the tree cleanly", extents.len()),
        ));
    }

    let mut unreadable = 0u64;
    let mut in_range = true;
    for e in &extents {
        if e.offset + e.length > source.size() {
            in_range = false;
        }
        let probe = (e.length as usize).min(PROBE_BYTES);
        let mut buf = vec![0u8; probe];
        if !matches!(source.read_at(e.offset, &mut buf), Ok(n) if n == probe) {
            unreadable += 1;
        }
    }
    checks.push(if !in_range {
        Check::fail(
            "extents_within_source",
            "at least one extent points past the end of the image; the image may be truncated",
        )
    } else if unreadable > 0 {
        Check::fail(
            "extents_readable",
            format!(
                "{unreadable} of {} extent(s) would not read back",
                extents.len()
            ),
        )
    } else if extents.is_empty() {
        Check::fail("extents_readable", "the inode maps no readable blocks")
    } else {
        Check::pass(
            "extents_readable",
            format!("{} extent(s) sampled and readable", extents.len()),
        )
    });

    checks.push(match (&path, name_from_slack) {
        (Some(p), true) => Check::fail(
            "name_from_live_directory",
            format!("the name {p} came from a deleted directory entry in slack space"),
        ),
        (Some(p), false) => Check::pass(
            "name_from_live_directory",
            format!("the name {p} came from a live directory entry"),
        ),
        (None, _) => Check::fail(
            "name_from_live_directory",
            "no directory entry references this inode; the original name is unrecoverable",
        ),
    });

    if let Some(e) = &encrypted {
        checks.push(Check::fail("data_unencrypted", e.clone()));
    }

    let readable = unreadable == 0 && in_range && !extents.is_empty();
    let (confidence, summary) = if encrypted.is_some() {
        (
            Confidence::Medium,
            "inode intact, but the contents are encrypted and are exported as ciphertext".into(),
        )
    } else if !covered || !readable || !problems.is_empty() {
        (
            Confidence::Medium,
            "inode found, but the extent tree is incomplete or does not read back cleanly".into(),
        )
    } else if deleted {
        (
            Confidence::Medium,
            "inode and extent tree intact and every extent reads back, but the file is deleted: \
             its blocks are free and may since have been reallocated"
                .into(),
        )
    } else {
        (
            Confidence::High,
            "live inode, complete extent tree, every extent read back cleanly".into(),
        )
    };

    let export_name = path
        .as_deref()
        .and_then(|p| p.rsplit('/').next())
        .map(str::to_string)
        .unwrap_or_else(|| format!("inode-{}", inode.number));
    let file_type = crate::ntfs::extension_of(&export_name);

    RecoveredFile {
        id: format!(
            "{}-{:06}",
            if method == Method::Ext4Journal {
                "ext4j"
            } else {
                "ext4"
            },
            inode.number
        ),
        method,
        original_path: path,
        export_name,
        file_type,
        size: inode.size,
        extents,
        created_utc: unix_to_rfc3339(inode.ctime as i64, 0),
        modified_utc: unix_to_rfc3339(inode.mtime as i64, 0),
        accessed_utc: unix_to_rfc3339(inode.atime as i64, 0),
        deleted,
        encrypted,
        rationale: Rationale {
            confidence,
            summary,
            checks,
        },
    }
}

/// Walk the jbd2 journal for inode-table blocks and return the inodes in them
/// that the live table no longer has.
fn journal_inodes(
    source: &mut dyn Source,
    sb: &Superblock,
    live: &HashMap<u32, Inode>,
) -> Result<(Vec<Inode>, Vec<String>)> {
    let mut notes = Vec::new();

    // The journal is an ordinary file; its inode says where it lives.
    let group = (sb.journal_inum - 1) / sb.inodes_per_group;
    let index = (sb.journal_inum - 1) % sb.inodes_per_group;
    let gd_at =
        sb.block_offset(sb.first_data_block as u64 + 1) + group as u64 * sb.desc_size as u64;
    let gd = source
        .read_exact_at(gd_at, sb.desc_size as usize)
        .context("read the journal's group descriptor")?;
    let table = u32le(&gd, 0x08).unwrap_or(0) as u64
        | if sb.has_64bit() {
            (u32le(&gd, 0x28).unwrap_or(0) as u64) << 32
        } else {
            0
        };
    let inode_buf = source
        .read_exact_at(
            sb.block_offset(table) + index as u64 * sb.inode_size as u64,
            sb.inode_size as usize,
        )
        .context("read the journal inode")?;
    let journal = parse_inode(&inode_buf, sb.journal_inum).context("parse the journal inode")?;
    if journal.flags & INODE_FLAG_EXTENTS == 0 {
        bail!("the journal inode carries no extent tree");
    }

    let mut triples = Vec::new();
    let mut problems = Vec::new();
    walk_extents(
        source,
        sb,
        &journal.block,
        MAX_EXTENT_DEPTH,
        &mut triples,
        &mut problems,
    );
    triples.sort_by_key(|(logical, _, _)| *logical);
    if triples.is_empty() {
        bail!("the journal inode maps no blocks");
    }

    // Logical journal block -> physical block, so descriptor blocks and the data
    // blocks that follow them can be read in journal order.
    let mut map: Vec<u64> = Vec::new();
    for (_, physical, len) in &triples {
        for b in 0..*len {
            map.push(physical + b);
        }
    }

    let jsb = source.read_exact_at(sb.block_offset(map[0]), sb.block_size as usize)?;
    if u32be(&jsb, 0) != Some(JBD2_MAGIC) {
        bail!("no jbd2 superblock at the start of the journal");
    }
    let jfeatures = u32be(&jsb, 0x28).unwrap_or(0);
    let tag_size = if jfeatures & JBD2_FEATURE_INCOMPAT_CSUM_V3 != 0 {
        16
    } else if jfeatures & JBD2_FEATURE_INCOMPAT_64BIT != 0 {
        12
    } else {
        8
    };

    // Which physical blocks are inode tables, and which inode each byte in them
    // belongs to.
    let mut table_of: HashMap<u64, u32> = HashMap::new();
    for g in 0..sb.groups() {
        let at = sb.block_offset(sb.first_data_block as u64 + 1) + g as u64 * sb.desc_size as u64;
        let Ok(gd) = source.read_exact_at(at, sb.desc_size as usize) else {
            continue;
        };
        let start = u32le(&gd, 0x08).unwrap_or(0) as u64
            | if sb.has_64bit() {
                (u32le(&gd, 0x28).unwrap_or(0) as u64) << 32
            } else {
                0
            };
        let bytes = sb.inodes_per_group as u64 * sb.inode_size as u64;
        for b in 0..bytes.div_ceil(sb.block_size) {
            let first_index = b * sb.block_size / sb.inode_size as u64;
            table_of.insert(start + b, g * sb.inodes_per_group + first_index as u32 + 1);
        }
    }

    let mut recovered: HashMap<u32, Inode> = HashMap::new();
    let mut descriptors = 0u64;
    let mut i = 1usize;
    while i < map.len() {
        let Ok(block) = source.read_exact_at(sb.block_offset(map[i]), sb.block_size as usize)
        else {
            break;
        };
        if u32be(&block, 0) != Some(JBD2_MAGIC) || u32be(&block, 4) != Some(JBD2_DESCRIPTOR_BLOCK) {
            i += 1;
            continue;
        }
        descriptors += 1;

        // Tags follow the 12-byte header. Each names the filesystem block that
        // the next journal data block is a copy of.
        let mut tag_at = 12usize;
        let mut data_at = i + 1;
        while tag_at + tag_size <= block.len() && data_at < map.len() {
            let target = u32be(&block, tag_at).unwrap_or(0) as u64;
            let flags = if tag_size == 16 {
                // csum v3 puts flags at a different offset than the classic tag.
                u32be(&block, tag_at + 8).unwrap_or(0) as u16
            } else {
                crate::source::u16le(&block, tag_at + 6)
                    .map(u16::swap_bytes)
                    .unwrap_or(0)
            };

            if let Some(first_inode) = table_of.get(&target).copied() {
                if let Ok(copy) =
                    source.read_exact_at(sb.block_offset(map[data_at]), sb.block_size as usize)
                {
                    let per_block = sb.block_size / sb.inode_size as u64;
                    for n in 0..per_block {
                        let at = (n * sb.inode_size as u64) as usize;
                        let Some(slice) = copy.get(at..at + sb.inode_size as usize) else {
                            break;
                        };
                        let number = first_inode + n as u32;
                        let Some(inode) = parse_inode(slice, number) else {
                            continue;
                        };
                        if inode.is_empty() || !inode.is_regular() {
                            continue;
                        }
                        // Only what the live table has lost. A journalled copy
                        // of an inode that is still live adds nothing and would
                        // double every result.
                        if live.get(&number).is_some_and(|l| !l.is_empty()) {
                            continue;
                        }
                        recovered.entry(number).or_insert(inode);
                    }
                }
            }

            data_at += 1;
            tag_at += tag_size;
            if flags & JBD2_TAG_FLAG_SAME_UUID == 0 {
                tag_at += 16;
            }
            if flags & JBD2_TAG_FLAG_ESCAPE != 0 {
                // The escape flag concerns the first four bytes of the data
                // block, which an inode table copy does not care about.
            }
            if flags & JBD2_TAG_FLAG_LAST != 0 {
                break;
            }
        }
        i = data_at.max(i + 1);
    }

    notes.push(format!(
        "journal: {descriptors} descriptor block(s) walked, {} inode(s) recovered that the live \
         table no longer holds",
        recovered.len()
    ));
    Ok((recovered.into_values().collect(), notes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deleted_and_empty_inodes_are_different_things() {
        let mut i = Inode {
            number: 12,
            mode: S_IFREG,
            size: 100,
            atime: 1,
            ctime: 1,
            mtime: 1,
            dtime: 0,
            links: 1,
            flags: INODE_FLAG_EXTENTS,
            block: [0u8; 60],
        };
        assert!(!i.is_deleted());
        assert!(!i.is_empty());
        i.links = 0;
        i.dtime = 99;
        assert!(i.is_deleted());
        assert!(!i.is_empty());

        let empty = Inode {
            mode: 0,
            size: 0,
            ctime: 0,
            ..i.clone()
        };
        assert!(empty.is_empty());
    }

    /// The slack scan is the only way a deleted file keeps its name, and the
    /// only place a false positive would invent one.
    #[test]
    fn deleted_dir_entries_are_found_in_slack() {
        let mut block = vec![0u8; 64];
        // A live entry "keep" whose rec_len swallows a deleted "gone" behind it.
        block[0..4].copy_from_slice(&11u32.to_le_bytes());
        block[4..6].copy_from_slice(&32u16.to_le_bytes());
        block[6] = 4;
        block[7] = 1;
        block[8..12].copy_from_slice(b"keep");
        // Deleted entry starts at the 4-aligned end of "keep": 8 + 4 = 12.
        block[12..16].copy_from_slice(&12u32.to_le_bytes());
        block[16..18].copy_from_slice(&16u16.to_le_bytes());
        block[18] = 4;
        block[19] = 1;
        block[20..24].copy_from_slice(b"gone");
        // Tail entry so the walk terminates cleanly.
        block[32..36].copy_from_slice(&13u32.to_le_bytes());
        block[36..38].copy_from_slice(&32u16.to_le_bytes());
        block[38] = 4;
        block[39] = 1;
        block[40..44].copy_from_slice(b"tail");

        let mut out = Vec::new();
        parse_dir_block(&block, &mut out);
        let names: Vec<_> = out.iter().map(|e| (e.name.as_str(), e.orphaned)).collect();
        assert!(names.contains(&("keep", false)), "{names:?}");
        assert!(names.contains(&("gone", true)), "{names:?}");
        assert!(names.contains(&("tail", false)), "{names:?}");
    }

    /// Slack is mostly stale bytes. A "name" of control characters must not
    /// become a recovered filename.
    #[test]
    fn slack_junk_is_not_mistaken_for_a_name() {
        let mut block = vec![0u8; 32];
        block[0..4].copy_from_slice(&11u32.to_le_bytes());
        block[4..6].copy_from_slice(&32u16.to_le_bytes());
        block[6] = 4;
        block[8..12].copy_from_slice(b"real");
        block[12..16].copy_from_slice(&9u32.to_le_bytes());
        block[16..18].copy_from_slice(&12u16.to_le_bytes());
        block[18] = 4;
        block[20..24].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);

        let mut out = Vec::new();
        parse_dir_block(&block, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, "real");
    }

    #[test]
    fn extent_leaves_decode_including_uninitialized_ones() {
        let mut node = vec![0u8; 60];
        node[0..2].copy_from_slice(&EXTENT_MAGIC.to_le_bytes());
        node[2..4].copy_from_slice(&2u16.to_le_bytes());
        node[6..8].copy_from_slice(&0u16.to_le_bytes()); // depth 0
                                                         // extent 0: logical 0, 4 blocks at physical 100
        node[12..16].copy_from_slice(&0u32.to_le_bytes());
        node[16..18].copy_from_slice(&4u16.to_le_bytes());
        node[20..24].copy_from_slice(&100u32.to_le_bytes());
        // extent 1: logical 4, 2 uninitialized blocks at physical 200
        node[24..28].copy_from_slice(&4u32.to_le_bytes());
        node[28..30].copy_from_slice(&(32768u16 + 2).to_le_bytes());
        node[32..36].copy_from_slice(&200u32.to_le_bytes());

        let sb = Superblock {
            base: 0,
            block_size: 1024,
            blocks_per_group: 8192,
            inodes_per_group: 64,
            inode_size: 256,
            inodes_count: 64,
            first_data_block: 1,
            desc_size: 32,
            feature_incompat: INCOMPAT_EXTENTS,
            journal_inum: 8,
        };
        let mut source = crate::source::MemorySource::new(vec![0u8; 1024], "t");
        let mut out = Vec::new();
        let mut problems = Vec::new();
        walk_extents(
            &mut source,
            &sb,
            &node,
            MAX_EXTENT_DEPTH,
            &mut out,
            &mut problems,
        );
        assert_eq!(out, vec![(0, 100, 4), (4, 200, 2)]);
        assert!(problems[0].contains("preallocated"));
    }
}
