//! Builders for the small synthetic filesystem images the parser tests run
//! against, and that `tests/fixture.rs` writes into `test-fixtures/`.
//!
//! These are built rather than captured from real media for two reasons. A real
//! image is the wrong thing to put in a public repository — even a scratch disk
//! carries filenames, timestamps and slack from whoever's machine made it — and
//! a built image can be made to contain exactly the case under test: one live
//! file, one deleted file whose run list is intact, one whose parent directory
//! is gone. **No real personal data is used as a fixture anywhere in this
//! crate.**
//!
//! Everything here writes the same on-disk structures the parsers read, so a
//! test that passes against one of these images is exercising the real parsing
//! path, not a stub.

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// NTFS
// ---------------------------------------------------------------------------

pub mod ntfs {
    pub const BYTES_PER_SECTOR: usize = 512;
    pub const SECTORS_PER_CLUSTER: usize = 8;
    pub const CLUSTER: usize = BYTES_PER_SECTOR * SECTORS_PER_CLUSTER;
    pub const RECORD: usize = 1024;
    /// Cluster the MFT starts at.
    pub const MFT_LCN: usize = 4;
    /// Total clusters in the image. 128 KiB: enough for the MFT and three
    /// files, small enough to check into a repository without thinking about it.
    pub const CLUSTERS: usize = 32;

    /// Record numbers used by the fixture.
    pub const REC_MFT: u64 = 0;
    pub const REC_ROOT: u64 = 5;
    pub const REC_DIR: u64 = 16;
    pub const REC_LIVE: u64 = 17;
    pub const REC_DELETED: u64 = 18;
    pub const REC_ORPHAN: u64 = 19;

    /// Cluster each fixture file's data starts at.
    pub const LCN_LIVE: usize = 20;
    pub const LCN_DELETED: usize = 22;
    pub const LCN_ORPHAN: usize = 24;

    /// 2026-03-01T12:00:00Z as a Windows FILETIME.
    pub const FIXTURE_TIME: u64 = 116_444_736_000_000_000 + 1_772_366_400 * 10_000_000;

    /// Build the fixture image: a live file, a deleted file whose run list is
    /// intact, and a deleted file whose parent directory record has been reused
    /// so its path cannot be rebuilt.
    pub fn image() -> Vec<u8> {
        let mut img = vec![0u8; CLUSTERS * CLUSTER];
        boot_sector(&mut img);

        let live_data: Vec<u8> = b"%PDF-1.7\nlive quarterly report\n%%EOF\n".to_vec();
        let deleted_data: Vec<u8> = {
            let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
            v.extend(std::iter::repeat_n(0x41, 200));
            v.extend([0xFF, 0xD9]);
            v
        };
        let orphan_data: Vec<u8> = b"orphaned note, parent directory record reused".to_vec();

        put(&mut img, LCN_LIVE * CLUSTER, &live_data);
        put(&mut img, LCN_DELETED * CLUSTER, &deleted_data);
        put(&mut img, LCN_ORPHAN * CLUSTER, &orphan_data);

        let mft_at = MFT_LCN * CLUSTER;

        // Record 0: $MFT itself. Its own run list is what the parser follows to
        // read every other record, so it has to cover them all.
        let mft_clusters = 8u64;
        put(
            &mut img,
            mft_at,
            &file_record(
                REC_MFT,
                true,
                false,
                vec![
                    standard_information(),
                    file_name(REC_ROOT, "$MFT", 3),
                    data_nonresident(
                        &runlist(&[(mft_clusters, MFT_LCN as i64)]),
                        mft_clusters * CLUSTER as u64,
                    ),
                ],
            ),
        );

        // Record 5: the root directory. build_path stops here by record number,
        // so its name is never used — but a real volume has one.
        put(
            &mut img,
            mft_at + REC_ROOT as usize * RECORD,
            &file_record(
                REC_ROOT,
                true,
                true,
                vec![standard_information(), file_name(REC_ROOT, ".", 3)],
            ),
        );

        // Record 16: a directory, so a recovered file has a path to rebuild.
        put(
            &mut img,
            mft_at + REC_DIR as usize * RECORD,
            &file_record(
                REC_DIR,
                true,
                true,
                vec![standard_information(), file_name(REC_ROOT, "Cases", 3)],
            ),
        );

        // Record 17: a live file.
        put(
            &mut img,
            mft_at + REC_LIVE as usize * RECORD,
            &file_record(
                REC_LIVE,
                true,
                false,
                vec![
                    standard_information(),
                    file_name(REC_DIR, "quarterly.pdf", 3),
                    data_nonresident(&runlist(&[(1, LCN_LIVE as i64)]), live_data.len() as u64),
                ],
            ),
        );

        // Record 18: deleted, with an intact run list. The case the whole
        // filesystem-aware path exists for.
        put(
            &mut img,
            mft_at + REC_DELETED as usize * RECORD,
            &file_record(
                REC_DELETED,
                false,
                false,
                vec![
                    standard_information(),
                    file_name(REC_DIR, "evidence-photo.jpg", 3),
                    data_nonresident(
                        &runlist(&[(1, LCN_DELETED as i64)]),
                        deleted_data.len() as u64,
                    ),
                ],
            ),
        );

        // Record 19: deleted, and its parent directory (record 40) does not
        // exist — the path is unrecoverable and must be reported as such rather
        // than invented.
        put(
            &mut img,
            mft_at + REC_ORPHAN as usize * RECORD,
            &file_record(
                REC_ORPHAN,
                false,
                false,
                vec![
                    standard_information(),
                    file_name(40, "orphan.txt", 3),
                    data_nonresident(
                        &runlist(&[(1, LCN_ORPHAN as i64)]),
                        orphan_data.len() as u64,
                    ),
                ],
            ),
        );

        img
    }

    fn boot_sector(img: &mut [u8]) {
        img[3..11].copy_from_slice(b"NTFS    ");
        img[0x0B..0x0D].copy_from_slice(&(BYTES_PER_SECTOR as u16).to_le_bytes());
        img[0x0D] = SECTORS_PER_CLUSTER as u8;
        img[0x28..0x30].copy_from_slice(&((CLUSTERS * SECTORS_PER_CLUSTER) as u64).to_le_bytes());
        img[0x30..0x38].copy_from_slice(&(MFT_LCN as u64).to_le_bytes());
        // Negative means 2^-n bytes per record: -10 gives 1024.
        img[0x38] = (-10i8) as u8;
        img[0x40] = 1;
        img[510] = 0x55;
        img[511] = 0xAA;
    }

    fn put(img: &mut [u8], at: usize, bytes: &[u8]) {
        img[at..at + bytes.len()].copy_from_slice(bytes);
    }

    /// Assemble one MFT record and apply the update sequence array, which is
    /// what the parser checks before it trusts anything in the record.
    pub fn file_record(
        number: u64,
        in_use: bool,
        is_directory: bool,
        attrs: Vec<Vec<u8>>,
    ) -> Vec<u8> {
        const USA_OFFSET: usize = 0x30;
        let sectors = RECORD / BYTES_PER_SECTOR;
        let usa_count = sectors + 1;
        let attrs_offset = (USA_OFFSET + usa_count * 2).next_multiple_of(8);

        let mut rec = vec![0u8; RECORD];
        rec[0..4].copy_from_slice(b"FILE");
        rec[0x04..0x06].copy_from_slice(&(USA_OFFSET as u16).to_le_bytes());
        rec[0x06..0x08].copy_from_slice(&(usa_count as u16).to_le_bytes());
        rec[0x10..0x12].copy_from_slice(&1u16.to_le_bytes()); // sequence
        rec[0x12..0x14].copy_from_slice(&1u16.to_le_bytes()); // hard links
        rec[0x14..0x16].copy_from_slice(&(attrs_offset as u16).to_le_bytes());
        let mut flags = 0u16;
        if in_use {
            flags |= 0x0001;
        }
        if is_directory {
            flags |= 0x0002;
        }
        rec[0x16..0x18].copy_from_slice(&flags.to_le_bytes());
        rec[0x1C..0x20].copy_from_slice(&(RECORD as u32).to_le_bytes());
        rec[0x20..0x28].copy_from_slice(&0u64.to_le_bytes()); // base record
        rec[0x2C..0x30].copy_from_slice(&(number as u32).to_le_bytes());

        let mut at = attrs_offset;
        for a in &attrs {
            rec[at..at + a.len()].copy_from_slice(a);
            at += a.len();
        }
        rec[at..at + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        at += 8;
        rec[0x18..0x1C].copy_from_slice(&(at as u32).to_le_bytes());

        // Reverse fixups: park each sector's last two bytes in the array and
        // stamp the sequence number in their place.
        let usn: u16 = 0x0001;
        rec[USA_OFFSET..USA_OFFSET + 2].copy_from_slice(&usn.to_le_bytes());
        for s in 0..sectors {
            let tail = (s + 1) * BYTES_PER_SECTOR - 2;
            let original = [rec[tail], rec[tail + 1]];
            rec[USA_OFFSET + 2 + s * 2..USA_OFFSET + 4 + s * 2].copy_from_slice(&original);
            rec[tail..tail + 2].copy_from_slice(&usn.to_le_bytes());
        }
        rec
    }

    fn resident_attr(attr_type: u32, value: &[u8]) -> Vec<u8> {
        let value_offset = 0x18usize;
        let len = (value_offset + value.len()).next_multiple_of(8);
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&attr_type.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[8] = 0; // resident
        a[0x0A..0x0C].copy_from_slice(&(value_offset as u16).to_le_bytes());
        a[0x10..0x14].copy_from_slice(&(value.len() as u32).to_le_bytes());
        a[0x14..0x16].copy_from_slice(&(value_offset as u16).to_le_bytes());
        a[value_offset..value_offset + value.len()].copy_from_slice(value);
        a
    }

    pub fn standard_information() -> Vec<u8> {
        let mut v = vec![0u8; 72];
        for slot in 0..4 {
            v[slot * 8..slot * 8 + 8].copy_from_slice(&FIXTURE_TIME.to_le_bytes());
        }
        resident_attr(0x10, &v)
    }

    pub fn file_name(parent: u64, name: &str, namespace: u8) -> Vec<u8> {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let mut v = vec![0u8; 0x42 + utf16.len() * 2];
        // Parent reference: record number in the low 48 bits, sequence above.
        v[0..8].copy_from_slice(&(parent | (1u64 << 48)).to_le_bytes());
        for slot in 0..4 {
            v[8 + slot * 8..16 + slot * 8].copy_from_slice(&FIXTURE_TIME.to_le_bytes());
        }
        v[0x40] = utf16.len() as u8;
        v[0x41] = namespace;
        for (i, u) in utf16.iter().enumerate() {
            v[0x42 + i * 2..0x44 + i * 2].copy_from_slice(&u.to_le_bytes());
        }
        resident_attr(0x30, &v)
    }

    /// Encode a run list from (cluster count, absolute LCN) pairs.
    pub fn runlist(runs: &[(u64, i64)]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut previous: i64 = 0;
        for (clusters, lcn) in runs {
            let delta = lcn - previous;
            previous = *lcn;
            let len_bytes = width_unsigned(*clusters);
            let off_bytes = width_signed(delta);
            out.push((len_bytes | (off_bytes << 4)) as u8);
            out.extend(&clusters.to_le_bytes()[..len_bytes]);
            out.extend(&delta.to_le_bytes()[..off_bytes]);
        }
        out.push(0);
        out
    }

    fn width_unsigned(v: u64) -> usize {
        (1..=8).find(|n| v < (1u64 << (n * 8 - 1))).unwrap_or(8)
    }

    fn width_signed(v: i64) -> usize {
        (1..=8)
            .find(|n| {
                let bits = n * 8 - 1;
                v >= -(1i64 << bits) && v < (1i64 << bits)
            })
            .unwrap_or(8)
    }

    pub fn data_nonresident(runs: &[u8], real_size: u64) -> Vec<u8> {
        let runs_offset = 0x40usize;
        let len = (runs_offset + runs.len()).next_multiple_of(8);
        let clusters = real_size.div_ceil(CLUSTER as u64).max(1);
        let mut a = vec![0u8; len];
        a[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        a[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        a[8] = 1; // non-resident
        a[0x0A..0x0C].copy_from_slice(&(runs_offset as u16).to_le_bytes());
        a[0x10..0x18].copy_from_slice(&0u64.to_le_bytes()); // start VCN
        a[0x18..0x20].copy_from_slice(&(clusters - 1).to_le_bytes()); // last VCN
        a[0x20..0x22].copy_from_slice(&(runs_offset as u16).to_le_bytes());
        a[0x28..0x30].copy_from_slice(&(clusters * CLUSTER as u64).to_le_bytes());
        a[0x30..0x38].copy_from_slice(&real_size.to_le_bytes());
        a[0x38..0x40].copy_from_slice(&real_size.to_le_bytes());
        a[runs_offset..runs_offset + runs.len()].copy_from_slice(runs);
        a
    }
}

// ---------------------------------------------------------------------------
// ext4
// ---------------------------------------------------------------------------

pub mod ext4 {
    pub const BLOCK: usize = 1024;
    pub const BLOCKS: usize = 128;
    pub const INODE_SIZE: usize = 256;
    pub const INODES: u32 = 32;
    pub const INODE_TABLE_BLOCK: usize = 5;
    pub const ROOT_DIR_BLOCK: usize = 20;
    pub const DELETED_DATA_BLOCK: usize = 30;
    pub const LIVE_DATA_BLOCK: usize = 40;

    pub const INODE_ROOT: u32 = 2;
    pub const INODE_DELETED: u32 = 12;
    pub const INODE_LIVE: u32 = 13;

    /// 2026-03-01T12:00:00Z.
    pub const FIXTURE_TIME: u32 = 1_772_366_400;

    const EXTENTS_FLAG: u32 = 0x0008_0000;
    const S_IFREG: u16 = 0x8000;
    const S_IFDIR: u16 = 0x4000;

    /// Build the fixture image: a root directory holding one live file and, in
    /// the slack behind it, the deleted entry for a file whose inode still
    /// carries an intact extent tree.
    pub fn image() -> Vec<u8> {
        let mut img = vec![0u8; BLOCKS * BLOCK];
        superblock(&mut img);
        group_descriptor(&mut img);
        root_directory(&mut img);

        let deleted_data = {
            let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0];
            v.extend(std::iter::repeat_n(0x42, 300));
            v.extend([0xFF, 0xD9]);
            v
        };
        let live_data = b"%PDF-1.7\nlive engagement notes\n%%EOF\n".to_vec();
        put(&mut img, DELETED_DATA_BLOCK * BLOCK, &deleted_data);
        put(&mut img, LIVE_DATA_BLOCK * BLOCK, &live_data);

        // Root: a directory whose single block holds the entries.
        write_inode(
            &mut img,
            INODE_ROOT,
            S_IFDIR | 0o755,
            BLOCK as u64,
            2,
            0,
            &[(0, ROOT_DIR_BLOCK as u64, 1)],
        );
        // The deleted file: unlinked, i_dtime set, extent tree untouched.
        write_inode(
            &mut img,
            INODE_DELETED,
            S_IFREG | 0o644,
            deleted_data.len() as u64,
            0,
            FIXTURE_TIME + 3600,
            &[(0, DELETED_DATA_BLOCK as u64, 1)],
        );
        write_inode(
            &mut img,
            INODE_LIVE,
            S_IFREG | 0o644,
            live_data.len() as u64,
            1,
            0,
            &[(0, LIVE_DATA_BLOCK as u64, 1)],
        );
        img
    }

    fn put(img: &mut [u8], at: usize, bytes: &[u8]) {
        img[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn superblock(img: &mut [u8]) {
        let sb = 1024;
        img[sb..sb + 4].copy_from_slice(&INODES.to_le_bytes()); // s_inodes_count
        img[sb + 4..sb + 8].copy_from_slice(&(BLOCKS as u32).to_le_bytes());
        img[sb + 0x14..sb + 0x18].copy_from_slice(&1u32.to_le_bytes()); // first data block
        img[sb + 0x18..sb + 0x1C].copy_from_slice(&0u32.to_le_bytes()); // log block size -> 1024
        img[sb + 0x20..sb + 0x24].copy_from_slice(&(BLOCKS as u32).to_le_bytes()); // blocks/group
        img[sb + 0x28..sb + 0x2C].copy_from_slice(&INODES.to_le_bytes()); // inodes/group
        img[sb + 0x38..sb + 0x3A].copy_from_slice(&0xEF53u16.to_le_bytes());
        img[sb + 0x4C..sb + 0x50].copy_from_slice(&1u32.to_le_bytes()); // rev level
        img[sb + 0x58..sb + 0x5A].copy_from_slice(&(INODE_SIZE as u16).to_le_bytes());
        img[sb + 0x60..sb + 0x64].copy_from_slice(&0x40u32.to_le_bytes()); // INCOMPAT_EXTENTS
        img[sb + 0xE0..sb + 0xE4].copy_from_slice(&8u32.to_le_bytes()); // journal inode
    }

    fn group_descriptor(img: &mut [u8]) {
        let gd = 2 * BLOCK;
        img[gd..gd + 4].copy_from_slice(&3u32.to_le_bytes()); // block bitmap
        img[gd + 4..gd + 8].copy_from_slice(&4u32.to_le_bytes()); // inode bitmap
        img[gd + 8..gd + 12].copy_from_slice(&(INODE_TABLE_BLOCK as u32).to_le_bytes());
    }

    /// The root directory block: `.`, `..`, one live entry, and behind the live
    /// entry's oversized `rec_len` the deleted entry that gives the recovered
    /// file its name.
    fn root_directory(img: &mut [u8]) {
        let b = ROOT_DIR_BLOCK * BLOCK;
        dir_entry(img, b, INODE_ROOT, 12, ".", 2);
        dir_entry(img, b + 12, INODE_ROOT, 12, "..", 2);
        // rec_len 64 leaves 48 bytes of slack after the 16 the entry needs.
        dir_entry(img, b + 24, INODE_LIVE, 64, "live.txt", 1);
        // The deleted entry, sitting in that slack exactly as a real unlink
        // leaves it.
        dir_entry(img, b + 40, INODE_DELETED, 32, "evidence-photo.jpg", 1);
        // Tail hole out to the end of the block.
        dir_entry(img, b + 88, 0, (BLOCK - 88) as u16, "", 0);
    }

    fn dir_entry(img: &mut [u8], at: usize, inode: u32, rec_len: u16, name: &str, kind: u8) {
        img[at..at + 4].copy_from_slice(&inode.to_le_bytes());
        img[at + 4..at + 6].copy_from_slice(&rec_len.to_le_bytes());
        img[at + 6] = name.len() as u8;
        img[at + 7] = kind;
        img[at + 8..at + 8 + name.len()].copy_from_slice(name.as_bytes());
    }

    /// Write one inode, with an extent tree built from (logical, physical, len).
    fn write_inode(
        img: &mut [u8],
        number: u32,
        mode: u16,
        size: u64,
        links: u16,
        dtime: u32,
        extents: &[(u32, u64, u16)],
    ) {
        let at = INODE_TABLE_BLOCK * BLOCK + (number as usize - 1) * INODE_SIZE;
        img[at..at + 2].copy_from_slice(&mode.to_le_bytes());
        img[at + 4..at + 8].copy_from_slice(&(size as u32).to_le_bytes());
        img[at + 8..at + 12].copy_from_slice(&FIXTURE_TIME.to_le_bytes()); // atime
        img[at + 12..at + 16].copy_from_slice(&FIXTURE_TIME.to_le_bytes()); // ctime
        img[at + 16..at + 20].copy_from_slice(&FIXTURE_TIME.to_le_bytes()); // mtime
        img[at + 20..at + 24].copy_from_slice(&dtime.to_le_bytes());
        img[at + 26..at + 28].copy_from_slice(&links.to_le_bytes());
        img[at + 32..at + 36].copy_from_slice(&EXTENTS_FLAG.to_le_bytes());

        let block = at + 0x28;
        img[block..block + 2].copy_from_slice(&0xF30Au16.to_le_bytes());
        img[block + 2..block + 4].copy_from_slice(&(extents.len() as u16).to_le_bytes());
        img[block + 4..block + 6].copy_from_slice(&4u16.to_le_bytes()); // eh_max
        img[block + 6..block + 8].copy_from_slice(&0u16.to_le_bytes()); // depth 0
        for (i, (logical, physical, len)) in extents.iter().enumerate() {
            let e = block + 12 + i * 12;
            img[e..e + 4].copy_from_slice(&logical.to_le_bytes());
            img[e + 4..e + 6].copy_from_slice(&len.to_le_bytes());
            img[e + 6..e + 8].copy_from_slice(&((physical >> 32) as u16).to_le_bytes());
            img[e + 8..e + 12].copy_from_slice(&(*physical as u32).to_le_bytes());
        }
    }
}
