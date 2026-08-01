//! TCP stream reassembly.
//!
//! Segments arrive out of order and get retransmitted, so payload is keyed by
//! sequence offset in a `BTreeMap` rather than appended in arrival order. That
//! sorts the stream, collapses duplicate retransmissions, and makes a gap
//! visible instead of silently splicing two non-adjacent regions together.
//!
//! Offsets are *signed* deltas from the first sequence number seen. The first
//! segment captured is not necessarily the lowest one — a reordered network or a
//! capture that starts mid-stream both break that assumption — so a segment
//! preceding the base gets a negative offset and still sorts into place. Signed
//! 32-bit arithmetic is also what makes sequence wraparound a non-event, on the
//! usual TCP assumption that a live window spans well under 2 GiB.

use std::collections::BTreeMap;

pub struct StreamAssembler {
    /// Sequence number of the first payload byte seen. Offsets are signed deltas
    /// from it, so a segment that precedes it sorts ahead of it.
    base: u32,
    segments: BTreeMap<i64, Vec<u8>>,
    stored: usize,
    limit: usize,
    pub truncated: bool,
}

impl StreamAssembler {
    pub fn new(first_seq: u32, limit: usize) -> Self {
        StreamAssembler {
            base: first_seq,
            segments: BTreeMap::new(),
            stored: 0,
            limit,
            truncated: false,
        }
    }

    pub fn push(&mut self, seq: u32, payload: &[u8]) {
        if payload.is_empty() || self.stored >= self.limit {
            self.truncated |= self.stored >= self.limit;
            return;
        }
        // Signed wrapping delta: handles both a stream crossing the 2^32 boundary
        // and a segment that arrives before the one we happened to see first.
        let offset = i64::from(seq.wrapping_sub(self.base) as i32);
        let take = payload.len().min(self.limit - self.stored);
        if take < payload.len() {
            self.truncated = true;
        }
        // A retransmission of an already-stored offset is dropped unless it
        // carries more data than what we have.
        match self.segments.get(&offset) {
            Some(existing) if existing.len() >= take => return,
            Some(existing) => self.stored -= existing.len(),
            None => {}
        }
        self.stored += take;
        self.segments.insert(offset, payload[..take].to_vec());
    }

    /// Concatenate in sequence order, skipping regions already covered by an
    /// earlier segment. A hole in the stream is simply absent: the bytes were
    /// never captured, and inventing filler would be fabricating evidence.
    pub fn finish(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.stored);
        let mut covered_to: Option<i64> = None;
        for (&offset, data) in &self.segments {
            let start = match covered_to {
                Some(c) if c > offset => (c - offset) as usize,
                _ => 0,
            };
            if start >= data.len() {
                continue; // fully overlapped by a previous segment
            }
            out.extend_from_slice(&data[start..]);
            covered_to = Some(offset + data.len() as i64);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn asm(first: u32) -> StreamAssembler {
        StreamAssembler::new(first, 1 << 20)
    }

    #[test]
    fn in_order_segments_concatenate() {
        let mut a = asm(100);
        a.push(100, b"hello ");
        a.push(106, b"world");
        assert_eq!(a.finish(), b"hello world");
        assert!(!a.truncated);
    }

    #[test]
    fn out_of_order_segments_are_sorted() {
        let mut a = asm(100);
        a.push(106, b"world");
        a.push(100, b"hello ");
        assert_eq!(a.finish(), b"hello world");
    }

    #[test]
    fn exact_retransmission_is_deduplicated() {
        let mut a = asm(100);
        a.push(100, b"hello ");
        a.push(100, b"hello ");
        a.push(106, b"world");
        assert_eq!(a.finish(), b"hello world");
    }

    #[test]
    fn overlapping_retransmission_does_not_duplicate_bytes() {
        let mut a = asm(100);
        a.push(100, b"hello ");
        a.push(103, b"lo world"); // overlaps the tail of the first segment
        assert_eq!(a.finish(), b"hello world");
    }

    #[test]
    fn longer_retransmission_of_the_same_offset_wins() {
        let mut a = asm(100);
        a.push(100, b"hel");
        a.push(100, b"hello");
        assert_eq!(a.finish(), b"hello");
    }

    #[test]
    fn a_segment_preceding_the_first_one_seen_still_sorts_first() {
        // The capture began mid-stream, or the network reordered: the first
        // segment we saw is not the lowest sequence number.
        let mut a = asm(106);
        a.push(106, b"world");
        a.push(100, b"hello ");
        assert_eq!(a.finish(), b"hello world");
    }

    #[test]
    fn sequence_wraparound_stays_in_order() {
        let mut a = asm(u32::MAX - 2);
        a.push(u32::MAX - 2, b"abc"); // offsets 0..3
        a.push(1, b"de"); // wraps past 2^32; offset 4
        assert_eq!(a.finish(), b"abcde");
    }

    #[test]
    fn a_gap_is_left_as_a_gap() {
        let mut a = asm(100);
        a.push(100, b"aaa");
        a.push(200, b"bbb"); // 97 bytes never captured
                             // Missing bytes are omitted, not fabricated as zeroes.
        assert_eq!(a.finish(), b"aaabbb");
    }

    #[test]
    fn the_limit_truncates_and_says_so() {
        let mut a = StreamAssembler::new(0, 4);
        a.push(0, b"aaaa");
        a.push(4, b"bbbb");
        assert_eq!(a.finish(), b"aaaa");
        assert!(a.truncated);
    }

    #[test]
    fn empty_payloads_are_ignored() {
        let mut a = asm(100);
        a.push(100, b"");
        assert!(a.finish().is_empty());
        assert!(!a.truncated);
    }
}
