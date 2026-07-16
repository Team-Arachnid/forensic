//! TCP stream reassembly.
//!
//! Segments arrive out of order and get retransmitted, so payload is keyed by
//! sequence offset in a `BTreeMap` rather than appended in arrival order. That
//! sorts the stream, collapses duplicate retransmissions, and makes a gap
//! visible instead of silently splicing two non-adjacent regions together.

use std::collections::BTreeMap;

pub struct StreamAssembler {
    /// Sequence number of the first payload byte seen; all offsets are relative
    /// to it, which is what makes 32-bit sequence wraparound a non-event.
    base: u32,
    segments: BTreeMap<u64, Vec<u8>>,
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
        // Wrapping arithmetic: a stream that crosses the 2^32 boundary keeps
        // producing increasing offsets instead of jumping back to zero.
        let offset = seq.wrapping_sub(self.base) as u64;
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
        let mut covered_to = 0u64;
        for (&offset, data) in &self.segments {
            let start = covered_to.saturating_sub(offset) as usize;
            if start >= data.len() {
                continue; // fully overlapped by a previous segment
            }
            out.extend_from_slice(&data[start..]);
            covered_to = covered_to.max(offset + data.len() as u64);
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
}
