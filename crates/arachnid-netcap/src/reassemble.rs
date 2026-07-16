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
