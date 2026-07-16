//! TCP stream reassembly.
//!
//! Segments arrive out of order and get retransmitted, so payload is keyed by
//! sequence offset in a `BTreeMap` rather than appended in arrival order. That
//! sorts the stream, collapses duplicate retransmissions, and makes a gap
//! visible instead of silently splicing two non-adjacent regions together.

use std::collections::BTreeMap;
