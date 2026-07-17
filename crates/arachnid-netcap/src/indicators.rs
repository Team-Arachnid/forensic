//! Indicator extraction: what an analyst pivots on.
//!
//! Everything here is derived from bytes that were actually captured. Nothing is
//! resolved, enriched, or looked up against a remote service — a triage tool that
//! phones out about the indicators it found leaks the investigation.

use std::collections::HashMap;
