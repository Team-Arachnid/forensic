//! Indicator extraction: what an analyst pivots on.
//!
//! Everything here is derived from bytes that were actually captured. Nothing is
//! resolved, enriched, or looked up against a remote service — a triage tool that
//! phones out about the indicators it found leaks the investigation.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::Decoded;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Indicator {
    /// `ipv4` | `ipv6` | `dns_query` | `dns_answer` | `tls_sni` | `http_host` | `http_uri` | `http_user_agent`
    pub kind: String,
    pub value: String,
    pub count: u64,
    pub first_seen_utc: String,
    pub last_seen_utc: String,
    /// Where it came from, e.g. the flow that carried it.
    pub context: Option<String>,
}
