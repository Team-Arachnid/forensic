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

#[derive(Default)]
pub(crate) struct Collector {
    seen: HashMap<(String, String), Indicator>,
}

impl Collector {
    fn record(&mut self, kind: &str, value: &str, ts: &str, context: Option<String>) {
        if value.is_empty() {
            return;
        }
        self.seen
            .entry((kind.to_string(), value.to_string()))
            .and_modify(|i| {
                i.count += 1;
                i.last_seen_utc = ts.to_string();
            })
            .or_insert_with(|| Indicator {
                kind: kind.into(),
                value: value.into(),
                count: 1,
                first_seen_utc: ts.into(),
                last_seen_utc: ts.into(),
                context,
            });
    }
}
