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

    pub fn observe_addresses(&mut self, src: &str, dst: &str, ts: &str) {
        for a in [src, dst] {
            let kind = if a.contains(':') { "ipv6" } else { "ipv4" };
            self.record(kind, a, ts, None);
        }
    }

    pub fn observe_udp(&mut self, d: &Decoded, ts: &str) {
        if d.src_port == 53 || d.dst_port == 53 || d.src_port == 5353 || d.dst_port == 5353 {
            let ctx = format!(
                "{}:{} -> {}:{}",
                d.src_addr, d.src_port, d.dst_addr, d.dst_port
            );
            for (kind, name) in parse_dns(&d.payload) {
                self.record(kind, &name, ts, Some(ctx.clone()));
            }
        }
    }

    /// Extract indicators from a reassembled TCP stream.
    pub fn observe_stream(
        &mut self,
        src: &str,
        sport: u16,
        dst: &str,
        dport: u16,
        data: &[u8],
        ts: &str,
    ) {
        if data.is_empty() {
            return;
        }
        let ctx = format!("{src}:{sport} -> {dst}:{dport}");

        if let Some(sni) = parse_tls_sni(data) {
            self.record("tls_sni", &sni, ts, Some(ctx.clone()));
        }
        // DNS over TCP is length-prefixed; the message follows a 2-byte length.
        if (sport == 53 || dport == 53) && data.len() > 2 {
            for (kind, name) in parse_dns(&data[2..]) {
                self.record(kind, &name, ts, Some(ctx.clone()));
            }
        }
        for (kind, value) in parse_http(data) {
            self.record(kind, &value, ts, Some(ctx.clone()));
        }
    }
}
