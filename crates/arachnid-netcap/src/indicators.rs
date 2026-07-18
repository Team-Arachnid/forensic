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

    pub fn finish(self) -> Vec<Indicator> {
        let mut out: Vec<Indicator> = self.seen.into_values().collect();
        out.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then(b.count.cmp(&a.count))
                .then(a.value.cmp(&b.value))
        });
        out
    }
}

/// Decode a DNS name at `pos`, following compression pointers.
///
/// Returns the name and the offset just past the name *in the wire format*,
/// which is not where a followed pointer ended up.
fn read_name(msg: &[u8], mut pos: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut end = None;
    // A malicious or corrupt message can point in a cycle; bound the walk.
    let mut budget = 128;

    loop {
        budget -= 1;
        if budget == 0 {
            return None;
        }
        let len = *msg.get(pos)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(pos + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(pos + 1)? as usize;
            end.get_or_insert(pos + 2);
            if ptr >= msg.len() {
                return None;
            }
            pos = ptr;
            continue;
        }
        let label = msg.get(pos + 1..pos + 1 + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        pos += 1 + len;
    }
}

/// Pull query names and the names inside CNAME/NS answers out of a DNS message.
/// Malformed messages yield whatever parsed cleanly before the break.
fn parse_dns(msg: &[u8]) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if msg.len() < 12 {
        return out;
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut pos = 12;

    for _ in 0..qd.min(64) {
        let Some((name, next)) = read_name(msg, pos) else {
            return out;
        };
        out.push(("dns_query", name));
        pos = next + 4; // QTYPE + QCLASS
    }

    for _ in 0..an.min(64) {
        let Some((name, next)) = read_name(msg, pos) else {
            return out;
        };
        if msg.len() < next + 10 {
            return out;
        }
        let rtype = u16::from_be_bytes([msg[next], msg[next + 1]]);
        let rdlen = u16::from_be_bytes([msg[next + 8], msg[next + 9]]) as usize;
        let rdata = next + 10;
        match rtype {
            1 if rdlen == 4 => {
                let ip = std::net::Ipv4Addr::from(
                    <[u8; 4]>::try_from(msg.get(rdata..rdata + 4).unwrap_or(&[0; 4]))
                        .unwrap_or([0; 4]),
                );
                out.push(("dns_answer", format!("{name} -> {ip}")));
            }
            28 if rdlen == 16 => {
                let ip = std::net::Ipv6Addr::from(
                    <[u8; 16]>::try_from(msg.get(rdata..rdata + 16).unwrap_or(&[0; 16]))
                        .unwrap_or([0; 16]),
                );
                out.push(("dns_answer", format!("{name} -> {ip}")));
            }
            5 => {
                if let Some((target, _)) = read_name(msg, rdata) {
                    out.push(("dns_answer", format!("{name} -> {target}")));
                }
            }
            _ => {}
        }
        pos = rdata + rdlen;
    }
    out
}
