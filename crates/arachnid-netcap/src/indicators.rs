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

/// Extract the SNI hostname from a TLS ClientHello at the start of a stream.
///
/// Reassembly runs first, so a ClientHello split across segments still parses.
/// Encrypted ClientHello and TLS 1.3 without SNI simply yield `None`; this reads
/// the plaintext handshake and does not attempt to decrypt anything.
fn parse_tls_sni(data: &[u8]) -> Option<String> {
    // TLS record: type(1) version(2) length(2)
    if *data.first()? != 0x16 {
        return None;
    }
    let rec_len = u16::from_be_bytes([*data.get(3)?, *data.get(4)?]) as usize;
    let body = data.get(5..(5 + rec_len).min(data.len()))?;

    // Handshake: type(1) length(3) version(2) random(32)
    if *body.first()? != 0x01 {
        return None;
    }
    let mut p = 4 + 2 + 32;

    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;

    let cs_len = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2 + cs_len;

    let comp_len = *body.get(p)? as usize;
    p += 1 + comp_len;

    let ext_total = u16::from_be_bytes([*body.get(p)?, *body.get(p + 1)?]) as usize;
    p += 2;
    let ext_end = (p + ext_total).min(body.len());

    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[p], body[p + 1]]);
        let ext_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        let ext = body.get(p + 4..p + 4 + ext_len)?;
        if ext_type == 0x0000 {
            // server_name: list_len(2) name_type(1) name_len(2) name
            let name_len = u16::from_be_bytes([*ext.get(3)?, *ext.get(4)?]) as usize;
            let name = ext.get(5..5 + name_len)?;
            return Some(String::from_utf8_lossy(name).into_owned());
        }
        p += 4 + ext_len;
    }
    None
}

const HTTP_METHODS: &[&str] = &[
    "GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "PATCH ", "TRACE ", "CONNECT ",
];

/// Pull request lines and the headers worth pivoting on out of a cleartext HTTP
/// stream. Deliberately line-based rather than a full HTTP parser: a reassembled
/// stream can hold several pipelined requests and a truncated tail, which a
/// strict parser would reject outright.
fn parse_http(data: &[u8]) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    // Bound the scan: indicators live in the headers, not in a 8 MiB body.
    let head = &data[..data.len().min(64 * 1024)];
    let text = String::from_utf8_lossy(head);
    let mut in_headers = false;

    for line in text.split("\r\n").chain(std::iter::once("")) {
        if HTTP_METHODS.iter().any(|m| line.starts_with(m)) {
            if let Some(uri) = line.split_whitespace().nth(1) {
                if line.contains("HTTP/1.") {
                    out.push(("http_uri", uri.to_string()));
                    in_headers = true;
                }
            }
            continue;
        }
        if !in_headers {
            continue;
        }
        if line.is_empty() {
            in_headers = false;
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.to_ascii_lowercase().as_str() {
            "host" => out.push(("http_host", value.to_string())),
            "user-agent" => out.push(("http_user_agent", value.to_string())),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `www.example.com` A query.
    fn dns_query_msg() -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in ["www", "example", "com"] {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.extend_from_slice(&[0, 0, 1, 0, 1]);
        m
    }

    #[test]
    fn dns_query_name_is_extracted() {
        let got = parse_dns(&dns_query_msg());
        assert_eq!(got, vec![("dns_query", "www.example.com".to_string())]);
    }

    #[test]
    fn dns_answer_a_record_is_extracted() {
        let mut m = dns_query_msg();
        m[6] = 0;
        m[7] = 1; // one answer
        m.extend_from_slice(&[0xc0, 0x0c]); // pointer back to the question name
        m.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        m.extend_from_slice(&[93, 184, 216, 34]);
        let got = parse_dns(&m);
        assert!(
            got.contains(&("dns_answer", "www.example.com -> 93.184.216.34".to_string())),
            "{got:?}"
        );
    }

    #[test]
    fn a_compression_pointer_loop_terminates() {
        // Name at offset 12 points at itself.
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[0xc0, 0x0c]);
        assert!(parse_dns(&m).is_empty());
    }

    #[test]
    fn truncated_dns_does_not_panic() {
        for n in 0..dns_query_msg().len() {
            let _ = parse_dns(&dns_query_msg()[..n]);
        }
    }

    /// Minimal ClientHello advertising SNI `example.org`.
    fn client_hello(host: &str) -> Vec<u8> {
        let mut sni = vec![0x00]; // name_type = host_name
        sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
        sni.extend_from_slice(host.as_bytes());
        let mut list = ((sni.len()) as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&sni);

        let mut ext = vec![0x00, 0x00]; // extension_type = server_name
        ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
        ext.extend_from_slice(&list);

        let mut body = vec![0x01, 0, 0, 0]; // handshake type + length placeholder
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0); // empty session id
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // one cipher suite
        body.extend_from_slice(&[0x01, 0x00]); // one compression method
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);

        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        rec
    }
}
