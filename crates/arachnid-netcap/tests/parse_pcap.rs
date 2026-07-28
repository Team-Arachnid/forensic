//! End-to-end parse of a synthetic PCAP.
//!
//! The file is built byte by byte here rather than checked in as a fixture, so
//! the test states exactly what traffic it expects indicators to come from.

use std::path::PathBuf;

use arachnid_netcap::{parse_pcap, ParseOptions};

const SRC: [u8; 4] = [192, 168, 1, 50];
const DST: [u8; 4] = [93, 184, 216, 34];

struct PcapBuilder {
    bytes: Vec<u8>,
    ts: u32,
}

impl PcapBuilder {
    fn new() -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xa1b2c3d4u32.to_le_bytes()); // magic
        bytes.extend_from_slice(&2u16.to_le_bytes()); // version major
        bytes.extend_from_slice(&4u16.to_le_bytes()); // version minor
        bytes.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        bytes.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        bytes.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        bytes.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
        PcapBuilder {
            bytes,
            ts: 1_767_225_600,
        } // 2026-01-01T00:00:00Z
    }

    fn packet(&mut self, frame: &[u8]) {
        self.bytes.extend_from_slice(&self.ts.to_le_bytes());
        self.bytes.extend_from_slice(&0u32.to_le_bytes());
        self.bytes
            .extend_from_slice(&(frame.len() as u32).to_le_bytes());
        self.bytes
            .extend_from_slice(&(frame.len() as u32).to_le_bytes());
        self.bytes.extend_from_slice(frame);
        self.ts += 1;
    }

    fn udp(&mut self, src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: &[u8]) {
        let mut udp = Vec::new();
        udp.extend_from_slice(&sport.to_be_bytes());
        udp.extend_from_slice(&dport.to_be_bytes());
        udp.extend_from_slice(&((payload.len() + 8) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes()); // checksum: optional over IPv4
        udp.extend_from_slice(payload);
        self.packet(&frame(src, dst, 17, &udp));
    }

    fn tcp(
        &mut self,
        src: [u8; 4],
        sport: u16,
        dst: [u8; 4],
        dport: u16,
        seq: u32,
        payload: &[u8],
    ) {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&sport.to_be_bytes());
        tcp.extend_from_slice(&dport.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
        tcp.push(5 << 4); // data offset = 5 words, no options
        tcp.push(0x18); // PSH | ACK
        tcp.extend_from_slice(&65535u16.to_be_bytes()); // window
        tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum
        tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent
        tcp.extend_from_slice(payload);
        self.packet(&frame(src, dst, 6, &tcp));
    }

    fn write(&self, name: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("arachnid-it-{}-{name}.pcap", std::process::id()));
        std::fs::write(&p, &self.bytes).unwrap();
        p
    }
}

/// Ethernet II + IPv4 around a transport payload.
fn frame(src: [u8; 4], dst: [u8; 4], proto: u8, transport: &[u8]) -> Vec<u8> {
    let mut ip = vec![0x45, 0x00];
    ip.extend_from_slice(&((20 + transport.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x01, 0x40, 0x00, 64, proto, 0x00, 0x00]);
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    ip.extend_from_slice(transport);

    let mut eth = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00];
    eth.extend_from_slice(&ip);
    eth
}

fn dns_query(name: &str) -> Vec<u8> {
    let mut m = vec![0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in name.split('.') {
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.extend_from_slice(&[0, 0, 1, 0, 1]);
    m
}

fn client_hello(host: &str) -> Vec<u8> {
    let mut sni = vec![0x00];
    sni.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni.extend_from_slice(host.as_bytes());
    let mut list = (sni.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&sni);
    let mut ext = vec![0x00, 0x00];
    ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&list);

    let mut body = vec![0x01, 0, 0, 0, 0x03, 0x03];
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01, 0x01, 0x00]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
    rec.extend_from_slice(&body);
    rec
}

fn indicator<'a>(
    a: &'a arachnid_netcap::PcapAnalysis,
    kind: &str,
    value: &str,
) -> Option<&'a arachnid_netcap::Indicator> {
    a.indicators
        .iter()
        .find(|i| i.kind == kind && i.value == value)
}

#[test]
fn a_mixed_capture_yields_flows_and_indicators() {
    let mut b = PcapBuilder::new();

    b.udp(
        SRC,
        51234,
        [1, 1, 1, 1],
        53,
        &dns_query("malware.example.com"),
    );

    // HTTP request delivered out of order and with a duplicate segment, which is
    // what reassembly exists to survive.
    let req =
        b"GET /payload.bin HTTP/1.1\r\nHost: evil.example\r\nUser-Agent: Arachnid-Test/1.0\r\n\r\n";
    let (head, tail) = req.split_at(30);
    b.tcp(SRC, 40001, DST, 80, 1000 + head.len() as u32, tail);
    b.tcp(SRC, 40001, DST, 80, 1000, head);
    b.tcp(SRC, 40001, DST, 80, 1000, head); // retransmission

    b.tcp(SRC, 40002, DST, 443, 5000, &client_hello("c2.example.net"));

    let path = b.write("mixed");
    let a = parse_pcap(&path, &ParseOptions::default()).unwrap();

    assert_eq!(a.packets, 5);
    assert_eq!(a.decode_errors, 0, "every synthetic frame should decode");
    assert_eq!(a.first_packet_utc.as_deref(), Some("2026-01-01T00:00:00Z"));

    // udp:53, tcp:80, tcp:443
    assert_eq!(a.flows.len(), 3, "{:#?}", a.flows);
    let http_flow = a.flows.iter().find(|f| f.dst_port == 80).unwrap();
    assert_eq!(http_flow.packets, 3);
    assert_eq!(
        http_flow.reassembled_bytes,
        req.len() as u64,
        "retransmission should not inflate the stream"
    );
    assert!(!http_flow.truncated);

    assert!(
        indicator(&a, "dns_query", "malware.example.com").is_some(),
        "{:#?}",
        a.indicators
    );
    assert!(
        indicator(&a, "tls_sni", "c2.example.net").is_some(),
        "{:#?}",
        a.indicators
    );
    assert!(
        indicator(&a, "http_host", "evil.example").is_some(),
        "{:#?}",
        a.indicators
    );
    assert!(
        indicator(&a, "http_uri", "/payload.bin").is_some(),
        "{:#?}",
        a.indicators
    );
    assert!(indicator(&a, "http_user_agent", "Arachnid-Test/1.0").is_some());

    // 93.184.216.34 appears in both TCP flows.
    assert_eq!(indicator(&a, "ipv4", "93.184.216.34").unwrap().count, 4);
    assert!(indicator(&a, "ipv4", "1.1.1.1").is_some());

    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_bpf_filter_narrows_the_parse() {
    let mut b = PcapBuilder::new();
    b.udp(SRC, 51234, [1, 1, 1, 1], 53, &dns_query("example.com"));
    b.tcp(SRC, 40002, DST, 443, 5000, &client_hello("c2.example.net"));
    let path = b.write("filtered");

    let a = parse_pcap(
        &path,
        &ParseOptions {
            filter: Some("tcp port 443".into()),
            ..Default::default()
        },
    )
    .unwrap();

    assert_eq!(a.packets, 1);
    assert_eq!(a.flows.len(), 1);
    assert!(indicator(&a, "tls_sni", "c2.example.net").is_some());
    assert!(
        indicator(&a, "dns_query", "example.com").is_none(),
        "filter should have excluded DNS"
    );

    std::fs::remove_file(&path).unwrap();
}

#[test]
fn the_reassembly_ceiling_is_reported_not_silent() {
    let mut b = PcapBuilder::new();
    let chunk = vec![b'A'; 1000];
    for i in 0..4u32 {
        b.tcp(SRC, 40003, DST, 8080, 1 + i * 1000, &chunk);
    }
    let path = b.write("truncated");

    let a = parse_pcap(
        &path,
        &ParseOptions {
            max_stream_bytes: 1500,
            ..Default::default()
        },
    )
    .unwrap();

    let flow = &a.flows[0];
    assert_eq!(flow.reassembled_bytes, 1500);
    assert!(
        flow.truncated,
        "hitting the ceiling must be visible to the analyst"
    );

    std::fs::remove_file(&path).unwrap();
}
