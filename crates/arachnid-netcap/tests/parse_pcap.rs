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
