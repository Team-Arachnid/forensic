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
}
