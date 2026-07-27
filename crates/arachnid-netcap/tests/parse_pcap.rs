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
