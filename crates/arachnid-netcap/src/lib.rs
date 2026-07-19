//! Live packet capture and offline PCAP analysis.
//!
//! **Capture and parse only.** This crate opens capture handles and reads
//! savefiles. It never transmits: no injection, no ARP or DNS spoofing, no
//! interception. `pcap::Capture` is opened for reading and the send path is
//! never called. Anything that would require transmitting is out of scope by
//! design, not by omission.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

mod indicators;
mod reassemble;

pub use indicators::Indicator;
use reassemble::StreamAssembler;

/// Per-flow reassembly ceiling. A capture holding a multi-gigabyte download must
/// not put that download in RAM; indicators live in the first few KiB anyway.
pub const DEFAULT_MAX_STREAM_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub loopback: bool,
}

/// Interfaces available for capture. Requires the same privilege as capture
/// itself (root / `CAP_NET_RAW` on Linux, Npcap driver access on Windows).
pub fn list_devices() -> Result<Vec<DeviceInfo>> {
    Ok(pcap::Device::list()
        .context("enumerate capture devices")?
        .into_iter()
        .map(|d| DeviceInfo {
            loopback: d.flags.is_loopback(),
            name: d.name,
            description: d.desc,
            addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
        })
        .collect())
}
