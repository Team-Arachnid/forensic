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

#[derive(Debug, Clone)]
pub struct LiveOptions {
    pub device: String,
    /// BPF filter, applied in the kernel so filtered traffic is never copied.
    pub filter: Option<String>,
    pub snaplen: i32,
    pub promiscuous: bool,
    /// Stop after this many packets. `None` for unlimited.
    pub max_packets: Option<u64>,
    /// Stop after this long. `None` for unlimited.
    pub duration: Option<Duration>,
}

impl Default for LiveOptions {
    fn default() -> Self {
        LiveOptions {
            device: String::new(),
            filter: None,
            // Full frames: a truncated payload is a truncated indicator.
            snaplen: 65535,
            promiscuous: false,
            max_packets: None,
            duration: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureStats {
    pub device: String,
    pub filter: Option<String>,
    pub promiscuous: bool,
    pub snaplen: i32,
    pub datalink: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub packets_written: u64,
    pub bytes_written: u64,
    /// Dropped by the kernel or the driver: the capture did not keep up, and the
    /// resulting evidence has gaps. Non-zero is a finding, not a nuisance.
    pub packets_dropped_kernel: u64,
    pub packets_dropped_interface: u64,
    pub stop_reason: String,
}

/// Capture live traffic to a PCAP savefile.
///
/// Returns when a limit in `opts` is reached or `stop` is set. The savefile is
/// flushed before returning, including on the `stop` path, so an operator-
/// interrupted capture still yields a readable file.
pub fn capture_live(opts: &LiveOptions, out: &Path, stop: &AtomicBool) -> Result<CaptureStats> {
    let device = pcap::Device::list()
        .context("enumerate capture devices")?
        .into_iter()
        .find(|d| d.name == opts.device)
        .with_context(|| format!("capture device {:?} not found", opts.device))?;

    let mut cap = pcap::Capture::from_device(device)
        .context("open capture device")?
        .promisc(opts.promiscuous)
        .snaplen(opts.snaplen)
        // Bounded read timeout, so `stop` is honoured on an idle link instead of
        // blocking in the driver until the next packet arrives.
        .timeout(250)
        .immediate_mode(true)
        .open()
        .with_context(|| {
            format!(
                "open {:?} for capture (needs root/CAP_NET_RAW on Linux, Npcap on Windows)",
                opts.device
            )
        })?
        .setnonblock()
        .context("set non-blocking capture")?;

    if let Some(f) = &opts.filter {
        cap.filter(f, true)
            .with_context(|| format!("apply BPF filter {f:?}"))?;
    }

    let datalink = format!("{:?}", cap.get_datalink());
    let started_utc = now_utc();
    let start = Instant::now();
    let mut savefile = cap
        .savefile(out)
        .with_context(|| format!("create savefile {}", out.display()))?;

    let mut packets = 0u64;
    let mut bytes = 0u64;
    let stop_reason = loop {
        if stop.load(Ordering::Relaxed) {
            break "interrupted by operator";
        }
        if opts.max_packets.is_some_and(|m| packets >= m) {
            break "packet limit reached";
        }
        if opts.duration.is_some_and(|d| start.elapsed() >= d) {
            break "duration elapsed";
        }
        match cap.next_packet() {
            Ok(pkt) => {
                bytes += pkt.header.caplen as u64;
                packets += 1;
                savefile.write(&pkt);
            }
            Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => {
                // Non-blocking mode returns immediately; yield instead of spinning.
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => {
                savefile.flush().ok();
                return Err(anyhow::Error::new(e).context("read from capture device"));
            }
        }
    };

    savefile.flush().context("flush savefile")?;
    drop(savefile);

    let s = cap.stats().unwrap_or(pcap::Stat {
        received: 0,
        dropped: 0,
        if_dropped: 0,
    });
    if s.dropped > 0 || s.if_dropped > 0 {
        tracing::warn!(
            kernel = s.dropped,
            interface = s.if_dropped,
            "packets were dropped; this capture has gaps"
        );
    }

    Ok(CaptureStats {
        device: opts.device.clone(),
        filter: opts.filter.clone(),
        promiscuous: opts.promiscuous,
        snaplen: opts.snaplen,
        datalink,
        started_utc,
        finished_utc: now_utc(),
        packets_written: packets,
        bytes_written: bytes,
        packets_dropped_kernel: s.dropped as u64,
        packets_dropped_interface: s.if_dropped as u64,
        stop_reason: stop_reason.into(),
    })
}
