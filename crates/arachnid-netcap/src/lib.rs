//! Live packet capture and offline PCAP analysis.
//!
//! **Capture and parse only.** This crate opens capture handles and reads
//! savefiles. It never transmits: no injection, no ARP or DNS spoofing, no
//! interception. `pcap::Capture` is opened for reading and the send path is
//! never called. Anything that would require transmitting is out of scope by
//! design, not by omission.

use std::collections::HashMap;
use std::path::Path;
