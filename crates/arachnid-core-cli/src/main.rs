//! Arachnid Core — live triage and network forensics.
//!
//! Part of the Arachnid Forensic suite. For use by authorized analysts on
//! systems they have permission to examine.
//!
//! Every subcommand is read-only against the target system; the only writes go
//! to the evidence container the operator names. See `docs/SOC-ALLOWLISTING.md`
//! for the full list of paths and APIs this binary touches.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arachnid_collect as collect;
use arachnid_evidence::{Container, VerifyReport};
use arachnid_netcap as netcap;
use arachnid_report::{to_html, to_markdown, Report};
use clap::{Args, Parser, Subcommand, ValueEnum};

/// Exit codes, stable across releases so SOAR playbooks can branch on them.
mod exit {
    /// Everything requested completed.
    pub const OK: u8 = 0;
    /// Runtime failure: I/O, permission, missing device, unusable input.
    pub const ERROR: u8 = 1;
    /// Reserved: clap uses 2 for argument and usage errors.
    pub const _USAGE: u8 = 2;
    /// Integrity failure. `verify` found a container that does not check out.
    pub const INTEGRITY: u8 = 3;
    /// The run produced evidence, but at least one collector was degraded.
    pub const PARTIAL: u8 = 4;
}

#[derive(Parser)]
#[command(
    name = "arachnid-core",
    version,
    about = "Arachnid Core — live triage and network forensics (Arachnid Forensic suite)",
    long_about = "Arachnid Core collects volatile system state and network evidence into a \
tamper-evident, signed container.\n\n\
Read-only against the target: the only writes go to the evidence container you name.\n\n\
EXIT CODES\n  \
0  success\n  \
1  runtime error\n  \
2  usage error\n  \
3  integrity failure (verify found a problem)\n  \
4  completed, but one or more collectors were degraded (see report warnings)"
)]
struct Cli {
    /// Operational log destination. Distinct from the evidence log, which always
    /// lives in the container and is never written here.
    #[arg(long, global = true, value_name = "PATH")]
    log: Option<PathBuf>,

    /// Operational log verbosity.
    #[arg(long, global = true, default_value = "info", value_name = "LEVEL")]
    log_level: String,

    /// Emit machine-readable JSON on stdout instead of a human summary.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Collect volatile system state into a new evidence container.
    Collect(CollectArgs),
    /// Capture live network traffic to a PCAP file inside an evidence container.
    Capture(CaptureArgs),
    /// Parse an existing PCAP/PCAPNG: flows, TCP streams, indicators.
    ParsePcap(ParsePcapArgs),
    /// Re-hash a container's artifacts and check them against its signed log.
    Verify(VerifyArgs),
    /// Re-render the human-readable summary from a container's JSON report.
    Report(ReportArgs),
}
