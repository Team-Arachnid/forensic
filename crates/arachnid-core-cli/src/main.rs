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

#[derive(Args)]
struct ContainerArgs {
    /// Directory to create for this run's evidence container.
    #[arg(short, long, value_name = "DIR")]
    output: PathBuf,

    /// Operator identity recorded in every custody entry.
    /// Defaults to the invoking user.
    #[arg(long, value_name = "NAME")]
    operator: Option<String>,

    /// Ed25519 signing key: a file holding a 32-byte seed, raw or hex.
    /// Without it a key is generated for this run alone; record the fingerprint
    /// printed at the end, or the container cannot be trusted later.
    #[arg(long, value_name = "PATH")]
    signing_key: Option<PathBuf>,

    /// Run every collector and compute every hash, but write nothing to disk.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Args)]
struct CollectArgs {
    #[command(flatten)]
    container: ContainerArgs,

    /// Skip hashing on-disk process binaries. Faster; loses image integrity data.
    #[arg(long)]
    no_hash_binaries: bool,

    /// External memory acquisition tool (AVML on Linux, WinPmem on Windows).
    #[arg(long, value_name = "PATH", requires = "memory_tool_sha256")]
    memory_tool: Option<PathBuf>,

    /// Expected SHA-256 of the acquisition tool. Required with --memory-tool:
    /// an unverified acquisition binary is never executed.
    #[arg(long, value_name = "HEX")]
    memory_tool_sha256: Option<String>,

    /// Extra arguments for the acquisition tool, before the output path.
    #[arg(long, value_name = "ARG", num_args = 1..)]
    memory_arg: Vec<String>,
}

#[derive(Args)]
struct CaptureArgs {
    /// List capture devices and exit.
    #[arg(long, conflicts_with_all = ["device", "output"])]
    list_devices: bool,

    #[command(flatten)]
    container: ContainerArgs,

    /// Interface to capture on. See --list-devices.
    #[arg(short, long, value_name = "NAME")]
    device: Option<String>,

    /// BPF filter, applied in the kernel (e.g. "tcp port 443 and not host 10.0.0.1").
    #[arg(short, long, value_name = "BPF")]
    filter: Option<String>,

    /// Stop after this many seconds.
    #[arg(long, value_name = "SECS")]
    duration: Option<u64>,

    /// Stop after this many packets.
    #[arg(long, value_name = "N")]
    count: Option<u64>,

    /// Capture frames not addressed to this host. Changes the interface's
    /// receive mode; it is off by default because that is an observable change.
    #[arg(long)]
    promiscuous: bool,

    /// Bytes captured per frame.
    #[arg(long, default_value_t = 65535, value_name = "BYTES")]
    snaplen: i32,
}

#[derive(Args)]
struct ParsePcapArgs {
    /// PCAP or PCAPNG file to analyse. Opened read-only.
    #[arg(value_name = "PCAP")]
    input: PathBuf,

    #[command(flatten)]
    container: ContainerArgs,

    /// BPF filter applied while reading the savefile.
    #[arg(short, long, value_name = "BPF")]
    filter: Option<String>,

    /// Per-flow reassembly ceiling in bytes.
    #[arg(long, default_value_t = netcap::DEFAULT_MAX_STREAM_BYTES, value_name = "BYTES")]
    max_stream_bytes: usize,
}

#[derive(Args)]
struct VerifyArgs {
    /// Evidence container directory to verify.
    #[arg(value_name = "CONTAINER")]
    container: PathBuf,
}

#[derive(Args)]
struct ReportArgs {
    /// Evidence container directory holding `artifacts/report.json`.
    #[arg(value_name = "CONTAINER")]
    container: PathBuf,

    #[arg(long, default_value = "markdown")]
    format: ReportFormat,

    /// Write to this path instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum ReportFormat {
    Markdown,
    Html,
    Json,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    if let Err(e) = init_logging(&cli) {
        eprintln!("error: {e:#}");
        return ExitCode::from(exit::ERROR);
    }

    match run(&cli) {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            tracing::error!(error = %format!("{e:#}"), "command failed");
            eprintln!("error: {e:#}");
            ExitCode::from(exit::ERROR)
        }
    }
}

/// Operational log: stderr by default, or appended to `--log`. Never the same
/// stream as the evidence log, which lives inside the container.
fn init_logging(cli: &Cli) -> Result<()> {
    use tracing_subscriber::{fmt, EnvFilter};

    let filter = EnvFilter::try_from_env("ARACHNID_LOG")
        .or_else(|_| EnvFilter::try_new(&cli.log_level))
        .context("invalid --log-level")?;

    match &cli.log {
        Some(path) => {
            if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .with_context(|| format!("open operational log {}", path.display()))?;
            fmt()
                .with_env_filter(filter)
                .with_ansi(false)
                .with_writer(file)
                .init();
        }
        None => {
            fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .init();
        }
    }
    Ok(())
}

fn run(cli: &Cli) -> Result<u8> {
    match &cli.command {
        Command::Collect(a) => cmd_collect(cli, a),
        Command::Capture(a) => cmd_capture(cli, a),
        Command::ParsePcap(a) => cmd_parse_pcap(cli, a),
        Command::Verify(a) => cmd_verify(cli, a),
        Command::Report(a) => cmd_report(cli, a),
    }
}

/// Open a container and record the invocation, so the custody log states what
/// was asked for as well as what came back.
fn open_container(c: &ContainerArgs) -> Result<Container> {
    let operator = c.operator.clone().unwrap_or_else(default_operator);
    let key = c
        .signing_key
        .as_deref()
        .map(arachnid_evidence::load_signing_key)
        .transpose()?;

    let mut container = Container::create(&c.output, &operator, key, c.dry_run)?;
    container.note(format!(
        "invocation: {}",
        std::env::args().collect::<Vec<_>>().join(" ")
    ))?;
    if c.dry_run {
        tracing::warn!("dry run: nothing will be written to disk");
        container.note("dry-run: no artifacts were written")?;
    }
    Ok(container)
}

fn default_operator() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());
    format!("{user}@{}", std::env::consts::OS)
}

fn cmd_collect(cli: &Cli, a: &CollectArgs) -> Result<u8> {
    let mut container = open_container(&a.container)?;
    let mut report = Report::new(container.manifest().clone());

    tracing::info!("collecting volatile system state");
    let c = collect::collect_all(collect::Options {
        hash_binaries: !a.no_hash_binaries,
    });

    // One artifact per collector: an analyst can hash-verify and cite each
    // independently, and a downstream tool can consume just the one it needs.
    report.artifact(
        "processes.json",
        container.add_json("processes.json", &c.processes)?,
    );
    report.artifact(
        "connections.json",
        container.add_json("connections.json", &c.connections)?,
    );
    report.artifact(
        "sessions.json",
        container.add_json("sessions.json", &c.sessions)?,
    );
    report.artifact(
        "kernel_modules.json",
        container.add_json("kernel_modules.json", &c.kernel_modules)?,
    );
    report.artifact(
        "persistence.json",
        container.add_json("persistence.json", &c.persistence)?,
    );
    for w in &c.warnings {
        container.note(format!("collector degraded: {w}"))?;
    }

    if let Some(tool) = &a.memory_tool {
        let expected = a
            .memory_tool_sha256
            .as_deref()
            .context("--memory-tool requires --memory-tool-sha256")?;
        let out = container.artifact_path("memory.raw");
        if a.container.dry_run {
            tracing::warn!("dry run: skipping memory acquisition");
            container.note("dry-run: memory acquisition skipped")?;
        } else {
            tracing::info!(tool = %tool.display(), "acquiring physical memory");
            let acq = collect::acquire_memory(tool, expected, &out, &a.memory_arg)?;
            report.artifact("memory.raw", container.seal("memory.raw")?);
            container.note(format!(
                "memory acquired with {} ({})",
                acq.tool, acq.tool_sha256
            ))?;
            report.memory = Some(acq);
        }
    }

    report.collection = Some(c);
    let partial = report
        .collection
        .as_ref()
        .is_some_and(|c| !c.warnings.is_empty());
    finish(cli, container, report, partial)
}
