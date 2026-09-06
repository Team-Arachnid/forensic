//! Arachnid Core — live triage and network forensics.
//!
//! Part of the Arachnid Forensic suite. For use by authorized analysts on
//! systems they have permission to examine.
//!
//! Every subcommand is read-only against the target system; the only writes go
//! to the evidence container the operator names. See `docs/SOC-ALLOWLISTING.md`
//! for the full list of paths and APIs this binary touches.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arachnid_collect as collect;
use arachnid_evidence::bsa63_certificate as bsa63;
use arachnid_evidence::{Container, VerifyReport};
use arachnid_netcap as netcap;
use arachnid_report::{seal_into, to_html, to_markdown, Report};
use clap::{Args, Parser, Subcommand, ValueEnum};

/// Exit codes, stable across releases so SOAR playbooks can branch on them.
mod exit {
    /// Everything requested completed.
    pub const OK: u8 = 0;
    /// Runtime failure: I/O, permission, missing device, unusable input.
    pub const ERROR: u8 = 1;
    /// Argument and usage errors. clap returns this itself; a command returns
    /// it when an affirmation the operator must make was not made.
    pub const USAGE: u8 = 2;
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
3  integrity failure: verify found a problem, or certify refused\n  \
4  completed, but one or more collectors were degraded (see report warnings)"
)]
struct Cli {
    /// Operational log destination. Distinct from the evidence log, which always
    /// lives in the container and is never written here.
    #[arg(long, global = true, value_name = "PATH")]
    log: Option<PathBuf>,

    /// Operational log verbosity. Overrides ARACHNID_LOG; defaults to "info".
    #[arg(long, global = true, value_name = "LEVEL")]
    log_level: Option<String>,

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
    /// Generate a Section 63 (BSA 2023) certificate over a verified container.
    Certify(Box<CertifyArgs>),
}

#[derive(Args)]
struct ContainerArgs {
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
    /// Directory to create for this run's evidence container.
    #[arg(short, long, value_name = "DIR")]
    output: PathBuf,

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

    /// Directory to create for this run's evidence container.
    #[arg(
        short,
        long,
        value_name = "DIR",
        required_unless_present = "list_devices"
    )]
    output: Option<PathBuf>,

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

    /// Directory to create for this run's evidence container.
    #[arg(short, long, value_name = "DIR")]
    output: PathBuf,

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

#[derive(Args)]
struct CertifyArgs {
    /// Evidence container to certify. Verified before anything is generated;
    /// a container that does not verify is refused.
    #[arg(short, long, value_name = "CONTAINER")]
    input: PathBuf,

    /// Where to write the certificate. The PDF goes here (`.pdf` is appended
    /// if absent) and the signed JSON alongside it with the same stem — one
    /// invocation, one certificate, two renderings of the same document.
    #[arg(short, long, value_name = "PATH")]
    output: PathBuf,

    /// Case or reference number this record belongs to.
    #[arg(long, value_name = "TEXT")]
    case_reference: String,

    /// What the electronic record is, in the words a court will read.
    #[arg(long, value_name = "TEXT")]
    record_description: String,

    /// Signer 1 (device custodian): full name, as it appears on the certificate.
    #[arg(
        long,
        value_name = "NAME",
        help_heading = "Signer 1 — device custodian"
    )]
    custodian_name: String,

    /// Signer 1: designation or role.
    #[arg(
        long,
        value_name = "TEXT",
        help_heading = "Signer 1 — device custodian"
    )]
    custodian_designation: String,

    /// Signer 1: organization.
    #[arg(
        long,
        value_name = "TEXT",
        help_heading = "Signer 1 — device custodian"
    )]
    custodian_organization: String,

    /// Signer 1: contact details — an email address, a phone number, or both.
    #[arg(
        long,
        value_name = "TEXT",
        help_heading = "Signer 1 — device custodian"
    )]
    custodian_contact: String,

    /// Signer 1: Ed25519 key file for the in-software attestation path.
    /// Requires the expert's key too; omit both for wet-ink signature.
    #[arg(
        long,
        value_name = "PATH",
        requires = "expert_key",
        help_heading = "Signer 1 — device custodian"
    )]
    custodian_key: Option<PathBuf>,

    /// Signer 2 (independent expert): full name.
    #[arg(
        long,
        value_name = "NAME",
        help_heading = "Signer 2 — independent expert"
    )]
    expert_name: String,

    /// Signer 2: designation or role.
    #[arg(
        long,
        value_name = "TEXT",
        help_heading = "Signer 2 — independent expert"
    )]
    expert_designation: String,

    /// Signer 2: organization.
    #[arg(
        long,
        value_name = "TEXT",
        help_heading = "Signer 2 — independent expert"
    )]
    expert_organization: String,

    /// Signer 2: contact details.
    #[arg(
        long,
        value_name = "TEXT",
        help_heading = "Signer 2 — independent expert"
    )]
    expert_contact: String,

    /// Signer 2: Ed25519 key file for the in-software attestation path.
    #[arg(
        long,
        value_name = "PATH",
        requires = "custodian_key",
        help_heading = "Signer 2 — independent expert"
    )]
    expert_key: Option<PathBuf>,

    /// The device did not operate properly: state the malfunction and why it
    /// did not affect the accuracy of the record. Section 63(2) permits a
    /// malfunction; it does not permit an unstated one.
    #[arg(long, value_name = "TEXT")]
    malfunction: Option<String>,

    /// Affirm the Section 63(2) conditions, which `--help` prints in full.
    /// Required: the tool cannot observe whether a computer was in regular
    /// use, so it will not assert it on anyone's behalf.
    #[arg(long)]
    affirm_conditions: bool,

    /// Acknowledge the disclaimer printed above. Required.
    #[arg(long)]
    acknowledge: bool,
}

/// Parse `args` and run, returning the process exit code.
///
/// Takes the argument list rather than reading it, so the unified
/// `arachnid-cli` front end can dispatch into this without re-exec.
pub fn run_from<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = Cli::parse_from(args);
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

    // An explicit flag beats the ambient environment: an operator who asks for a
    // level on the command line gets it regardless of what ARACHNID_LOG holds.
    let filter = match &cli.log_level {
        Some(level) => EnvFilter::try_new(level).context("invalid --log-level")?,
        None => EnvFilter::try_from_env("ARACHNID_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
    };

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
        Command::Certify(a) => cmd_certify(cli, a),
    }
}

/// Open a container and record the invocation, so the custody log states what
/// was asked for as well as what came back.
fn open_container(output: &Path, c: &ContainerArgs) -> Result<Container> {
    let operator = c.operator.clone().unwrap_or_else(default_operator);
    let key = c
        .signing_key
        .as_deref()
        .map(arachnid_evidence::load_signing_key)
        .transpose()?;

    let mut container = Container::create(output, &operator, key, c.dry_run)?;
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
    let mut container = open_container(&a.output, &a.container)?;
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

fn cmd_capture(cli: &Cli, a: &CaptureArgs) -> Result<u8> {
    if a.list_devices {
        let devices = netcap::list_devices()?;
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&devices)?);
        } else if devices.is_empty() {
            println!("No capture devices visible. Capture needs root/CAP_NET_RAW on Linux, Npcap on Windows.");
        } else {
            for d in &devices {
                println!(
                    "{:<20} {}{}",
                    d.name,
                    d.addresses.join(", "),
                    if d.loopback { "  [loopback]" } else { "" }
                );
                if let Some(desc) = &d.description {
                    println!("{:<20} {desc}", "");
                }
            }
        }
        return Ok(exit::OK);
    }

    let device = a
        .device
        .as_deref()
        .context("--device is required (see --list-devices)")?;
    if a.duration.is_none() && a.count.is_none() {
        tracing::warn!("no --duration or --count: capture runs until interrupted with Ctrl-C");
    }

    // clap guarantees this is present unless --list-devices was given, which
    // returned above.
    let output = a.output.as_deref().expect("clap enforces --output here");
    let mut container = open_container(output, &a.container)?;
    let mut report = Report::new(container.manifest().clone());

    let opts = netcap::LiveOptions {
        device: device.to_string(),
        filter: a.filter.clone(),
        snaplen: a.snaplen,
        promiscuous: a.promiscuous,
        max_packets: a.count,
        duration: a.duration.map(Duration::from_secs),
    };

    if a.container.dry_run {
        tracing::warn!("dry run: not opening a capture handle");
        container.note(format!("dry-run: would capture on {device}"))?;
        return finish(cli, container, report, false);
    }

    // Ctrl-C sets the flag rather than killing the process, so the savefile is
    // flushed and its digest reaches the custody log. Losing a capture to an
    // abrupt exit would be losing evidence.
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = stop.clone();
    ctrlc::set_handler(move || {
        handler_stop.store(true, Ordering::Relaxed);
    })
    .context("install interrupt handler")?;

    let out = container.artifact_path("capture.pcap");
    std::fs::create_dir_all(out.parent().unwrap())?;
    tracing::info!(device, filter = ?a.filter, "starting capture; Ctrl-C to stop");

    let stats = netcap::capture_live(&opts, &out, &stop)?;
    tracing::info!(
        packets = stats.packets_written,
        dropped = stats.packets_dropped_kernel,
        reason = stats.stop_reason,
        "capture finished"
    );

    report.artifact("capture.pcap", container.seal("capture.pcap")?);
    let degraded = stats.packets_dropped_kernel > 0 || stats.packets_dropped_interface > 0;
    if degraded {
        container.note(format!(
            "capture dropped {} kernel / {} interface packets; evidence has gaps",
            stats.packets_dropped_kernel, stats.packets_dropped_interface
        ))?;
    }
    report.capture = Some(stats);
    finish(cli, container, report, degraded)
}

fn cmd_parse_pcap(cli: &Cli, a: &ParsePcapArgs) -> Result<u8> {
    if !a.input.is_file() {
        bail!("{} is not a readable file", a.input.display());
    }
    let mut container = open_container(&a.output, &a.container)?;
    let mut report = Report::new(container.manifest().clone());

    // The source file is evidence in its own right; bind its digest to this
    // analysis even though the file stays where it is.
    let (source_hash, size) = arachnid_evidence::sha256_file(&a.input)?;
    container.note(format!(
        "source pcap {} sha256={source_hash} size={size}",
        a.input.display()
    ))?;

    tracing::info!(input = %a.input.display(), "parsing savefile");
    let mut analysis = netcap::parse_pcap(
        &a.input,
        &netcap::ParseOptions {
            max_stream_bytes: a.max_stream_bytes,
            filter: a.filter.clone(),
        },
    )?;
    analysis.source_sha256 = Some(source_hash);
    tracing::info!(
        packets = analysis.packets,
        flows = analysis.flows.len(),
        indicators = analysis.indicators.len(),
        "parse finished"
    );

    report.artifact(
        "pcap_analysis.json",
        container.add_json("pcap_analysis.json", &analysis)?,
    );
    let degraded = analysis.decode_errors > 0;
    report.pcap = Some(analysis);
    finish(cli, container, report, degraded)
}

fn cmd_verify(cli: &Cli, a: &VerifyArgs) -> Result<u8> {
    let r = arachnid_evidence::verify(&a.container)
        .with_context(|| format!("verify {}", a.container.display()))?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&r)?);
    } else {
        print_verify(&r);
    }
    Ok(if r.ok() { exit::OK } else { exit::INTEGRITY })
}

fn print_verify(r: &VerifyReport) {
    println!("container:        {}", r.container);
    println!("schema:           {}", r.schema_version);
    println!("signing key:      {}", r.public_key);
    println!("key fingerprint:  {}", r.key_fingerprint);
    println!("custody records:  {}", r.records);
    println!("artifacts hashed: {}", r.artifacts_checked);
    if r.ok() {
        println!("\nVERIFIED: every artifact matches the signed custody log.");
        println!("This confirms the container is internally consistent. It is only proof of");
        println!("origin if the key fingerprint above matches the one recorded at collection.");
    } else {
        println!("\nFAILED: {} problem(s).", r.problems.len());
        for p in &r.problems {
            println!("  - {p}");
        }
    }
}

fn cmd_report(_cli: &Cli, a: &ReportArgs) -> Result<u8> {
    let path = a.container.join("artifacts/report.json");
    let raw = std::fs::read(&path)
        .with_context(|| format!("read {} (is this an Arachnid container?)", path.display()))?;
    let report: Report = serde_json::from_slice(&raw).context("parse report.json")?;

    if report.schema_version.split('.').next() != Some("1") {
        bail!(
            "report schema {} is not supported by this build (expected 1.x)",
            report.schema_version
        );
    }

    let rendered = match a.format {
        ReportFormat::Markdown => to_markdown(&report),
        ReportFormat::Html => to_html(&report),
        ReportFormat::Json => String::from_utf8(report.to_json()?)?,
    };
    match &a.output {
        Some(p) => {
            std::fs::write(p, &rendered).with_context(|| format!("write {}", p.display()))?;
            tracing::info!(path = %p.display(), "report written");
        }
        None => print!("{rendered}"),
    }
    Ok(exit::OK)
}

// ---------------------------------------------------------------------------
// certify
// ---------------------------------------------------------------------------

/// The notice printed before a certificate run does anything at all.
///
/// Deliberately first: an operator has to see what this document is and is not
/// *before* supplying signer details, not after holding a finished PDF. The
/// text comes from the certificate module, so the notice and the document
/// cannot drift apart.
fn certificate_notice() -> String {
    let mut s = String::from(
        "\nCERTIFICATE UNDER SECTION 63, BHARATIYA SAKSHYA ADHINIYAM, 2023\n\
         ---------------------------------------------------------------\n\n",
    );
    s.push_str(bsa63::DISCLAIMER);
    s.push_str(
        "\n\nThe certificate states the conditions below, under Section 63(2). \
         --affirm-conditions affirms them on behalf of the signers; this tool cannot observe \
         them and will not assert them on anyone's behalf.\n\n",
    );
    for (i, c) in bsa63::CONDITIONS.iter().enumerate() {
        s.push_str(&format!("  ({})  {c}\n\n", (b'a' + i as u8) as char));
    }
    s.push_str(
        "Section 63(4) requires two different people to sign: the person in charge of the \
         computer or communication device, and an independent expert. Whether the second signer \
         is genuinely independent is a human judgement this tool cannot make; it only refuses a \
         certificate where both signers give the same name, organization and contact.\n\n",
    );
    s
}

fn cmd_certify(cli: &Cli, a: &CertifyArgs) -> Result<u8> {
    // On stderr, so the notice still reaches an operator who redirected stdout
    // to a file and would otherwise never see it.
    eprint!("{}", certificate_notice());
    if !a.acknowledge || !a.affirm_conditions {
        eprintln!(
            "error: --acknowledge and --affirm-conditions are both required. Read the notice \
             above; nothing is generated until they are given."
        );
        return Ok(exit::USAGE);
    }

    let conditions = match a.malfunction.as_deref() {
        Some(note) => bsa63::Conditions::with_malfunction(note),
        None => bsa63::Conditions::operating_properly(),
    };
    let request = bsa63::Request {
        case_reference: a.case_reference.clone(),
        record_description: a.record_description.clone(),
        conditions,
        custodian: bsa63::Signer::new(
            bsa63::Capacity::DeviceCustodian,
            &a.custodian_name,
            &a.custodian_designation,
            &a.custodian_organization,
            &a.custodian_contact,
        ),
        expert: bsa63::Signer::new(
            bsa63::Capacity::IndependentExpert,
            &a.expert_name,
            &a.expert_designation,
            &a.expert_organization,
            &a.expert_contact,
        ),
    };

    tracing::info!(container = %a.input.display(), "verifying evidence before certifying it");
    let mut signed = match bsa63::issue(&a.input, &request) {
        Ok(c) => c,
        Err(refused) => {
            // A refusal is the feature working, not failing: say why in the
            // refusal's own words and exit on the refused-job code.
            eprintln!("{refused}");
            return Ok(exit::INTEGRITY);
        }
    };

    // Both keys or neither: clap's `requires` enforces the pairing, so seeing
    // one here means seeing both.
    if let (Some(ck), Some(ek)) = (&a.custodian_key, &a.expert_key) {
        let custodian = arachnid_evidence::load_signing_key(ck)?;
        let expert = arachnid_evidence::load_signing_key(ek)?;
        if custodian.verifying_key() == expert.verifying_key() {
            bail!(
                "both signers presented the same key; an attestation made twice with one key is \
                 one person's attestation, not two"
            );
        }
        signed.attest(bsa63::Capacity::DeviceCustodian, &custodian);
        signed.attest(bsa63::Capacity::IndependentExpert, &expert);
    }

    // Both paths are derived from one base, so the two files are always
    // renderings of the same certificate rather than two certificates
    // generated a second apart.
    let pdf_path = a.output.with_extension("pdf");
    let json_path = a.output.with_extension("json");
    if let Some(parent) = pdf_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&pdf_path, signed.to_pdf())
        .with_context(|| format!("write {}", pdf_path.display()))?;
    std::fs::write(&json_path, signed.to_json())
        .with_context(|| format!("write {}", json_path.display()))?;
    tracing::info!(pdf = %pdf_path.display(), json = %json_path.display(), "certificate written");

    // Loud, and on stderr in both output modes: a signer's name reaching the
    // page as question marks is not something to find out in court.
    for limitation in signed.pdf_limitations() {
        eprintln!("warning: {limitation}");
    }

    let c = &signed.certificate;
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "certificate_id": c.certificate_id,
                "case_reference": c.case_reference,
                "container": c.source.container_path,
                "custody_key_fingerprint": c.source.custody_key_fingerprint,
                "artifacts_verified": c.source.artifacts_verified,
                "attestations": signed.attestations.len(),
                "pdf": pdf_path.display().to_string(),
                "json": json_path.display().to_string(),
            }))?
        );
        return Ok(exit::OK);
    }

    println!("Certificate {} generated.", c.certificate_id);
    println!("  case            {}", c.case_reference);
    println!("  container       {}", c.source.container_path);
    println!(
        "  artifacts       {} re-verified",
        c.source.artifacts_verified
    );
    println!("  custody key     {}", c.source.custody_key_fingerprint);
    println!("  pdf             {}", pdf_path.display());
    println!("  json            {}", json_path.display());
    match signed.attestations.len() {
        0 => println!(
            "\nNo in-software attestation was recorded. Print the PDF and have both signers sign \
             the certificate."
        ),
        n => println!(
            "\n{n} in-software attestation(s) recorded. These are not represented as equivalent \
             to wet-ink signatures."
        ),
    }
    println!(
        "\nHave the certificate template reviewed by qualified legal counsel before relying on \
         it in any proceeding."
    );
    Ok(exit::OK)
}

/// Seal the report into the container and close it.
///
/// `report.json` is written last and hashed like any other artifact, so the
/// summary is covered by the same custody chain as the evidence it describes.
fn finish(cli: &Cli, mut container: Container, report: Report, partial: bool) -> Result<u8> {
    let md = to_markdown(&report);
    let json = seal_into(&mut container, &report)?;

    let fingerprint = container.key_fingerprint();
    let root = container.root().to_path_buf();
    container.finish()?;

    if cli.json {
        println!("{}", String::from_utf8(json)?);
    } else {
        print!("{md}");
        println!("\n---\n");
        println!("Evidence container: {}", root.display());
        println!("Signing key fingerprint: {fingerprint}");
        println!("Record this fingerprint out-of-band; `verify` can only prove origin against it.");
        println!("Verify with: arachnid-core verify {}", root.display());
    }

    Ok(if partial { exit::PARTIAL } else { exit::OK })
}
