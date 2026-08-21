//! Arachnid Sanitize — standards-compliant secure erasure.
//!
//! Part of the Arachnid Forensic suite. **This binary destroys data.** Every
//! other tool in the suite is read-only against the target; this one is not, and
//! the interface is shaped accordingly:
//!
//! - `wipe` will not start without `--confirm-serial <SERIAL>` matching the
//!   device exactly.
//! - A device hosting the running OS is refused unless `--force-system-volume`
//!   is also passed.
//! - `--dry-run` walks the whole flow and writes nothing.
//! - There is no "wipe all devices" verb. One invocation, one device.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arachnid_sanitize_core::{
    cert, device, engine,
    pattern::WipeMethod,
    safety::{self, WipeRequest},
    target::{RawDeviceTarget, WipeTarget},
    verify, Device, REGISTER_FILE,
};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ed25519_dalek::SigningKey;

/// Exit codes, stable across releases so asset-disposal scripts can branch on
/// them. Deliberately parallel to `arachnid-core`'s, with erasure-specific
/// meanings for 3 and 5.
mod exit {
    pub const OK: u8 = 0;
    pub const ERROR: u8 = 1;
    pub const _USAGE: u8 = 2;
    /// A safety rail refused the job. Nothing was written.
    pub const REFUSED: u8 = 3;
    /// The wipe ran but verification failed: the device may still hold data.
    pub const VERIFY_FAILED: u8 = 4;
    /// The wipe completed with unwritable regions.
    pub const PARTIAL: u8 = 5;
}

#[derive(Parser)]
#[command(
    name = "arachnid-sanitize",
    version,
    about = "Arachnid Sanitize — NIST/DoD-compliant secure erasure (Arachnid Forensic suite)",
    long_about = "Irreversibly destroys data on storage media to NIST SP 800-88 and DoD \
5220.22-M patterns, verifies the result by read-back sampling, and issues a signed \
certificate.\n\n\
THIS TOOL DESTROYS DATA. A wipe cannot be undone. Use --dry-run first.\n\n\
EXIT CODES\n  \
0  success\n  \
1  runtime error\n  \
2  usage error\n  \
3  refused by a safety rail (nothing was written)\n  \
4  wipe ran but verification failed\n  \
5  wipe completed with unwritable regions"
)]
struct Cli {
    /// Operational log destination.
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
    /// List attached storage devices, flagging any that host the running OS.
    ListDevices,
    /// Irreversibly erase one device.
    Wipe(WipeArgs),
    /// Re-read a device and check it against an expected wipe pattern.
    VerifyWipe(VerifyWipeArgs),
    /// Print or verify erasure certificates.
    Cert(CertArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum MethodArg {
    /// Single-pass zero overwrite. NIST 800-88 Clear.
    NistClear,
    /// Hardware purge where available, 3-pass software overwrite otherwise.
    NistPurge,
    /// DoD 5220.22-M, 3 passes.
    Dod3,
    /// DoD 5220.22-M, 7 passes.
    Dod7,
    /// Destroy the encryption key on a self-encrypting drive.
    CryptoErase,
}

impl From<MethodArg> for WipeMethod {
    fn from(m: MethodArg) -> Self {
        match m {
            MethodArg::NistClear => WipeMethod::NistClear,
            MethodArg::NistPurge => WipeMethod::NistPurge,
            MethodArg::Dod3 => WipeMethod::Dod3Pass,
            MethodArg::Dod7 => WipeMethod::Dod7Pass,
            MethodArg::CryptoErase => WipeMethod::CryptoErase,
        }
    }
}

#[derive(Args)]
struct WipeArgs {
    /// Device to erase, by OS path (\\.\PhysicalDrive2, /dev/sdb).
    /// See `list-devices`.
    #[arg(value_name = "DEVICE")]
    device: String,

    /// Erasure method. No default: the choice changes what standard the
    /// resulting certificate can claim, so it must be made explicitly.
    #[arg(long, value_enum)]
    method: MethodArg,

    /// The device's serial number, exactly as `list-devices` reports it.
    /// Required for every real wipe; this is the rail that stops the wrong
    /// drive being erased off a mis-selected list row.
    #[arg(long, value_name = "SERIAL", required_unless_present = "dry_run")]
    confirm_serial: Option<String>,

    /// Walk the entire flow and report what would happen. Writes nothing.
    #[arg(long)]
    dry_run: bool,

    /// Permit erasing a device that hosts the running operating system.
    /// This will destroy the system you are running from.
    #[arg(long)]
    force_system_volume: bool,

    /// Skip the countdown before writing starts. For unattended asset-disposal
    /// runs where a human has already confirmed the device out of band.
    #[arg(long)]
    no_countdown: bool,

    /// Operator identity recorded on the certificate.
    #[arg(long, value_name = "NAME")]
    operator: Option<String>,

    /// Ed25519 signing key: a file holding a 32-byte seed, raw or hex.
    /// Without it a key is generated for this run alone; record the fingerprint
    /// printed at the end or the certificate cannot be trusted later.
    #[arg(long, value_name = "PATH")]
    signing_key: Option<PathBuf>,

    /// Directory holding the append-only certificate register.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cert_dir: PathBuf,

    /// Verify a smaller sample. Faster on very large drives; still covers the
    /// head and tail, where a failed wipe shows first.
    #[arg(long)]
    quick_verify: bool,
}

#[derive(Args)]
struct VerifyWipeArgs {
    /// Device to read back.
    #[arg(value_name = "DEVICE")]
    device: String,

    /// Expect this fixed byte across the device, as hex (e.g. 00, ff).
    /// Use this to check a drive wiped by another tool or an earlier run.
    #[arg(long, value_name = "HEX", default_value = "00")]
    expect_byte: String,

    #[arg(long)]
    quick: bool,
}

#[derive(Args)]
struct CertArgs {
    /// Directory holding the certificate register.
    #[arg(long, default_value = ".", value_name = "DIR")]
    cert_dir: PathBuf,

    /// Check every signature and the hash chain instead of listing.
    #[arg(long)]
    verify: bool,

    /// Render one certificate by ID.
    #[arg(long, value_name = "ID")]
    id: Option<String>,

    #[arg(long, default_value = "markdown")]
    format: CertFormat,

    /// Write to this path instead of stdout.
    #[arg(short, long, value_name = "PATH")]
    output: Option<PathBuf>,
}

#[derive(Clone, Copy, ValueEnum)]
enum CertFormat {
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

fn init_logging(cli: &Cli) -> Result<()> {
    use tracing_subscriber::{fmt, EnvFilter};

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
        Command::ListDevices => cmd_list(cli),
        Command::Wipe(a) => cmd_wipe(cli, a),
        Command::VerifyWipe(a) => cmd_verify_wipe(cli, a),
        Command::Cert(a) => cmd_cert(cli, a),
    }
}

fn cmd_list(cli: &Cli) -> Result<u8> {
    let devices = device::enumerate()?;
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&devices)?);
        return Ok(exit::OK);
    }
    if devices.is_empty() {
        println!("No storage devices visible. Device enumeration needs Administrator on Windows, root on Linux.");
        return Ok(exit::OK);
    }
    println!(
        "{:<22} {:<26} {:<20} {:>10}  {:<8} FLAGS",
        "PATH", "MODEL", "SERIAL", "SIZE", "BUS"
    );
    for d in &devices {
        let mut flags = Vec::new();
        if d.is_system {
            flags.push("SYSTEM".to_string());
        }
        if d.removable {
            flags.push("removable".to_string());
        }
        println!(
            "{:<22} {:<26} {:<20} {:>10}  {:<8} {}",
            d.path,
            truncate(&d.model, 26),
            truncate(
                if d.serial.is_empty() {
                    "(none)"
                } else {
                    &d.serial
                },
                20
            ),
            d.size_human(),
            d.bus.label(),
            flags.join(", ")
        );
        if let Some(r) = &d.system_reason {
            println!("{:<22} └─ {r}", "");
        }
    }
    println!(
        "\nDevices flagged SYSTEM host the running operating system and are refused by `wipe` \
         unless --force-system-volume is passed."
    );
    Ok(exit::OK)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    }
}

fn cmd_wipe(cli: &Cli, a: &WipeArgs) -> Result<u8> {
    // Enumerate fresh. The device the operator names is matched against what is
    // actually attached right now, not against anything cached.
    let devices = device::enumerate()?;
    let Some(selected) = devices.iter().find(|d| d.path == a.device).cloned() else {
        bail!(
            "no device at {}. Run `arachnid-sanitize list-devices` to see what is attached.",
            a.device
        );
    };

    let request = WipeRequest {
        device: selected.clone(),
        method: a.method.into(),
        typed_serial: a
            .confirm_serial
            .clone()
            // clap requires --confirm-serial unless --dry-run. A dry run never
            // writes, so it is allowed to stand in the device's own serial and
            // still exercise the rest of the flow.
            .unwrap_or_else(|| selected.serial.clone()),
        force_system_volume: a.force_system_volume,
        dry_run: a.dry_run,
        operator: a.operator.clone().unwrap_or_else(default_operator),
    };

    let clearance = match safety::authorize(request, Some(&selected)) {
        Ok(c) => c,
        Err(refusal) => {
            tracing::error!("{refusal}");
            eprintln!("REFUSED: {refusal}");
            return Ok(exit::REFUSED);
        }
    };

    let estimate = engine::estimate(&clearance);
    print_plan(&selected, &clearance, estimate);

    if a.dry_run {
        println!("\nDRY RUN — nothing was written. Re-run without --dry-run to erase.");
        if a.confirm_serial.is_none() {
            // A dry run without a typed serial stands the device's own in, so
            // the serial rail was not actually exercised. Saying so matters:
            // otherwise a clean dry run reads as proof the real invocation will
            // be accepted, and it is not.
            println!(
                "Note: --confirm-serial was not supplied, so the serial check did not run.\n\
                 The real wipe will require --confirm-serial {}",
                selected.serial
            );
        }
        return Ok(exit::OK);
    }

    if !a.no_countdown {
        countdown(safety::CONFIRM_COOLDOWN);
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let handler = cancel.clone();
    // Ctrl-C stops at the next chunk rather than killing the process, so the
    // outcome records how far the wipe actually got. A drive left in an unknown
    // state is worse than one left in a recorded partial state.
    ctrlc::set_handler(move || handler.store(true, Ordering::Relaxed))
        .context("install interrupt handler")?;

    let mut target = RawDeviceTarget::open(&selected.path).with_context(|| {
        format!(
            "open {} for writing (needs Administrator on Windows, root on Linux)",
            selected.path
        )
    })?;

    let progress = engine::Progress::default();
    let outcome = engine::wipe(&mut target, &clearance, &progress, &cancel)?;

    if outcome.cancelled {
        eprintln!(
            "\nCANCELLED after {} of {}. The device is partially overwritten and holds no usable \
             filesystem, but it is NOT certified erased.",
            device::human_bytes(outcome.bytes_written),
            device::human_bytes(outcome.bytes_total)
        );
        return Ok(exit::PARTIAL);
    }

    let options = if a.quick_verify {
        verify::VerifyOptions::quick()
    } else {
        verify::VerifyOptions::default()
    };
    println!("\nVerifying by read-back sampling…");
    let report = verify::verify(&mut target, &outcome, &options)?;

    let key = load_or_generate_key(a.signing_key.as_deref())?;
    let register = a.cert_dir.join(REGISTER_FILE);
    let prev = cert::head(&register)?;

    match cert::issue(&clearance, &outcome, &report, &key, &prev) {
        Ok(certificate) => {
            cert::append(&register, &certificate, &key)?;
            if cli.json {
                println!("{}", serde_json::to_string_pretty(&certificate)?);
            } else {
                println!("\n{}", cert::to_markdown(&certificate));
                println!(
                    "Certificate appended to {}\nSigning key fingerprint: {}\nRecord this \
                     fingerprint out-of-band; verification proves origin only against it.",
                    register.display(),
                    cert::key_fingerprint(&key)
                );
            }
            Ok(exit::OK)
        }
        Err(refused) => {
            eprintln!("\n{refused}");
            for f in report.failures() {
                eprintln!(
                    "  mismatch at offset {}: expected {}, found {}",
                    f.first_mismatch_at.unwrap_or(f.offset),
                    f.expected_hex.as_deref().unwrap_or("?"),
                    f.observed_hex.as_deref().unwrap_or("?")
                );
            }
            for b in outcome.bad_regions.iter().take(20) {
                eprintln!(
                    "  unwritable region at offset {} ({} bytes, pass {}): {}",
                    b.offset, b.length, b.pass, b.error
                );
            }
            Ok(if outcome.bad_region_count > 0 {
                exit::PARTIAL
            } else {
                exit::VERIFY_FAILED
            })
        }
    }
}

fn print_plan(d: &Device, c: &safety::Clearance, estimate: Duration) {
    let method = c.method();
    println!("Device:   {} — {} ({})", d.path, d.model, d.size_human());
    println!("Serial:   {}", d.serial);
    println!(
        "Bus:      {}{}",
        d.bus.label(),
        if d.removable { ", removable" } else { "" }
    );
    println!("Method:   {}", method.label());
    println!("          {}", method.explanation());
    println!("Passes:   {}", method.passes().len());
    println!(
        "Estimate: {} (pessimistic; real throughput is usually better)",
        hms(estimate)
    );
    if c.overrode_system_volume {
        println!(
            "\n*** THIS DEVICE HOSTS THE RUNNING OPERATING SYSTEM. ***\n\
             *** Erasing it will destroy the system you are working from. ***"
        );
    }
    if method.tries_hardware_first() {
        println!(
            "\nNote: this build issues no hardware sanitize command. A software overwrite will \
             run and the certificate will say so."
        );
    }
}

fn hms(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60)
}

/// A deliberate pause before the first byte is written, so an operator who
/// started the wrong command has a moment to notice and interrupt it.
fn countdown(d: Duration) {
    let secs = d.as_secs().max(1);
    println!("\nIRREVERSIBLE DATA DESTRUCTION begins in:");
    for i in (1..=secs).rev() {
        print!("  {i}… ");
        use std::io::Write;
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_secs(1));
    }
    println!("\nWriting.");
}

fn cmd_verify_wipe(cli: &Cli, a: &VerifyWipeArgs) -> Result<u8> {
    let byte = u8::from_str_radix(a.expect_byte.trim_start_matches("0x"), 16)
        .context("--expect-byte must be two hex digits, e.g. 00 or ff")?;

    let mut target = RawDeviceTarget::open(&a.device)
        .with_context(|| format!("open {} for reading", a.device))?;
    let size = target.size()?;

    // A synthetic outcome describing "one fixed-byte pass covering the whole
    // device", which is exactly what the read-back comparison needs. Built here
    // rather than in the library because only this subcommand — checking a drive
    // some other tool wiped — has any reason to assert a wipe it did not run.
    let outcome = engine::WipeOutcome {
        method: WipeMethod::NistClear,
        purge_path: arachnid_sanitize_core::purge::PurgeOutcome::NotAttempted {
            capability: arachnid_sanitize_core::purge::PurgeCapability::UnsupportedTransport {
                reason: "read-back check of a previously wiped device".into(),
            },
        },
        passes: vec![arachnid_sanitize_core::pattern::PassPlan {
            pass: arachnid_sanitize_core::pattern::Pass::Fixed(byte),
            seed_hex: None,
        }],
        bytes_written: size,
        bytes_total: size,
        started_utc: arachnid_evidence::now_utc(),
        finished_utc: arachnid_evidence::now_utc(),
        duration_secs: 0.0,
        bad_region_count: 0,
        bad_regions: Vec::new(),
        cancelled: false,
        dry_run: false,
    };

    let options = if a.quick {
        verify::VerifyOptions::quick()
    } else {
        verify::VerifyOptions::default()
    };
    let report = verify::verify(&mut target, &outcome, &options)?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "{}: {} of {} sampled region(s) match 0x{byte:02x} ({} read, {:.4}% of the device)",
            if report.passed { "PASSED" } else { "FAILED" },
            report.samples.iter().filter(|s| s.ok).count(),
            report.samples.len(),
            device::human_bytes(report.bytes_sampled),
            report.coverage() * 100.0
        );
        for f in report.failures().take(20) {
            println!(
                "  offset {}: expected {}, found {}",
                f.first_mismatch_at.unwrap_or(f.offset),
                f.expected_hex.as_deref().unwrap_or("?"),
                f.observed_hex.as_deref().unwrap_or("?")
            );
        }
    }
    Ok(if report.passed {
        exit::OK
    } else {
        exit::VERIFY_FAILED
    })
}

fn cmd_cert(cli: &Cli, a: &CertArgs) -> Result<u8> {
    let register = a.cert_dir.join(REGISTER_FILE);

    if a.verify {
        let (checks, problems) = cert::verify_register(&register)?;
        if cli.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "certificates": checks,
                    "problems": problems,
                }))?
            );
        } else {
            println!("{} certificate(s) in {}", checks.len(), register.display());
            for c in &checks {
                println!(
                    "  {}  {}  signature {}  chain {}",
                    c.certificate_id,
                    c.device_serial,
                    if c.signature_ok { "ok" } else { "BAD" },
                    if c.chain_ok { "ok" } else { "BROKEN" }
                );
            }
            if problems.is_empty() {
                println!("\nVERIFIED: every certificate is intact and correctly chained.");
            } else {
                println!("\nFAILED: {} problem(s).", problems.len());
                for p in &problems {
                    println!("  - {p}");
                }
            }
        }
        return Ok(if problems.is_empty() {
            exit::OK
        } else {
            exit::VERIFY_FAILED
        });
    }

    let certificates = read_certificates(&register)?;
    let chosen = match &a.id {
        Some(id) => certificates
            .iter()
            .find(|c| &c.certificate_id == id)
            .with_context(|| format!("no certificate with id {id} in {}", register.display()))?,
        None => certificates
            .last()
            .context("the certificate register is empty")?,
    };

    let rendered = match a.format {
        CertFormat::Markdown => cert::to_markdown(chosen),
        CertFormat::Html => cert::to_html(chosen),
        CertFormat::Json => serde_json::to_string_pretty(chosen)?,
    };
    match &a.output {
        Some(p) => {
            std::fs::write(p, &rendered).with_context(|| format!("write {}", p.display()))?;
            println!("certificate written to {}", p.display());
        }
        None => print!("{rendered}"),
    }
    Ok(exit::OK)
}

fn read_certificates(register: &Path) -> Result<Vec<cert::Certificate>> {
    use std::io::BufRead;
    let file = std::fs::File::open(register)
        .with_context(|| format!("read certificate register {}", register.display()))?;
    let mut out = Vec::new();
    for (i, line) in std::io::BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        // Signatures are `cert --verify`'s business; skip past the separator.
        let body = line
            .split_once(' ')
            .map(|(_, b)| b.to_string())
            .with_context(|| {
                format!(
                    "{}: line {} has no signature separator",
                    register.display(),
                    i + 1
                )
            })?;
        out.push(
            serde_json::from_str(&body).with_context(|| {
                format!("{}: line {} is unparseable", register.display(), i + 1)
            })?,
        );
    }
    Ok(out)
}

/// An explicit key file, or an ephemeral key for this run alone.
///
/// The ephemeral path is a convenience for one-off wipes; a certificate signed
/// with it can only ever be checked against the fingerprint printed at the end,
/// which is why that fingerprint is printed prominently rather than logged.
fn load_or_generate_key(path: Option<&Path>) -> Result<SigningKey> {
    match path {
        Some(p) => arachnid_evidence::load_signing_key(p),
        None => cert::ephemeral_key(),
    }
}

fn default_operator() -> String {
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".into());
    format!("{user}@{}", std::env::consts::OS)
}
