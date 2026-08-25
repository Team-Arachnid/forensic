//! Arachnid Recover — file carving and filesystem-aware recovery.
//!
//! Part of the Arachnid Forensic suite, and read-only against its target in the
//! same way `arachnid-core` is: the only writes go to the output directory you
//! name. Unlike `arachnid-sanitize`, nothing here can write to the media under
//! examination — see `arachnid_recover_core::source` for why that is a property
//! of the types rather than a promise.
//!
//! One rail is worth stating up front, because it is the mistake that destroys
//! the evidence: **recovery output must not land on the device being recovered
//! from.** Writing a recovered file onto the source overwrites exactly the
//! unallocated space the rest of the recovery is reading. `scan` and `export`
//! refuse it where the platform lets them prove it, and say so loudly where they
//! cannot.

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use arachnid_recover_core::{
    carve, export,
    results::{Confidence, ScanResults},
    source::{DeviceSource, ImageSource, Source},
    Progress, ScanOptions,
};
use clap::{Args, Parser, Subcommand};

/// Exit codes, stable across releases so a case-processing script can branch on
/// them. Parallel to `arachnid-core`'s and `arachnid-sanitize`'s.
mod exit {
    pub const OK: u8 = 0;
    pub const ERROR: u8 = 1;
    pub const _USAGE: u8 = 2;
    /// A safety rail refused the job. Nothing was read or written.
    pub const REFUSED: u8 = 3;
    /// The work completed, but something was skipped: an unsupported
    /// filesystem feature, a file that would not read back, a cancelled pass.
    pub const DEGRADED: u8 = 4;
}

/// Default filename for a scan's results index.
pub const RESULTS_FILE: &str = "results.json";
/// Default filename for the human-readable summary written beside it.
pub const SUMMARY_FILE: &str = "summary.txt";

#[derive(Parser)]
#[command(
    name = "arachnid-recover",
    version,
    about = "Arachnid Recover — file carving and recovery (Arachnid Forensic suite)",
    long_about = "Recovers files from a disk image or a read-only device, by parsing filesystem \
metadata (NTFS MFT, ext4 inodes and journal) and by carving raw sectors for file signatures.\n\n\
Read-only against the source. Output always goes to a separate directory you name, and every \
exported file is hashed into a signed chain-of-custody log that `arachnid-core verify` checks.\n\n\
Encrypted files are reported as encrypted and left alone. No key recovery, password guessing or \
brute force of any kind is implemented.\n\n\
EXIT CODES\n  \
0  success\n  \
1  runtime error\n  \
2  usage error\n  \
3  refused by a safety rail\n  \
4  completed, but something was skipped or unsupported"
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
    /// Recover from an image or read-only device: filesystem pass, carving
    /// pass, or both.
    Scan(ScanArgs),
    /// Signature carving only, for media with no filesystem left to parse.
    Carve(CarveArgs),
    /// List and filter the results of a completed scan.
    ListResults(ListArgs),
    /// Write selected recovered files out, with a chain-of-custody log.
    Export(ExportArgs),
}

#[derive(Args)]
struct ScanArgs {
    /// Disk image, partition image, or device path (/dev/sdb, \\.\PhysicalDrive2).
    /// A device is opened read-only.
    #[arg(long, short, value_name = "PATH")]
    input: PathBuf,

    /// Where results.json and summary.txt are written. Must not be on the
    /// device being scanned.
    #[arg(long, short, value_name = "DIR")]
    output: PathBuf,

    /// Parse filesystem metadata. On by default; accepted so the intent can be
    /// stated explicitly in a scripted run.
    #[arg(long)]
    filesystem_pass: bool,

    /// Skip the filesystem pass. `carve` is the shorter way to say the same
    /// thing when carving is all you want.
    #[arg(long, conflicts_with = "filesystem_pass")]
    no_filesystem_pass: bool,

    /// Also scan raw sectors for file signatures. Adds to the filesystem pass
    /// rather than replacing it.
    #[arg(long)]
    carve_pass: bool,

    /// Types the carving pass looks for, comma-separated.
    /// Default: every type except txt, which matches too much on a real volume.
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    carve_types: Vec<String>,

    /// Also report files the filesystem still considers live. Off by default:
    /// live files are readable through the OS, and including them buries the
    /// deleted ones an investigation is usually after.
    #[arg(long)]
    include_live: bool,

    /// Operator identity recorded in the results.
    #[arg(long, value_name = "NAME")]
    operator: Option<String>,
}

#[derive(Args)]
struct CarveArgs {
    /// Image or device to carve.
    #[arg(long, short, value_name = "PATH")]
    input: PathBuf,

    /// Where results.json and summary.txt are written.
    #[arg(long, short, value_name = "DIR")]
    output: PathBuf,

    /// Types to carve, comma-separated. See --help for the full list.
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    carve_types: Vec<String>,

    #[arg(long, value_name = "NAME")]
    operator: Option<String>,
}

#[derive(Args)]
struct ListArgs {
    /// A results.json written by scan or carve.
    #[arg(long, short, value_name = "PATH")]
    input: PathBuf,

    /// Keep only these confidence levels, comma-separated: high, medium, low.
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    confidence: Vec<String>,

    /// Keep only these file types, comma-separated.
    #[arg(long = "type", value_name = "LIST", value_delimiter = ',')]
    types: Vec<String>,

    /// Print the full scoring rationale for one result, by id.
    #[arg(long, value_name = "ID")]
    detail: Option<String>,
}

#[derive(Args)]
struct ExportArgs {
    /// A results.json written by scan or carve.
    #[arg(long, short, value_name = "PATH")]
    input: PathBuf,

    /// Directory to write recovered files and the custody log into. Created if
    /// it does not exist; must be empty of a prior container.
    #[arg(long, short, value_name = "DIR")]
    output: PathBuf,

    /// Read from this image or device instead of the one recorded in the
    /// results. Use when the image has moved since the scan.
    #[arg(long, value_name = "PATH")]
    source: Option<PathBuf>,

    /// Export only these confidence levels, comma-separated.
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    confidence: Vec<String>,

    /// Export only these file types, comma-separated.
    #[arg(long = "type", value_name = "LIST", value_delimiter = ',')]
    types: Vec<String>,

    /// Export only these result ids, comma-separated. Overrides the filters.
    #[arg(long, value_name = "LIST", value_delimiter = ',')]
    id: Vec<String>,

    #[arg(long, value_name = "NAME")]
    operator: Option<String>,
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
        Command::Scan(a) => cmd_scan(cli, a),
        Command::Carve(a) => cmd_carve(cli, a),
        Command::ListResults(a) => cmd_list(cli, a),
        Command::Export(a) => cmd_export(cli, a),
    }
}

// ---------------------------------------------------------------------------
// Opening a source
// ---------------------------------------------------------------------------

/// True when `path` names a raw device rather than a file.
pub fn looks_like_device(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.starts_with("/dev/") || s.starts_with(r"\\.\") || s.starts_with(r"\\?\")
}

/// Open an image or a device, read-only either way.
fn open_source(path: &Path) -> Result<Box<dyn Source>> {
    if looks_like_device(path) {
        tracing::info!(device = %path.display(), "opening device read-only");
        Ok(Box::new(DeviceSource::open(&path.to_string_lossy())?))
    } else {
        if !path.is_file() {
            bail!(
                "{} is not a readable file. For a device, give its OS path \
                 (/dev/sdb, \\\\.\\PhysicalDrive2).",
                path.display()
            );
        }
        Ok(Box::new(ImageSource::open(path)?))
    }
}

/// Refuse to write recovery output onto the device being recovered from.
///
/// This is the mistake that quietly destroys the case: every byte written to the
/// source lands in the unallocated space the recovery is reading out of. On
/// Linux the mount table proves it outright. Elsewhere it cannot be proven
/// cheaply, so the risk is stated rather than assumed away — refusing on a guess
/// would block legitimate work, and staying silent would let a real one through.
fn check_output_not_on_source(input: &Path, output: &Path) -> Result<Option<String>> {
    if !looks_like_device(input) {
        // An image is an ordinary file. Writing results beside it is normal and
        // touches nothing the scan reads.
        return Ok(None);
    }
    let device = input.to_string_lossy().to_string();
    let resolved = export::resolve_output(output);
    same_media(&device, &resolved, output)
}

/// Linux can prove it from the mount table.
#[cfg(target_os = "linux")]
fn same_media(device: &str, resolved: &Path, output: &Path) -> Result<Option<String>> {
    let _ = output;
    let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
    let mut offending: Option<(String, String)> = None;
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let (Some(src), Some(point)) = (parts.next(), parts.next()) else {
            continue;
        };
        // /proc/mounts escapes spaces as \040. A mount point this misses falls
        // through to no match, which is the safe direction only because the
        // refusal below is not the only thing standing between the operator and
        // the mistake — the summary says where output went, every time.
        let point = point.replace("\\040", " ");
        if !src.starts_with(device) || !resolved.starts_with(&point) {
            continue;
        }
        // Keep the longest matching mount point: /mnt/case beats /.
        if offending
            .as_ref()
            .is_none_or(|(_, p)| point.len() > p.len())
        {
            offending = Some((src.to_string(), point));
        }
    }
    match offending {
        Some((src, point)) => bail!(
            "the output directory {} is on {src}, mounted at {point}, which is part of the device \
             being recovered from. Writing there would overwrite the unallocated space this \
             recovery reads out of. Choose an output directory on different media.",
            resolved.display()
        ),
        None => Ok(None),
    }
}

/// Elsewhere it cannot be proven cheaply, so the risk is stated rather than
/// assumed away: refusing on a guess would block legitimate work, and staying
/// silent would let a real one through.
#[cfg(not(target_os = "linux"))]
fn same_media(device: &str, resolved: &Path, output: &Path) -> Result<Option<String>> {
    let _ = resolved;
    Ok(Some(format!(
        "cannot prove on this platform that {} is not on {device}. If it is, this recovery will \
         overwrite the space it is reading. Verify the output is on different media before \
         continuing.",
        output.display()
    )))
}

// ---------------------------------------------------------------------------
// scan / carve
// ---------------------------------------------------------------------------

fn cmd_scan(cli: &Cli, a: &ScanArgs) -> Result<u8> {
    // The filesystem pass is the default and --carve-pass adds to it, rather
    // than replacing it: an operator who asks for more work should never
    // silently get less. `carve` is the subcommand for carving alone.
    let options = ScanOptions {
        filesystem_pass: !a.no_filesystem_pass,
        carve_pass: a.carve_pass,
        carve_types: if a.carve_types.is_empty() {
            carve::default_types()
        } else {
            a.carve_types.clone()
        },
        deleted_only: !a.include_live,
        operator: a
            .operator
            .clone()
            .unwrap_or_else(arachnid_recover_core::default_operator),
    };
    scan_and_write(cli, &a.input, &a.output, options)
}

fn cmd_carve(cli: &Cli, a: &CarveArgs) -> Result<u8> {
    let options = ScanOptions {
        filesystem_pass: false,
        carve_pass: true,
        carve_types: if a.carve_types.is_empty() {
            carve::default_types()
        } else {
            a.carve_types.clone()
        },
        deleted_only: true,
        operator: a
            .operator
            .clone()
            .unwrap_or_else(arachnid_recover_core::default_operator),
    };
    scan_and_write(cli, &a.input, &a.output, options)
}

fn scan_and_write(cli: &Cli, input: &Path, output: &Path, options: ScanOptions) -> Result<u8> {
    for t in &options.carve_types {
        if !carve::known_types()
            .iter()
            .any(|k| k.eq_ignore_ascii_case(t))
        {
            bail!(
                "unknown carve type {t:?}. Known types: {}",
                carve::known_types().join(", ")
            );
        }
    }

    match check_output_not_on_source(input, output) {
        Ok(Some(warning)) => {
            tracing::warn!("{warning}");
            eprintln!("WARNING: {warning}");
        }
        Ok(None) => {}
        Err(refusal) => {
            tracing::error!("{refusal:#}");
            eprintln!("REFUSED: {refusal:#}");
            return Ok(exit::REFUSED);
        }
    }

    let mut source = open_source(input)?;
    std::fs::create_dir_all(output)
        .with_context(|| format!("create output directory {}", output.display()))?;

    let cancel = Arc::new(AtomicBool::new(false));
    let handler = cancel.clone();
    // Ctrl-C stops at the next chunk rather than killing the process, so the
    // results file still records everything found up to that point.
    ctrlc::set_handler(move || handler.store(true, Ordering::Relaxed))
        .context("install interrupt handler")?;

    let progress = Progress::default();
    if !cli.json {
        println!("Scanning {} ({} bytes)…", source.label(), source.size());
    }
    let results = arachnid_recover_core::scan(source.as_mut(), &options, &progress, &cancel)?;

    let results_path = output.join(RESULTS_FILE);
    std::fs::write(&results_path, serde_json::to_vec_pretty(&results)?)
        .with_context(|| format!("write {}", results_path.display()))?;
    let summary_path = output.join(SUMMARY_FILE);
    std::fs::write(&summary_path, results.summary())
        .with_context(|| format!("write {}", summary_path.display()))?;

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        print!("{}", results.summary());
        println!("\nResults index: {}", results_path.display());
        println!("Summary:       {}", summary_path.display());
        println!(
            "\nNothing has been written to the source. To write the recovered files out:\n  \
             arachnid-recover export -i {} -o <DIR> --confidence high,medium",
            results_path.display()
        );
    }

    Ok(outcome_code(&results))
}

/// Degraded when the scan left something out; success otherwise.
fn outcome_code(results: &ScanResults) -> u8 {
    let unsupported = results
        .filesystems
        .iter()
        .any(|f| !f.unsupported.is_empty());
    if !results.problems.is_empty() || unsupported {
        exit::DEGRADED
    } else {
        exit::OK
    }
}

// ---------------------------------------------------------------------------
// list-results
// ---------------------------------------------------------------------------

fn parse_confidence(list: &[String]) -> Result<Vec<Confidence>> {
    list.iter()
        .map(|s| {
            Confidence::parse(s)
                .ok_or_else(|| anyhow::anyhow!("unknown confidence {s:?}: use high, medium or low"))
        })
        .collect()
}

fn cmd_list(cli: &Cli, a: &ListArgs) -> Result<u8> {
    let results = arachnid_recover_core::load_results(&a.input)?;

    if let Some(id) = &a.detail {
        let Some(file) = results.files.iter().find(|f| &f.id == id) else {
            bail!("no result with id {id:?} in {}", a.input.display());
        };
        if cli.json {
            println!("{}", serde_json::to_string_pretty(file)?);
            return Ok(exit::OK);
        }
        println!("{}  {}", file.id, file.display_name());
        println!("  method      {}", file.method.label());
        println!("  type        {}", file.file_type);
        println!("  size        {} bytes", file.size);
        println!("  deleted     {}", file.deleted);
        if let Some(t) = &file.modified_utc {
            println!("  modified    {t}");
        }
        if let Some(e) = &file.encrypted {
            println!("  ENCRYPTED   {e}");
        }
        println!("  extents     {}", file.extents.len());
        for e in file.extents.iter().take(10) {
            println!("    offset {:<16} {} bytes", e.offset, e.length);
        }
        println!(
            "\n  confidence  {}\n  {}\n",
            file.rationale.confidence.label(),
            file.rationale.summary
        );
        println!("  checks");
        for c in &file.rationale.checks {
            println!(
                "    [{}] {:<26} {}",
                if c.passed { "ok" } else { "  " },
                c.check,
                c.detail
            );
        }
        return Ok(exit::OK);
    }

    let confidence = parse_confidence(&a.confidence)?;
    let selected: Vec<_> = results.filter(&confidence, &a.types).collect();

    if cli.json {
        println!("{}", serde_json::to_string_pretty(&selected)?);
        return Ok(outcome_code(&results));
    }

    if selected.is_empty() {
        println!("No results match. {} in the file.", results.files.len());
        return Ok(outcome_code(&results));
    }
    println!(
        "{:<14} {:<8} {:<6} {:>12}  {:<12} NAME / PATH",
        "ID", "CONF", "TYPE", "SIZE", "METHOD"
    );
    for f in &selected {
        println!(
            "{:<14} {:<8} {:<6} {:>12}  {:<12} {}{}",
            f.id,
            f.rationale.confidence.label(),
            f.file_type,
            f.size,
            f.method.label(),
            f.display_name(),
            if f.encrypted.is_some() {
                "  [ENCRYPTED]"
            } else {
                ""
            }
        );
    }
    println!(
        "\n{} of {} result(s). Use --detail <ID> for the scoring rationale.",
        selected.len(),
        results.files.len()
    );
    Ok(outcome_code(&results))
}

// ---------------------------------------------------------------------------
// export
// ---------------------------------------------------------------------------

fn cmd_export(cli: &Cli, a: &ExportArgs) -> Result<u8> {
    let results = arachnid_recover_core::load_results(&a.input)?;
    let source_path = a
        .source
        .clone()
        .unwrap_or_else(|| PathBuf::from(&results.source));

    match check_output_not_on_source(&source_path, &a.output) {
        Ok(Some(warning)) => eprintln!("WARNING: {warning}"),
        Ok(None) => {}
        Err(refusal) => {
            eprintln!("REFUSED: {refusal:#}");
            return Ok(exit::REFUSED);
        }
    }

    let confidence = parse_confidence(&a.confidence)?;
    let selected: Vec<_> = if a.id.is_empty() {
        results.filter(&confidence, &a.types).collect()
    } else {
        results
            .files
            .iter()
            .filter(|f| a.id.iter().any(|i| i == &f.id))
            .collect()
    };
    if selected.is_empty() {
        bail!(
            "nothing selected to export from {} ({} result(s) in the file)",
            a.input.display(),
            results.files.len()
        );
    }

    let mut source = open_source(&source_path).with_context(|| {
        format!(
            "open the source the results were scanned from ({}). Pass --source if it has moved.",
            source_path.display()
        )
    })?;
    // Refused here rather than after the container exists, so a rejected export
    // leaves nothing behind. `export` checks again; this is only so the refusal
    // carries the exit code a rail refusal should.
    match export::check_source_matches(source.as_mut(), &results) {
        Ok(Some(warning)) => eprintln!("WARNING: {warning}"),
        Ok(None) => {}
        Err(refusal) => {
            tracing::error!("{refusal:#}");
            eprintln!("REFUSED: {refusal:#}");
            return Ok(exit::REFUSED);
        }
    }

    let operator = a
        .operator
        .clone()
        .unwrap_or_else(|| results.operator.clone());
    let report = export::export(source.as_mut(), &results, &selected, &a.output, &operator)?;

    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "output_dir": report.output_dir,
                "exported": report.exported,
                "skipped": report.skipped,
                "key_fingerprint": report.key_fingerprint,
            }))?
        );
    } else {
        println!(
            "Exported {} file(s) to {}",
            report.exported.len(),
            report.output_dir.display()
        );
        for (id, why) in &report.skipped {
            println!("  skipped {id}: {why}");
        }
        println!(
            "Chain of custody: {}",
            report.container.join("custody.log").display()
        );
        println!("Signing key SHA-256: {}", report.key_fingerprint);
        println!(
            "\nRecord that fingerprint out of band. Re-check the export at any time with:\n  \
             arachnid-core verify {}",
            report.output_dir.display()
        );
    }

    Ok(if report.skipped.is_empty() {
        exit::OK
    } else {
        exit::DEGRADED
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_paths_are_told_from_image_paths() {
        assert!(looks_like_device(Path::new("/dev/sdb")));
        assert!(looks_like_device(Path::new(r"\\.\PhysicalDrive2")));
        assert!(!looks_like_device(Path::new("./evidence/disk.img")));
        assert!(!looks_like_device(Path::new("/home/a/dev/sdb.img")));
    }

    /// Writing beside an image file is normal and must not be refused; the rail
    /// exists for devices.
    #[test]
    fn an_image_source_never_trips_the_output_rail() {
        assert!(
            check_output_not_on_source(Path::new("disk.img"), Path::new("/tmp/out"))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn confidence_lists_parse_or_explain_themselves() {
        assert_eq!(
            parse_confidence(&["high".into(), "medium".into()]).unwrap(),
            vec![Confidence::High, Confidence::Medium]
        );
        let e = parse_confidence(&["definitely".into()]).unwrap_err();
        assert!(e.to_string().contains("high, medium or low"));
    }

    #[test]
    fn the_cli_surface_parses() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }
}
