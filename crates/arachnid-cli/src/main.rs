//! Arachnid Forensic — the single entry point.
//!
//! One command to remember. Bare, it opens the terminal UI, which covers every
//! module. With a subcommand it runs the same triage and erasure paths the
//! standalone `arachnid-core` and `arachnid-sanitize` binaries expose, by
//! calling into them directly — nothing is re-exec'd, so the release build
//! stays a single file and the exit codes are the ones the callee returns.
//!
//! Those two binaries still ship: SOAR playbooks and the release scripts refer
//! to them by name, and their exit codes are a documented contract. This is a
//! front door, not a replacement.

use std::ffi::OsString;
use std::process::ExitCode;

/// Everything `arachnid-core` answers to. Anything in this list is forwarded to
/// it verbatim; `sanitize` goes to the erasure CLI; anything else is a usage
/// error we answer ourselves rather than letting a callee guess at it.
const CORE: [&str; 6] = [
    "collect",
    "capture",
    "parse-pcap",
    "verify",
    "report",
    "help",
];

const USAGE: &str = "\
Arachnid Forensic — live triage, network forensics and secure erasure.

USAGE
  arachnid-cli                     open the terminal UI (every module)
  arachnid-cli tui                 the same, explicitly
  arachnid-cli <command> [args]    run one command directly

TRIAGE AND NETWORK FORENSICS
  collect        collect volatile system state into an evidence container
  capture        capture live network traffic
  parse-pcap     parse a PCAP: flows, TCP streams, indicators
  verify         re-hash a container and check it against its signed log
  report         re-render a container's report

SECURE ERASURE — destroys data
  sanitize       list-devices | wipe | verify-wipe | cert

Add --help to any command for its own options, e.g.
  arachnid-cli collect --help
  arachnid-cli sanitize wipe --help

EXIT CODES
  Passed through from the command that ran. 0 success, 1 runtime error,
  2 usage, 3 integrity failure or a refused wipe, 4 degraded or unverified,
  5 erasure completed with unwritable regions.

For use by authorized analysts on systems they have permission to examine.
";

/// Globals that take a separate value, so the token after them is that value
/// and must not be mistaken for the command. `--json` takes none.
const VALUED: [&str; 2] = ["--log", "--log-level"];

/// Index of the token naming the command.
///
/// Not simply `args[1]`: both callees accept their globals *before* the
/// subcommand — `--json verify …` is the documented form — so the command can
/// sit anywhere in the list. Skips the value of a valued global so that
/// `--log report collect` routes on `collect`, not on the log filename.
fn command_at(args: &[OsString]) -> Option<(usize, String)> {
    let mut i = 1;
    while i < args.len() {
        let tok = args[i].to_string_lossy().into_owned();
        if VALUED.contains(&tok.as_str()) {
            i += 2;
            continue;
        }
        if tok.starts_with('-') {
            i += 1;
            continue;
        }
        return Some((i, tok));
    }
    None
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().collect();

    // A bare -h/--help/-V with no command is ours to answer.
    let flags: Vec<String> = args[1..]
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let command = command_at(&args);
    if command.is_none() {
        if flags.iter().any(|f| f == "-h" || f == "--help") {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        if flags.iter().any(|f| f == "-V" || f == "--version") {
            println!("arachnid-cli {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
    }

    match command.as_ref().map(|(_, c)| c.as_str()) {
        // No subcommand is the common case: open the UI.
        None | Some("tui") => match arachnid_core_tui::start() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },

        // Re-label argv[0] so the callee's own --help and usage errors name the
        // command the operator actually typed, not the crate behind it. The
        // "sanitize" token itself is dropped; everything around it, globals
        // included, is passed through untouched.
        Some("sanitize") => {
            let at = command.expect("matched above").0;
            let mut forwarded = vec![OsString::from("arachnid-cli sanitize")];
            forwarded.extend(
                args.into_iter()
                    .enumerate()
                    .filter(|(i, _)| *i != 0 && *i != at)
                    .map(|(_, a)| a),
            );
            arachnid_sanitize_cli::run_from(forwarded)
        }

        Some(cmd) if CORE.contains(&cmd) => {
            let mut forwarded = vec![OsString::from("arachnid-cli")];
            forwarded.extend(args.into_iter().skip(1));
            arachnid_core_cli::run_from(forwarded)
        }

        Some(other) => {
            eprintln!("error: unknown command {other:?}\n");
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(argv: &[&str]) -> Option<String> {
        let args: Vec<OsString> = std::iter::once("arachnid-cli")
            .chain(argv.iter().copied())
            .map(OsString::from)
            .collect();
        command_at(&args).map(|(_, c)| c)
    }

    /// Routing has to survive the globals both callees accept ahead of the
    /// subcommand, because `--json verify` is the documented form.
    #[test]
    fn the_command_is_found_past_leading_globals() {
        assert_eq!(at(&[]), None);
        assert_eq!(at(&["collect"]).as_deref(), Some("collect"));
        assert_eq!(at(&["--json", "verify", "./ev"]).as_deref(), Some("verify"));
        assert_eq!(at(&["sanitize", "wipe"]).as_deref(), Some("sanitize"));
    }

    /// The value of a valued global is not the command. `--log report collect`
    /// logs to a file called "report" and runs collect — routing on the
    /// filename would send it to the wrong callee.
    #[test]
    fn a_valued_global_does_not_swallow_the_command() {
        assert_eq!(
            at(&["--log", "report", "collect"]).as_deref(),
            Some("collect")
        );
        assert_eq!(
            at(&["--log-level", "warn", "verify"]).as_deref(),
            Some("verify")
        );
        assert_eq!(
            at(&["--log", "sanitize", "collect"]).as_deref(),
            Some("collect")
        );
    }

    /// Every name the dispatcher claims to forward must be one the callee
    /// actually has, or the front door advertises a command that does not run.
    #[test]
    fn usage_lists_exactly_what_is_routed() {
        for cmd in CORE.iter().filter(|c| **c != "help") {
            assert!(
                USAGE.contains(cmd),
                "{cmd} is routed but not in the usage text"
            );
        }
        assert!(USAGE.contains("sanitize"));
    }
}
