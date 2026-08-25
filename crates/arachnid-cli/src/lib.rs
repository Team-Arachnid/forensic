//! Arachnid Forensic — the single entry point.
//!
//! One command to remember. Bare, it opens the terminal UI, which covers every
//! module. With a subcommand it runs the same triage, recovery and erasure paths
//! the standalone `arachnid-core`, `arachnid-recover` and `arachnid-sanitize`
//! binaries expose, by calling into them directly — nothing is re-exec'd, so the
//! release build stays a single file and the exit codes are the ones the callee
//! returns.
//!
//! Those binaries still ship: SOAR playbooks and the release scripts refer to
//! them by name, and their exit codes are a documented contract. This is a front
//! door, not a replacement.
//!
//! # Why the dispatch is hand-rolled
//!
//! Each module already owns a complete `clap` definition, with its own flags,
//! its own `--help` and its own documented exit codes. Re-declaring those here
//! would give an operator two sources of truth for one flag and let them drift.
//! So this layer only finds the command token and forwards everything else
//! **verbatim** to the module that owns it. What `arachnid-cli recover scan
//! --help` prints is what `arachnid-recover scan --help` prints, because it is
//! the same code reading the same arguments.

use std::ffi::OsString;
use std::process::ExitCode;

pub mod doctor;
pub mod selfcmd;
pub mod update;

/// Module groups. The first token after any globals selects one, and everything
/// after it belongs to that module's own parser.
const GROUPS: [&str; 3] = ["core", "recover", "sanitize"];

/// `arachnid-core`'s own subcommands.
///
/// Accepted at the top level too, without the `core` prefix: that is the form
/// every existing script, playbook and doc page uses, and breaking it to tidy up
/// the grammar would be a poor trade. `core collect` is the documented form;
/// `collect` keeps working.
const CORE: [&str; 6] = [
    "collect",
    "capture",
    "parse-pcap",
    "verify",
    "report",
    "help",
];

pub const USAGE: &str = "\
Arachnid Forensic — live triage, network forensics, file recovery and secure erasure.

USAGE
  arachnid-cli                          open the terminal UI (every module)
  arachnid-cli tui                      the same, explicitly
  arachnid-cli <module> <command>       run one command directly

MODULES
  core       collect | capture | parse-pcap | verify | report
             live triage and network forensics. Read-only against the target.
  recover    scan | carve | list-results | export
             file carving and recovery. Read-only against the source.
  sanitize   list-devices | wipe | verify-wipe | cert
             secure erasure. DESTROYS DATA.

TOOL
  doctor                 check this installation and report what is wrong
  version                version, build hash, and release signing key
  self update            download, verify and replace this binary
  self uninstall         remove this binary and revert the installer's PATH edit

OPTIONS
  --no-update-check      skip the launch-time update check for this run
                         (ARACHNID_NO_UPDATE_CHECK=1 disables it permanently)

The five `core` commands also work without the `core` prefix, which is the form
older scripts use:  arachnid-cli collect -o ./ev-host01

Add --help to any command for its own options, e.g.
  arachnid-cli core collect --help
  arachnid-cli recover scan --help
  arachnid-cli sanitize wipe --help

EXIT CODES
  Passed through from the command that ran. 0 success, 1 runtime error,
  2 usage, 3 integrity failure or a refused job, 4 degraded, unverified or
  incomplete, 5 erasure completed with unwritable regions.

For use by authorized analysts on systems they have permission to examine.
";

/// Globals that take a separate value, so the token after them is that value
/// and must not be mistaken for the command. `--json` takes none.
const VALUED: [&str; 2] = ["--log", "--log-level"];

/// Flags this layer consumes itself. They are stripped before forwarding,
/// because no module's parser knows them and clap would reject the whole
/// invocation on one it has never heard of.
const OURS: [&str; 1] = ["--no-update-check"];

/// Index of the token naming the command.
///
/// Not simply `args[1]`: every callee accepts its globals *before* the
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

/// Remove the flags this layer owns, reporting whether any were present.
fn take_ours(args: &mut Vec<OsString>) -> bool {
    let before = args.len();
    args.retain(|a| !OURS.contains(&a.to_string_lossy().as_ref()));
    before != args.len()
}

/// Forward to a module, relabelling `argv[0]` so the callee's own `--help` and
/// usage errors name the command the operator actually typed rather than the
/// crate behind it.
///
/// `drop` is the index of a token to remove — the group name, which the module
/// itself has never heard of.
fn forward(
    args: Vec<OsString>,
    label: &str,
    drop: Option<usize>,
    run: fn(Vec<OsString>) -> ExitCode,
) -> ExitCode {
    let mut forwarded = vec![OsString::from(label)];
    forwarded.extend(
        args.into_iter()
            .enumerate()
            .filter(|(i, _)| *i != 0 && Some(*i) != drop)
            .map(|(_, a)| a),
    );
    run(forwarded)
}

/// Parse `args` and run, returning the process exit code.
pub fn run_from(args: impl IntoIterator<Item = OsString>) -> ExitCode {
    let mut args: Vec<OsString> = args.into_iter().collect();
    let opted_out = take_ours(&mut args);

    let flags: Vec<String> = args[1..]
        .iter()
        .map(|a| a.to_string_lossy().into_owned())
        .collect();
    let command = command_at(&args);

    // A bare -h/--help/-V with no command is ours to answer.
    if command.is_none() {
        if flags.iter().any(|f| f == "-h" || f == "--help") {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        if flags.iter().any(|f| f == "-V" || f == "--version") {
            print!("{}", update::version_report());
            return ExitCode::SUCCESS;
        }
    }

    let name = command.as_ref().map(|(_, c)| c.as_str());

    // The check is a courtesy, so it stands down wherever it would be noise: the
    // update commands themselves, and `doctor`, which reports the same thing in
    // context and with a remediation line.
    let quiet = matches!(name, Some("self") | Some("doctor") | Some("version"));
    if !opted_out && !quiet {
        update::notify_if_newer();
    }

    match name {
        // No subcommand is the common case: open the UI.
        None | Some("tui") => match arachnid_core_tui::start() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        },

        Some("doctor") => doctor::run(&args),
        Some("version") => {
            print!("{}", update::version_report());
            ExitCode::SUCCESS
        }

        // `self <verb>`, and `uninstall` as a top-level alias because that is
        // the word people try first when they want a tool gone.
        Some("self") => {
            let at = command.expect("matched above").0;
            selfcmd::run(args.get(at + 1).map(|a| a.to_string_lossy().into_owned()))
        }
        Some("uninstall") => selfcmd::run(Some("uninstall".into())),

        Some(group) if GROUPS.contains(&group) => {
            let at = command.as_ref().expect("matched above").0;
            let label = format!("arachnid-cli {group}");
            match group {
                "recover" => forward(args, &label, Some(at), arachnid_recover_cli::run_from),
                "sanitize" => forward(args, &label, Some(at), arachnid_sanitize_cli::run_from),
                _ => forward(args, &label, Some(at), arachnid_core_cli::run_from),
            }
        }

        // The prefix-free form. Kept working, deliberately: see CORE.
        Some(cmd) if CORE.contains(&cmd) => {
            forward(args, "arachnid-cli", None, arachnid_core_cli::run_from)
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

    fn argv(items: &[&str]) -> Vec<OsString> {
        std::iter::once("arachnid-cli")
            .chain(items.iter().copied())
            .map(OsString::from)
            .collect()
    }

    fn at(items: &[&str]) -> Option<String> {
        command_at(&argv(items)).map(|(_, c)| c)
    }

    /// Routing has to survive the globals every callee accepts ahead of the
    /// subcommand, because `--json verify` is the documented form.
    #[test]
    fn the_command_is_found_past_leading_globals() {
        assert_eq!(at(&[]), None);
        assert_eq!(at(&["collect"]).as_deref(), Some("collect"));
        assert_eq!(at(&["--json", "verify", "./ev"]).as_deref(), Some("verify"));
        assert_eq!(at(&["sanitize", "wipe"]).as_deref(), Some("sanitize"));
        assert_eq!(at(&["recover", "scan"]).as_deref(), Some("recover"));
        assert_eq!(at(&["core", "collect"]).as_deref(), Some("core"));
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
        assert_eq!(
            at(&["--log", "core", "recover", "scan"]).as_deref(),
            Some("recover")
        );
    }

    /// The group token is ours; the module's parser has never heard of it and
    /// would reject the whole invocation.
    #[test]
    fn the_group_token_is_dropped_and_the_rest_forwarded_verbatim() {
        let args = argv(&["--json", "recover", "scan", "-i", "x.img"]);
        let at = command_at(&args).unwrap().0;
        let mut seen: Vec<OsString> = Vec::new();
        let forwarded = {
            // Rebuild what `forward` builds, without running a module.
            let mut v = vec![OsString::from("arachnid-cli recover")];
            v.extend(
                args.into_iter()
                    .enumerate()
                    .filter(|(i, _)| *i != 0 && *i != at)
                    .map(|(_, a)| a),
            );
            v
        };
        seen.extend(forwarded.iter().cloned());
        let as_str: Vec<String> = seen
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            as_str,
            ["arachnid-cli recover", "--json", "scan", "-i", "x.img"]
        );
    }

    /// `--no-update-check` is ours. Left in the list it would reach a module's
    /// clap parser, which rejects unknown flags and would fail the whole run.
    #[test]
    fn our_own_flag_never_reaches_a_module() {
        let mut args = argv(&["--no-update-check", "recover", "scan", "-i", "x.img"]);
        assert!(take_ours(&mut args));
        let as_str: Vec<String> = args
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert!(!as_str.contains(&"--no-update-check".to_string()));
        assert_eq!(command_at(&args).unwrap().1, "recover");

        let mut clean = argv(&["recover", "scan"]);
        assert!(!take_ours(&mut clean));
    }

    /// Every name the dispatcher claims to route must be one a callee actually
    /// has, or the front door advertises a command that does not run.
    #[test]
    fn usage_lists_exactly_what_is_routed() {
        for cmd in CORE.iter().filter(|c| **c != "help") {
            assert!(
                USAGE.contains(cmd),
                "{cmd} is routed but not in the usage text"
            );
        }
        for group in GROUPS {
            assert!(
                USAGE.contains(group),
                "{group} is routed but not in the usage text"
            );
        }
        for tool in ["doctor", "version", "self update", "self uninstall"] {
            assert!(
                USAGE.contains(tool),
                "{tool} is routed but not in the usage text"
            );
        }
        assert!(USAGE.contains("--no-update-check"));
    }

    /// The prefix-free form is a compatibility promise, not an accident. Every
    /// script and doc page written before the groups existed uses it.
    #[test]
    fn the_prefix_free_core_form_still_routes() {
        for cmd in CORE {
            assert_eq!(at(&[cmd]).as_deref(), Some(cmd));
            assert!(
                CORE.contains(&cmd),
                "{cmd} would fall through to the unknown-command arm"
            );
        }
    }
}
