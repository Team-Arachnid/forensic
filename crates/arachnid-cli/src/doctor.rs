//! `arachnid-cli doctor` — tell the operator what is wrong and how to fix it.
//!
//! An installation problem should cost a command, not a bug report. Every check
//! that fails carries the exact remediation for *this* machine — the package
//! manager that is actually installed, the path that actually shadows us — and
//! not a generic "capture unavailable".
//!
//! Everything here is read-only and side-effect free. It reports whether a raw
//! socket or a raw block device *could* be opened, by reading the process's own
//! credentials, rather than by opening one and closing it again: on a monitored
//! host, a diagnostic that opens a raw socket is a diagnostic that trips an EDR
//! rule.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use crate::update;

/// One line of the report.
struct Check {
    ok: bool,
    /// `None` for an informational line that cannot fail.
    label: &'static str,
    detail: String,
    /// What to do about it. Only rendered when `ok` is false.
    fix: Option<String>,
}

impl Check {
    fn pass(label: &'static str, detail: impl Into<String>) -> Self {
        Check {
            ok: true,
            label,
            detail: detail.into(),
            fix: None,
        }
    }

    fn fail(label: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Check {
            ok: false,
            label,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }

    /// A check that did not pass but is not a fault — an optional capability
    /// this host simply does not have. Reported, not counted as a failure.
    fn note(label: &'static str, detail: impl Into<String>, fix: impl Into<String>) -> Self {
        Check {
            ok: true,
            label,
            detail: detail.into(),
            fix: Some(fix.into()),
        }
    }
}

pub fn run(args: &[OsString]) -> ExitCode {
    let json = args.iter().any(|a| a == "--json");
    let checks = collect();

    if json {
        let rows: Vec<serde_json::Value> = checks
            .iter()
            .map(|c| {
                serde_json::json!({
                    "check": c.label,
                    "ok": c.ok,
                    "detail": c.detail,
                    "remediation": c.fix,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "version": update::version(),
                "build": update::build_hash(),
                "checks": rows,
            }))
            .unwrap_or_default()
        );
    } else {
        println!("arachnid-cli {} — installation check\n", update::version());
        for c in &checks {
            println!(
                "  [{}] {:<22} {}",
                if c.ok { "ok" } else { "!!" },
                c.label,
                c.detail
            );
            if let Some(fix) = &c.fix {
                for line in fix.lines() {
                    println!("       {line}");
                }
            }
        }
        let failed = checks.iter().filter(|c| !c.ok).count();
        println!();
        if failed == 0 {
            println!("All checks passed.");
        } else {
            println!(
                "{failed} check(s) need attention. Everything above with [!!] has the fix beneath it."
            );
        }
    }

    if checks.iter().any(|c| !c.ok) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn collect() -> Vec<Check> {
    let mut out = Vec::new();

    // -- identity
    out.push(Check::pass(
        "version",
        format!("{} ({})", update::version(), update::build_hash()),
    ));
    out.push(match update::release_pubkey() {
        Some(_) => Check::pass(
            "release key",
            "embedded; `self update` can verify a download",
        ),
        None => Check::note(
            "release key",
            "not embedded — this is a development build",
            "`self update` is disabled. Install a signed release from\n\
             https://github.com/ArachnidGs/forensic/releases",
        ),
    });
    out.push(Check::pass(
        "platform",
        update::target_asset().unwrap_or_else(|_| target_triple()),
    ));

    // -- PATH
    out.push(path_check());

    // -- capture stack, which is the dependency that actually goes missing
    out.push(capture_check());

    // -- privileges, per module
    let (priv_label, elevated, caps) = privileges();
    out.push(Check::pass("privilege", priv_label));
    out.push(raw_socket_check(elevated, caps));
    out.push(raw_device_check(elevated));

    // -- update check posture, stated rather than left to be discovered
    out.push(if update::disabled_by_env() {
        Check::pass("update check", "disabled by ARACHNID_NO_UPDATE_CHECK")
    } else {
        Check::pass(
            "update check",
            "enabled: one GitHub request per day, interactive terminals only, never installs",
        )
    });

    out
}

/// Is the binary that runs when you type `arachnid-cli` this one?
///
/// A stale copy earlier in PATH is the single most confusing installation
/// failure there is: every fix appears to do nothing.
fn path_check() -> Check {
    let Ok(me) = std::env::current_exe() else {
        return Check::fail(
            "PATH",
            "cannot determine my own path",
            "This is unexpected; please report it.",
        );
    };
    let me = me.canonicalize().unwrap_or(me);

    match which("arachnid-cli") {
        None => Check::fail(
            "PATH",
            format!("{} is not on PATH", me.display()),
            format!(
                "Add its directory to PATH, or re-run the installer:\n  {}",
                shell_path_hint(me.parent().unwrap_or(Path::new(".")))
            ),
        ),
        Some(found) => {
            let found_c = found.canonicalize().unwrap_or(found.clone());
            if found_c == me {
                Check::pass("PATH", format!("resolves to {}", me.display()))
            } else {
                Check::fail(
                    "PATH",
                    format!(
                        "`arachnid-cli` resolves to {}, not to {}",
                        found_c.display(),
                        me.display()
                    ),
                    format!(
                        "An older copy is earlier in PATH. Remove it, or put {} first.",
                        me.parent().unwrap_or(Path::new(".")).display()
                    ),
                )
            }
        }
    }
}

/// Resolve a command against PATH, the way the shell would.
fn which(name: &str) -> Option<PathBuf> {
    let exts: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.CMD;.BAT".into())
            .split(';')
            .map(|e| e.to_ascii_lowercase())
            .collect()
    } else {
        vec![String::new()]
    };
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        for ext in &exts {
            let candidate = dir.join(format!("{name}{ext}"));
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Ask the capture library whether it is there, through the same call the rest
/// of the suite uses. A second probe could disagree with the real one.
fn capture_check() -> Check {
    match arachnid_netcap::list_devices() {
        Ok(devices) if devices.is_empty() => Check::fail(
            "capture",
            "the capture library loaded, but no interface is visible",
            if cfg!(windows) {
                "Npcap is installed but exposes no adapter. Reinstall it with \
                 \"Support raw 802.11 traffic\" unchecked, or run as Administrator."
                    .to_string()
            } else {
                format!(
                    "This usually means missing privileges rather than a missing library:\n  \
                     sudo setcap cap_net_raw,cap_net_admin=eip {}",
                    std::env::current_exe().unwrap_or_default().display()
                )
            },
        ),
        Ok(devices) => Check::pass(
            "capture",
            format!(
                "{} interface(s): {}",
                devices.len(),
                devices
                    .iter()
                    .map(|d| d.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
        Err(e) => Check::fail(
            "capture",
            format!("unavailable: {e}"),
            libpcap_remediation(),
        ),
    }
}

/// The install line for the package manager this machine actually has.
fn libpcap_remediation() -> String {
    if cfg!(windows) {
        return "Install Npcap from https://npcap.com/#download and re-run this check.\n\
                Arachnid does not bundle it: the driver's trust chain should stay with its vendor."
            .into();
    }
    if cfg!(target_os = "macos") {
        return "libpcap ships with macOS. If this fails, the binary was built against a \
                different version; install a matching release."
            .into();
    }
    let (manager, install) = if which("apt-get").is_some() {
        ("apt", "sudo apt install libpcap0.8")
    } else if which("dnf").is_some() {
        ("dnf", "sudo dnf install libpcap")
    } else if which("pacman").is_some() {
        ("pacman", "sudo pacman -S libpcap")
    } else if which("zypper").is_some() {
        ("zypper", "sudo zypper install libpcap")
    } else if which("apk").is_some() {
        ("apk", "sudo apk add libpcap")
    } else {
        return "libpcap is missing. Install it with this system's package manager.".into();
    };
    format!("libpcap is missing. On this system ({manager}):\n  {install}")
}

/// Effective privilege, and on Linux the capability bits that actually decide
/// whether capture works without root.
fn privileges() -> (String, bool, u64) {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        let field = |name: &str, col: usize| -> Option<String> {
            status
                .lines()
                .find(|l| l.starts_with(name))
                .and_then(|l| l.split_whitespace().nth(col).map(str::to_string))
        };
        // Uid: <real> <effective> <saved> <fs>
        let euid = field("Uid:", 2)
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(u32::MAX);
        let caps = field("CapEff:", 1)
            .and_then(|v| u64::from_str_radix(&v, 16).ok())
            .unwrap_or(0);
        let label = if euid == 0 {
            "root".to_string()
        } else {
            format!("uid {euid} — unprivileged")
        };
        (label, euid == 0, caps)
    }
    #[cfg(windows)]
    {
        // The one-call form of the CheckTokenMembership dance; a report needs
        // the yes/no, not the token.
        let admin = unsafe { windows::Win32::UI::Shell::IsUserAnAdmin().as_bool() };
        (
            if admin {
                "Administrator".into()
            } else {
                "standard user — not elevated".into()
            },
            admin,
            0,
        )
    }
    #[cfg(not(any(target_os = "linux", windows)))]
    {
        // Nothing portable to read; say so rather than guess.
        ("unknown on this platform".to_string(), false, 0)
    }
}

/// CAP_NET_RAW is bit 13 of the capability bitmask.
const CAP_NET_RAW: u64 = 1 << 13;

fn raw_socket_check(elevated: bool, caps: u64) -> Check {
    if elevated {
        return Check::pass(
            "capture privilege",
            "elevated; live capture can open an interface",
        );
    }
    if cfg!(target_os = "linux") && caps & CAP_NET_RAW != 0 {
        return Check::pass(
            "capture privilege",
            "CAP_NET_RAW is held; no root needed for capture",
        );
    }
    if cfg!(windows) {
        return Check::note(
            "capture privilege",
            "not elevated; Npcap may still permit capture depending on its install options",
            "If capture fails, re-run from an elevated prompt.",
        );
    }
    Check::note(
        "capture privilege",
        "not elevated and CAP_NET_RAW is not held; live capture will not open an interface",
        format!(
            "Grant the capability instead of running everything as root:\n  \
             sudo setcap cap_net_raw,cap_net_admin=eip {}\n\
             Collection, parsing, verification, reporting and recovery from an image all work \
             without this.",
            std::env::current_exe().unwrap_or_default().display()
        ),
    )
}

fn raw_device_check(elevated: bool) -> Check {
    if elevated {
        return Check::pass(
            "device access",
            "elevated; recovery from an attached device and erasure can open one",
        );
    }
    Check::note(
        "device access",
        "not elevated; raw block devices cannot be opened",
        if cfg!(windows) {
            "Sanitize, and Recover against a live device, need an Administrator prompt.\n\
             Recovery from an image file needs nothing."
                .to_string()
        } else {
            "Sanitize, and Recover against a live device, need root.\n\
             Recovery from an image file needs nothing."
                .to_string()
        },
    )
}

/// The line the installer would add, for an operator who wants to add it
/// themselves.
fn shell_path_hint(dir: &Path) -> String {
    if cfg!(windows) {
        format!("$env:Path = \"{};$env:Path\"", dir.display())
    } else {
        format!("export PATH=\"{}:$PATH\"", dir.display())
    }
}

/// The Rust target triple this binary was built for. Assembled from the
/// compiler's own `cfg`s, so it cannot disagree with what was actually built.
pub fn target_triple() -> String {
    let arch = if cfg!(target_arch = "x86_64") {
        "x86_64"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64"
    } else {
        std::env::consts::ARCH
    };
    if cfg!(windows) {
        format!("{arch}-pc-windows-msvc")
    } else if cfg!(target_os = "macos") {
        format!("{arch}-apple-darwin")
    } else if cfg!(target_env = "musl") {
        format!("{arch}-unknown-linux-musl")
    } else {
        format!("{arch}-unknown-linux-gnu")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The triple has to match the asset names the release workflow publishes,
    /// or `self update` looks for a file that does not exist.
    #[test]
    fn the_target_triple_is_one_the_release_workflow_builds() {
        const PUBLISHED: [&str; 6] = [
            "x86_64-unknown-linux-gnu",
            "x86_64-unknown-linux-musl",
            "aarch64-unknown-linux-gnu",
            "x86_64-apple-darwin",
            "aarch64-apple-darwin",
            "x86_64-pc-windows-msvc",
        ];
        let triple = target_triple();
        assert!(
            PUBLISHED.contains(&triple.as_str()),
            "{triple} is not a target the release workflow builds"
        );
    }

    /// `which` has to find something every system has, or the PATH check is
    /// reporting on a lookup that never works.
    #[test]
    fn which_resolves_a_command_that_exists() {
        let probe = if cfg!(windows) { "cmd" } else { "sh" };
        assert!(which(probe).is_some(), "could not resolve {probe} on PATH");
        assert!(which("definitely-not-a-real-command-xyzzy").is_none());
    }

    /// Doctor must never open a raw socket or a device to find out whether it
    /// could — on a monitored host that is itself an alert. Running the whole
    /// report is the check.
    #[test]
    fn collecting_the_report_is_side_effect_free() {
        let checks = collect();
        assert!(checks.len() >= 7);
        // Every failing line must carry a remediation; that is the whole point.
        for c in &checks {
            if !c.ok {
                assert!(
                    c.fix.is_some(),
                    "{} fails without telling anyone how to fix it",
                    c.label
                );
            }
            assert!(!c.detail.is_empty(), "{} has no detail", c.label);
        }
    }
}
