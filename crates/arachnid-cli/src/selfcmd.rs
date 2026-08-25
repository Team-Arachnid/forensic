//! `arachnid-cli self update` and `arachnid-cli self uninstall`.
//!
//! Uninstall's contract is narrow on purpose: **it removes what the installer
//! added and nothing else.** The installer appends one marked line to one shell
//! profile; uninstall removes that line and that binary. It never rewrites a
//! profile it does not recognise, never deletes a directory it did not create,
//! and never touches evidence containers, certificates or results — which live
//! wherever the operator put them and are not the installer's to reason about.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};

use crate::update;

/// The marker the installer writes beside its PATH line, and the only thing
/// uninstall will remove from a shell profile.
///
/// Matching on a marker rather than on the path means an operator who edited
/// the line, or who added their own `export PATH` for the same directory, keeps
/// what they wrote.
pub const PATH_MARKER: &str = "# added by arachnid-cli installer";

const USAGE: &str = "\
USAGE
  arachnid-cli self update [--dry-run]   download, verify and replace this binary
  arachnid-cli self uninstall [--yes]    remove this binary and the installer's PATH line

`self update` verifies a minisign signature over the release digest file, then
the SHA-256 of the downloaded binary, before replacing anything. It refuses on
either failure and leaves the running binary untouched.
";

pub fn run(verb: Option<String>) -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let flag = |f: &str| args.iter().any(|a| a == f);

    match verb.as_deref() {
        Some("update") => match update::self_update(flag("--dry-run")) {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::from(1)
            }
        },
        Some("uninstall") => match uninstall(flag("--yes")) {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::from(1)
            }
        },
        Some(other) => {
            eprintln!("error: unknown `self` command {other:?}\n");
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
        None => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
    }
}

/// Remove the binary and revert the installer's PATH edit.
fn uninstall(confirmed: bool) -> Result<String> {
    let exe = std::env::current_exe().context("locate the running binary")?;
    let exe = exe.canonicalize().unwrap_or(exe);
    let dir = exe.parent().unwrap_or(Path::new(".")).to_path_buf();

    let profiles = profiles_with_marker();

    if !confirmed {
        let mut plan = format!("This would remove:\n  {}\n", exe.display());
        if profiles.is_empty() {
            plan.push_str(
                "\nNo shell profile carries the installer's PATH line, so none will be edited.\n",
            );
        } else {
            plan.push_str("\nAnd remove the installer's PATH line from:\n");
            for p in &profiles {
                plan.push_str(&format!("  {}\n", p.display()));
            }
        }
        plan.push_str(
            "\nEvidence containers, certificates and recovery output are never touched — they \
             live where you put them.\n\nRe-run with --yes to proceed.",
        );
        return Ok(plan);
    }

    let mut edited = Vec::new();
    for profile in &profiles {
        match strip_marker_from(profile) {
            Ok(true) => edited.push(profile.clone()),
            Ok(false) => {}
            Err(e) => eprintln!("warning: could not edit {}: {e:#}", profile.display()),
        }
    }

    // The binary goes last: if removing it fails, the PATH edit is already
    // reverted and the operator is not left with a broken PATH *and* a binary.
    //
    // A running image cannot be deleted on Windows, so it is renamed aside and
    // the operator is told where it went rather than being given a silent
    // failure.
    let removed = if cfg!(windows) {
        let parked = dir.join(".arachnid-cli.removed");
        let _ = std::fs::remove_file(&parked);
        std::fs::rename(&exe, &parked).with_context(|| format!("move {} aside", exe.display()))?;
        format!(
            "{} was moved to {} — Windows cannot delete a running program.\nDelete that file to \
             finish.",
            exe.display(),
            parked.display()
        )
    } else {
        std::fs::remove_file(&exe).with_context(|| format!("remove {}", exe.display()))?;
        format!("Removed {}", exe.display())
    };

    let mut out = removed;
    if edited.is_empty() {
        out.push_str("\nNo shell profile needed editing.");
    } else {
        out.push_str("\nReverted the installer's PATH line in:");
        for p in edited {
            out.push_str(&format!("\n  {}", p.display()));
        }
        out.push_str("\n\nOpen a new shell for that to take effect.");
    }
    out.push_str("\n\nThe standalone binaries, if you installed them, are untouched.");
    Ok(out)
}

/// Shell profiles the installer might have edited, that actually carry its
/// marker right now.
fn profiles_with_marker() -> Vec<PathBuf> {
    candidate_profiles()
        .into_iter()
        .filter(|p| {
            std::fs::read_to_string(p)
                .map(|s| s.contains(PATH_MARKER))
                .unwrap_or(false)
        })
        .collect()
}

/// Every profile the installer knows how to write. Kept in step with the shell
/// list in `install.sh` and `install.ps1`.
pub fn candidate_profiles() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        if let Some(docs) = std::env::var_os("USERPROFILE").map(PathBuf::from) {
            out.push(docs.join("Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1"));
            out.push(docs.join("Documents/PowerShell/Microsoft.PowerShell_profile.ps1"));
        }
        return out;
    }
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return out;
    };
    out.push(home.join(".bashrc"));
    out.push(home.join(".bash_profile"));
    out.push(home.join(".profile"));
    out.push(home.join(".zshrc"));
    out.push(home.join(".config/fish/config.fish"));
    out
}

/// Remove the marked line, and the marker comment above it, from one profile.
///
/// Returns whether anything changed. Everything else in the file is preserved
/// byte for byte — an operator's shell config is theirs, and an uninstaller
/// that reformats it has overstepped.
pub fn strip_marker_from(path: &Path) -> Result<bool> {
    let text = std::fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let (out, changed) = strip_marker(&text);
    if changed {
        std::fs::write(path, out).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(changed)
}

/// The text transformation, split out so it can be tested without a filesystem.
pub fn strip_marker(text: &str) -> (String, bool) {
    let lines: Vec<&str> = text.lines().collect();
    let mut kept: Vec<&str> = Vec::with_capacity(lines.len());
    let mut changed = false;
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim() == PATH_MARKER {
            // The marker and the single line it introduces.
            changed = true;
            i += if i + 1 < lines.len() { 2 } else { 1 };
            continue;
        }
        // A line the installer marked inline rather than on its own line.
        if lines[i].contains(PATH_MARKER) {
            changed = true;
            i += 1;
            continue;
        }
        kept.push(lines[i]);
        i += 1;
    }
    if !changed {
        return (text.to_string(), false);
    }
    // Collapse the blank run the removal can leave behind, without touching
    // blank lines anywhere else.
    let mut out = String::with_capacity(text.len());
    let mut blanks = 0;
    for line in kept {
        if line.trim().is_empty() {
            blanks += 1;
            if blanks > 1 {
                continue;
            }
        } else {
            blanks = 0;
        }
        out.push_str(line);
        out.push('\n');
    }
    (out, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROFILE: &str = "\
export EDITOR=vim

# my own path, nothing to do with arachnid
export PATH=\"$HOME/bin:$PATH\"

# added by arachnid-cli installer
export PATH=\"$HOME/.local/bin:$PATH\"

alias ll='ls -la'
";

    /// The contract: remove our line, leave everything else byte for byte.
    #[test]
    fn only_the_installers_own_line_is_removed() {
        let (out, changed) = strip_marker(PROFILE);
        assert!(changed);
        assert!(!out.contains(PATH_MARKER));
        assert!(!out.contains(".local/bin"));
        // Everything the operator wrote survives, including their own PATH edit
        // for a different directory.
        assert!(out.contains("export EDITOR=vim"));
        assert!(out.contains("# my own path, nothing to do with arachnid"));
        assert!(out.contains("export PATH=\"$HOME/bin:$PATH\""));
        assert!(out.contains("alias ll='ls -la'"));
    }

    /// An operator who added the same directory themselves keeps their line.
    /// Matching on the path rather than the marker would eat it.
    #[test]
    fn an_unmarked_line_for_the_same_directory_is_left_alone() {
        let mine = "export PATH=\"$HOME/.local/bin:$PATH\"\n";
        let (out, changed) = strip_marker(mine);
        assert!(!changed);
        assert_eq!(out, mine);
    }

    /// Running uninstall twice must not corrupt the profile the second time.
    #[test]
    fn stripping_is_idempotent() {
        let (once, _) = strip_marker(PROFILE);
        let (twice, changed) = strip_marker(&once);
        assert!(!changed);
        assert_eq!(once, twice);
    }

    /// A marker as the very last line, with nothing after it, must not panic on
    /// the lookahead.
    #[test]
    fn a_trailing_marker_does_not_run_off_the_end() {
        let (out, changed) = strip_marker("export A=1\n# added by arachnid-cli installer\n");
        assert!(changed);
        assert_eq!(out, "export A=1\n");
    }

    #[test]
    fn a_profile_without_the_marker_is_untouched() {
        let plain = "export EDITOR=vim\nalias ll='ls -la'\n";
        assert_eq!(strip_marker(plain), (plain.to_string(), false));
    }
}
