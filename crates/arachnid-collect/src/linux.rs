//! Linux collectors. Everything here is a read of `/proc`, `/sys`, or a config
//! path — no writes, no ioctls, no privileged syscalls.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::{hash_file_opt, KernelModule, PersistenceItem, Session};

/// Distinct file-backed executable mappings from `/proc/<pid>/maps`.
///
/// Unreadable maps (process exited, or not ours and we are unprivileged) yield
/// an empty list rather than an error: a missing module list must not cost us
/// the rest of the process record.
pub fn loaded_modules(pid: u32) -> Option<Vec<String>> {
    let maps = fs::read_to_string(format!("/proc/{pid}/maps")).ok()?;
    let mut set = BTreeSet::new();
    for line in maps.lines() {
        // addr perms offset dev inode pathname
        let mut fields = line.split_whitespace();
        let (_addr, perms) = (fields.next()?, fields.next()?);
        if !perms.contains('x') {
            continue;
        }
        let path = fields.nth(3).unwrap_or("");
        // Anonymous and pseudo-mappings ([heap], [vdso]) are not modules.
        if path.starts_with('/') {
            set.insert(path.to_string());
        }
    }
    Some(set.into_iter().collect())
}

/// Active login sessions, from the utmp database.
///
/// `/var/run/utmp` is a flat array of fixed-size `struct utmp`. The layout is
/// stable ABI on glibc and musl for a given arch, so it is parsed by offset
/// rather than by linking libc's `getutent`, which is not thread-safe and would
/// pull in a dependency for one record type.
pub fn sessions() -> Result<Vec<Session>> {
    const USER_PROCESS: i16 = 7;

    // x86_64/aarch64 glibc + musl layout.
    const RECORD: usize = 384;
    const OFF_TYPE: usize = 0;
    const OFF_PID: usize = 4;
    const OFF_LINE: usize = 8; // 32 bytes
    const OFF_USER: usize = 44; // 32 bytes
    const OFF_HOST: usize = 76; // 256 bytes
    const OFF_TV_SEC: usize = 340;

    let path = ["/var/run/utmp", "/run/utmp"]
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .context("no utmp database found (/var/run/utmp, /run/utmp)")?;
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;

    let cstr = |b: &[u8]| {
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        String::from_utf8_lossy(&b[..end]).trim().to_string()
    };

    let mut out = Vec::new();
    for rec in data.chunks_exact(RECORD) {
        let ut_type = i16::from_ne_bytes([rec[OFF_TYPE], rec[OFF_TYPE + 1]]);
        if ut_type != USER_PROCESS {
            continue;
        }
        let user = cstr(&rec[OFF_USER..OFF_USER + 32]);
        if user.is_empty() {
            continue;
        }
        let host = cstr(&rec[OFF_HOST..OFF_HOST + 256]);
        let secs = i32::from_ne_bytes(rec[OFF_TV_SEC..OFF_TV_SEC + 4].try_into().unwrap());
        let pid = u32::from_ne_bytes(rec[OFF_PID..OFF_PID + 4].try_into().unwrap());

        out.push(Session {
            user,
            terminal: Some(cstr(&rec[OFF_LINE..OFF_LINE + 32])).filter(|s| !s.is_empty()),
            remote_host: Some(host).filter(|s| !s.is_empty()),
            login_time: time::OffsetDateTime::from_unix_timestamp(secs as i64)
                .ok()
                .and_then(|t| {
                    t.format(&time::format_description::well_known::Rfc3339)
                        .ok()
                }),
            session_id: Some(pid.to_string()),
            state: Some("active".into()),
        });
    }
    Ok(out)
}

/// Loaded kernel modules from `/proc/modules`, hashed against their on-disk
/// `.ko` where one is resolvable under `/lib/modules/<release>`.
pub fn kernel_modules() -> Result<Vec<KernelModule>> {
    let text = fs::read_to_string("/proc/modules").context("read /proc/modules")?;
    let release = fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    let mut out = Vec::new();
    for line in text.lines() {
        // name size refcount used_by state offset
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.is_empty() {
            continue;
        }
        let used_by: Vec<String> = f
            .get(3)
            .filter(|s| **s != "-")
            .map(|s| {
                s.trim_end_matches(',')
                    .split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();

        let path = find_module_file(f[0], &release);
        out.push(KernelModule {
            name: f[0].to_string(),
            size: f.get(1).and_then(|s| s.parse().ok()),
            sha256: path.as_deref().and_then(hash_file_opt),
            path: path.map(|p| p.display().to_string()),
            used_by,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Locate a module's `.ko` under `/lib/modules/<release>`. Modules loaded from
/// an unusual path (a real finding) simply resolve to `None`.
fn find_module_file(name: &str, release: &str) -> Option<PathBuf> {
    let root = PathBuf::from("/lib/modules").join(release);
    if !root.is_dir() {
        return None;
    }
    let wanted: Vec<String> = ["ko", "ko.xz", "ko.zst", "ko.gz"]
        .iter()
        // Module names normalise '-' to '_'; filenames may use either.
        .flat_map(|ext| {
            [
                format!("{name}.{ext}"),
                format!("{}.{ext}", name.replace('_', "-")),
            ]
        })
        .collect();

    let mut stack = vec![root];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p
                .file_name()
                .is_some_and(|n| wanted.iter().any(|w| w == &n.to_string_lossy()))
            {
                return Some(p);
            }
        }
    }
    None
}

/// Enumerate persistence locations. Read-only: nothing here is disabled,
/// removed, or rewritten.
pub fn persistence() -> Result<Vec<PersistenceItem>> {
    let mut out = Vec::new();
    systemd_units(&mut out);
    cron(&mut out);
    autostart(&mut out);
    rc_local(&mut out);
    out.sort_by(|a, b| (&a.kind, &a.location, &a.name).cmp(&(&b.kind, &b.location, &b.name)));
    Ok(out)
}

fn systemd_units(out: &mut Vec<PersistenceItem>) {
    // Ordered by precedence: an admin-placed unit in /etc shadows a vendor one.
    for dir in [
        "/etc/systemd/system",
        "/run/systemd/system",
        "/usr/lib/systemd/system",
        "/lib/systemd/system",
        "/etc/systemd/user",
        "/usr/lib/systemd/user",
    ] {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().into_owned();
            if !(name.ends_with(".service") || name.ends_with(".timer")) {
                continue;
            }
            // A unit symlinked into a .wants/ dir is enabled; the file itself is
            // what executes, so record the file.
            let exec = fs::read_to_string(&path).ok().and_then(|t| {
                t.lines()
                    .find(|l| l.trim_start().starts_with("ExecStart="))
                    .map(|l| {
                        l.trim_start()
                            .trim_start_matches("ExecStart=")
                            .trim()
                            .to_string()
                    })
            });
            out.push(PersistenceItem {
                kind: "systemd".into(),
                location: dir.into(),
                name,
                sha256: hash_file_opt(&path),
                value: exec,
            });
        }
    }
}

fn cron(out: &mut Vec<PersistenceItem>) {
    let mut push_file = |kind: &str, path: &Path| {
        let Ok(text) = fs::read_to_string(path) else {
            return;
        };
        let sha = hash_file_opt(path);
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || !line.contains(' ') {
                continue;
            }
            // Skip environment assignments (PATH=, SHELL=, MAILTO=).
            if line
                .split_whitespace()
                .next()
                .is_some_and(|w| w.contains('='))
            {
                continue;
            }
            out.push(PersistenceItem {
                kind: kind.into(),
                location: path.display().to_string(),
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                value: Some(line.to_string()),
                sha256: sha.clone(),
            });
        }
    };

    push_file("cron", Path::new("/etc/crontab"));
    for dir in ["/etc/cron.d", "/var/spool/cron", "/var/spool/cron/crontabs"] {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            if entry.path().is_file() {
                push_file("cron", &entry.path());
            }
        }
    }
    // cron.{hourly,daily,weekly,monthly} hold scripts, not crontab lines.
    for dir in [
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
    ] {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                out.push(PersistenceItem {
                    kind: "cron".into(),
                    location: dir.into(),
                    name: entry.file_name().to_string_lossy().into_owned(),
                    value: None,
                    sha256: hash_file_opt(&path),
                });
            }
        }
    }
}

fn autostart(out: &mut Vec<PersistenceItem>) {
    let mut dirs: Vec<PathBuf> = vec!["/etc/xdg/autostart".into()];
    // Per-user autostart under every real home, not just the invoking user's.
    if let Ok(homes) = fs::read_dir("/home") {
        dirs.extend(homes.flatten().map(|e| e.path().join(".config/autostart")));
    }
    dirs.push("/root/.config/autostart".into());

    for dir in dirs {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_none_or(|e| e != "desktop") {
                continue;
            }
            let exec = fs::read_to_string(&path).ok().and_then(|t| {
                t.lines()
                    .find(|l| l.starts_with("Exec="))
                    .map(|l| l.trim_start_matches("Exec=").trim().to_string())
            });
            out.push(PersistenceItem {
                kind: "autostart".into(),
                location: dir.display().to_string(),
                name: entry.file_name().to_string_lossy().into_owned(),
                value: exec,
                sha256: hash_file_opt(&path),
            });
        }
    }
}

fn rc_local(out: &mut Vec<PersistenceItem>) {
    for p in ["/etc/rc.local", "/etc/rc.d/rc.local"] {
        let path = Path::new(p);
        if path.is_file() {
            out.push(PersistenceItem {
                kind: "rc_local".into(),
                location: p.into(),
                name: "rc.local".into(),
                value: None,
                sha256: hash_file_opt(path),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_maps_include_our_binary() {
        let mods = loaded_modules(std::process::id()).expect("own maps readable");
        assert!(
            mods.iter().all(|m| m.starts_with('/')),
            "non-absolute mapping: {mods:?}"
        );
        assert!(!mods.is_empty());
    }

    #[test]
    fn maps_of_a_dead_pid_are_none_not_an_error() {
        assert!(loaded_modules(u32::MAX).is_none());
    }

    #[test]
    fn kernel_modules_parse() {
        // Containers and minimal kernels legitimately have none; assert shape.
        for m in kernel_modules().unwrap() {
            assert!(!m.name.is_empty());
            assert!(
                !m.used_by.iter().any(|u| u.is_empty()),
                "empty used_by entry in {m:?}"
            );
        }
    }

    #[test]
    fn persistence_entries_are_well_formed() {
        for p in persistence().unwrap() {
            assert!(!p.location.is_empty() && !p.name.is_empty(), "{p:?}");
            assert!(
                matches!(
                    p.kind.as_str(),
                    "systemd" | "cron" | "autostart" | "rc_local"
                ),
                "unexpected kind {}",
                p.kind
            );
        }
    }

    #[test]
    fn sessions_do_not_error_when_utmp_exists() {
        // No assertion on count: a container may have zero interactive sessions.
        if Path::new("/var/run/utmp").exists() || Path::new("/run/utmp").exists() {
            for s in sessions().unwrap() {
                assert!(!s.user.is_empty());
            }
        }
    }
}
