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
