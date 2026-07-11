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
