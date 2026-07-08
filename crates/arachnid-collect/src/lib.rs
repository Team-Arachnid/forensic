//! Read-only volatile data collectors.
//!
//! Hard rule for everything in this crate: **no writes to the target system.**
//! Collectors open files and OS query APIs for reading and nothing else. The only
//! path that writes is [`acquire_memory`], and it writes solely into the evidence
//! container directory the operator named.
//!
//! Collectors degrade rather than abort. A host where `/proc/<pid>/maps` is
//! unreadable, or where the operator lacks the privilege for one query, still
//! yields evidence for everything else; the gap is recorded in
//! [`Collection::warnings`] so the analyst sees what was *not* obtained.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as sys;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as sys;

#[cfg(not(any(target_os = "linux", windows)))]
mod unsupported;
#[cfg(not(any(target_os = "linux", windows)))]
use unsupported as sys;

/// Binaries larger than this are recorded without a hash. Nothing legitimate on a
/// persistence path is this big, and a hostile 40 GiB file should not stall triage.
const MAX_HASH_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Process {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name: String,
    /// Full argv, joined for readability but collected as a list.
    pub cmdline: Vec<String>,
    pub exe: Option<String>,
    /// SHA-256 of the on-disk binary, where the path resolves and is readable.
    pub exe_sha256: Option<String>,
    pub user: Option<String>,
    /// Seconds since the Unix epoch.
    pub start_time: Option<u64>,
    pub cwd: Option<String>,
    /// Distinct file-backed executable mappings: shared libraries and injected images.
    pub loaded_modules: Vec<String>,
}
