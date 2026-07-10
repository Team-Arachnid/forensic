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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String,
    pub pids: Vec<u32>,
    /// Resolved from `pids` against the process table for analyst readability.
    pub process_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub user: String,
    pub terminal: Option<String>,
    pub remote_host: Option<String>,
    pub login_time: Option<String>,
    pub session_id: Option<String>,
    pub state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModule {
    pub name: String,
    pub size: Option<u64>,
    pub path: Option<String>,
    pub sha256: Option<String>,
    /// Linux: modules that depend on this one. Windows: unused.
    pub used_by: Vec<String>,
}

/// One enumerated persistence location. Recorded, never modified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceItem {
    /// `registry_run` | `scheduled_task` | `systemd` | `cron` | `launch_agent` | `autostart` | `rc_local`
    pub kind: String,
    /// Registry key, unit path, crontab path — where the entry lives.
    pub location: String,
    pub name: String,
    /// Command or target the entry executes, where one is parseable.
    pub value: Option<String>,
    /// SHA-256 of the file backing the entry, where resolvable.
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Collection {
    pub processes: Vec<Process>,
    pub connections: Vec<Connection>,
    pub sessions: Vec<Session>,
    pub kernel_modules: Vec<KernelModule>,
    pub persistence: Vec<PersistenceItem>,
    /// What could not be collected, and why. Absence of evidence is evidence.
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Hash on-disk process binaries. Costs I/O proportional to distinct images.
    pub hash_binaries: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            hash_binaries: true,
        }
    }
}
