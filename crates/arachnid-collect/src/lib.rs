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

/// Run every collector. Individual failures become warnings, not an aborted run.
pub fn collect_all(opts: Options) -> Collection {
    let mut c = Collection::default();
    let warn = |what: &str, e: anyhow::Error| {
        tracing::warn!(collector = what, error = %e, "collector failed");
        format!("{what}: {e:#}")
    };

    match collect_processes(opts) {
        Ok(v) => c.processes = v,
        Err(e) => c.warnings.push(warn("processes", e)),
    }
    match collect_connections(&c.processes) {
        Ok(v) => c.connections = v,
        Err(e) => c.warnings.push(warn("connections", e)),
    }
    match sys::sessions() {
        Ok(v) => c.sessions = v,
        Err(e) => c.warnings.push(warn("sessions", e)),
    }
    match sys::kernel_modules() {
        Ok(v) => c.kernel_modules = v,
        Err(e) => c.warnings.push(warn("kernel_modules", e)),
    }
    match sys::persistence() {
        Ok(v) => c.persistence = v,
        Err(e) => c.warnings.push(warn("persistence", e)),
    }
    c
}

pub fn collect_processes(opts: Options) -> Result<Vec<Process>> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, Users};

    let mut sysi = System::new();
    sysi.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::everything(),
    );
    let users = Users::new_with_refreshed_list();

    // One image is usually mapped by many processes; hash each path once.
    let mut hashes: std::collections::HashMap<PathBuf, Option<String>> = Default::default();

    let mut out: Vec<Process> = sysi
        .processes()
        .values()
        .map(|p| {
            let exe = p.exe().map(Path::to_path_buf);
            let exe_sha256 = match (opts.hash_binaries, &exe) {
                (true, Some(path)) => hashes
                    .entry(path.clone())
                    .or_insert_with(|| hash_file_opt(path))
                    .clone(),
                _ => None,
            };
            Process {
                pid: p.pid().as_u32(),
                parent_pid: p.parent().map(|p| p.as_u32()),
                name: p.name().to_string_lossy().into_owned(),
                cmdline: p
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect(),
                exe: exe.as_ref().map(|p| p.display().to_string()),
                exe_sha256,
                user: p
                    .user_id()
                    .and_then(|uid| users.get_user_by_id(uid))
                    .map(|u| u.name().to_string()),
                start_time: Some(p.start_time()),
                cwd: p.cwd().map(|p| p.display().to_string()),
                loaded_modules: sys::loaded_modules(p.pid().as_u32()).unwrap_or_default(),
            }
        })
        .collect();

    out.sort_by_key(|p| p.pid);
    Ok(out)
}

/// Open sockets mapped to owning processes. `processes` is used only to attach a
/// readable name to each PID; pass an empty slice to skip that.
pub fn collect_connections(processes: &[Process]) -> Result<Vec<Connection>> {
    use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

    let names: std::collections::HashMap<u32, &str> =
        processes.iter().map(|p| (p.pid, p.name.as_str())).collect();

    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP | ProtocolFlags::UDP,
    )
    .context("enumerate sockets")?;

    let mut out: Vec<Connection> = sockets
        .into_iter()
        .map(|s| {
            let pids = s.associated_pids.clone();
            let process_name = pids
                .iter()
                .find_map(|p| names.get(p).map(|n| n.to_string()));
            match s.protocol_socket_info {
                ProtocolSocketInfo::Tcp(t) => Connection {
                    protocol: if t.local_addr.is_ipv6() {
                        "tcp6"
                    } else {
                        "tcp"
                    }
                    .into(),
                    local_addr: t.local_addr.to_string(),
                    local_port: t.local_port,
                    remote_addr: Some(t.remote_addr.to_string()),
                    remote_port: Some(t.remote_port),
                    state: t.state.to_string(),
                    pids,
                    process_name,
                },
                ProtocolSocketInfo::Udp(u) => Connection {
                    protocol: if u.local_addr.is_ipv6() {
                        "udp6"
                    } else {
                        "udp"
                    }
                    .into(),
                    local_addr: u.local_addr.to_string(),
                    local_port: u.local_port,
                    remote_addr: None,
                    remote_port: None,
                    // UDP is connectionless; netstat2 reports no state for it.
                    state: "STATELESS".into(),
                    pids,
                    process_name,
                },
            }
        })
        .collect();

    out.sort_by(|a, b| (&a.protocol, a.local_port).cmp(&(&b.protocol, b.local_port)));
    Ok(out)
}

/// SHA-256 of a file, or `None` if unreadable or implausibly large.
/// Collectors never fail a run over one unreadable file.
pub(crate) fn hash_file_opt(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_HASH_BYTES {
        return None;
    }
    arachnid_evidence::sha256_file(path).ok().map(|(h, _)| h)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAcquisition {
    pub tool: String,
    pub tool_sha256: String,
    pub args: Vec<String>,
    pub output_artifact: String,
    pub started_utc: String,
    pub finished_utc: String,
    pub exit_code: Option<i32>,
    pub stderr_tail: String,
}
