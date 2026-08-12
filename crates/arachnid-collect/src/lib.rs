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

/// The collectors [`collect_all`] runs, in order.
///
/// A front end that shows progress renders this list; the names are the same
/// ones that prefix a [`Collection::warnings`] entry and that
/// [`collect_all_with_progress`] reports.
pub const COLLECTORS: [&str; 5] = [
    "processes",
    "connections",
    "sessions",
    "kernel_modules",
    "persistence",
];

/// Run every collector. Individual failures become warnings, not an aborted run.
pub fn collect_all(opts: Options) -> Collection {
    collect_all_with_progress(opts, &mut |_| {})
}

/// As [`collect_all`], but calls `starting` with each collector's name just
/// before it runs, so an operator UI can show which one is in flight.
///
/// Observation only: the set of collectors, their order and their results are
/// identical to [`collect_all`].
pub fn collect_all_with_progress(opts: Options, starting: &mut dyn FnMut(&str)) -> Collection {
    let mut c = Collection::default();
    let warn = |what: &str, e: anyhow::Error| {
        tracing::warn!(collector = what, error = %e, "collector failed");
        format!("{what}: {e:#}")
    };

    starting("processes");
    match collect_processes(opts) {
        Ok(v) => c.processes = v,
        Err(e) => c.warnings.push(warn("processes", e)),
    }
    starting("connections");
    match collect_connections(&c.processes) {
        Ok(v) => c.connections = v,
        Err(e) => c.warnings.push(warn("connections", e)),
    }
    starting("sessions");
    match sys::sessions() {
        Ok(v) => c.sessions = v,
        Err(e) => c.warnings.push(warn("sessions", e)),
    }
    starting("kernel_modules");
    match sys::kernel_modules() {
        Ok(v) => c.kernel_modules = v,
        Err(e) => c.warnings.push(warn("kernel_modules", e)),
    }
    starting("persistence");
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

/// Acquire physical memory by invoking an external, vetted acquisition tool
/// (AVML on Linux, WinPmem on Windows).
///
/// This tool deliberately ships no kernel-mode memory driver of its own: a custom
/// driver is a kernel attack surface on the very host under investigation, and it
/// would not carry the review history that AVML and WinPmem already have.
///
/// `expected_sha256` is required. The acquisition tool runs with the operator's
/// privilege on a host that may already be compromised, so it is hash-pinned:
/// a swapped binary aborts the run before execution rather than being recorded
/// after the fact.
pub fn acquire_memory(
    tool: &Path,
    expected_sha256: &str,
    output: &Path,
    extra_args: &[String],
) -> Result<MemoryAcquisition> {
    let (actual, _) = arachnid_evidence::sha256_file(tool)
        .with_context(|| format!("hash acquisition tool {}", tool.display()))?;
    if !actual.eq_ignore_ascii_case(expected_sha256.trim()) {
        bail!(
            "acquisition tool hash mismatch for {}: expected {}, found {}. \
             Refusing to execute an unverified tool.",
            tool.display(),
            expected_sha256.trim(),
            actual
        );
    }

    if let Some(parent) = output.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // AVML and WinPmem share the shape `<tool> [args] <output-path>`.
    let mut args: Vec<String> = extra_args.to_vec();
    args.push(output.display().to_string());

    let started_utc = arachnid_evidence::now_utc();
    tracing::info!(tool = %tool.display(), output = %output.display(), "invoking memory acquisition tool");
    let out = Command::new(tool)
        .args(&args)
        .output()
        .with_context(|| format!("execute {}", tool.display()))?;
    let finished_utc = arachnid_evidence::now_utc();

    let stderr = String::from_utf8_lossy(&out.stderr);
    let stderr_tail: String = stderr.lines().rev().take(20).collect::<Vec<_>>().join("\n");

    if !out.status.success() {
        bail!(
            "{} exited with {:?}: {}",
            tool.display(),
            out.status.code(),
            stderr_tail
        );
    }

    Ok(MemoryAcquisition {
        tool: tool.display().to_string(),
        tool_sha256: actual,
        args,
        output_artifact: output
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        started_utc,
        finished_utc,
        exit_code: out.status.code(),
        stderr_tail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn processes_include_this_one() {
        let procs = collect_processes(Options {
            hash_binaries: false,
        })
        .unwrap();
        let me = std::process::id();
        assert!(
            procs.iter().any(|p| p.pid == me),
            "own pid {me} not in process list"
        );
        assert!(
            procs.iter().all(|p| p.parent_pid != Some(p.pid)),
            "process is its own parent"
        );
    }

    #[test]
    fn connections_enumerate_without_privilege() {
        // Ports vary by host, so assert shape rather than content.
        let conns = collect_connections(&[]).unwrap();
        for c in &conns {
            assert!(matches!(
                c.protocol.as_str(),
                "tcp" | "tcp6" | "udp" | "udp6"
            ));
        }
    }

    #[test]
    fn connections_resolve_process_names() {
        let procs = collect_processes(Options {
            hash_binaries: false,
        })
        .unwrap();
        let conns = collect_connections(&procs).unwrap();
        for c in &conns {
            if c.process_name.is_some() {
                assert!(!c.pids.is_empty(), "named connection with no pid");
            }
        }
    }

    #[test]
    fn collect_all_never_panics_and_reports_gaps() {
        let c = collect_all(Options {
            hash_binaries: false,
        });
        assert!(!c.processes.is_empty());
        // Warnings are the contract for a degraded run; they must be readable.
        assert!(c.warnings.iter().all(|w| w.contains(':')));
    }

    /// The progress names a UI renders must be exactly the collectors that run,
    /// in the order they run. Drift here would show an operator a checklist that
    /// does not match the collection.
    #[test]
    fn progress_reports_every_collector_in_order() {
        let mut seen = Vec::new();
        collect_all_with_progress(
            Options {
                hash_binaries: false,
            },
            &mut |name| seen.push(name.to_string()),
        );
        assert_eq!(seen, COLLECTORS);
    }

    #[test]
    fn memory_acquisition_rejects_a_hash_mismatch() {
        let fake = std::env::temp_dir().join(format!("arachnid-fake-tool-{}", std::process::id()));
        std::fs::write(&fake, b"not really avml").unwrap();
        let err = acquire_memory(&fake, &"0".repeat(64), Path::new("/dev/null"), &[]).unwrap_err();
        assert!(format!("{err:#}").contains("hash mismatch"), "{err:#}");
        std::fs::remove_file(&fake).unwrap();
    }

    #[test]
    fn hash_file_opt_tolerates_missing_files() {
        assert!(hash_file_opt(Path::new("/nonexistent/arachnid")).is_none());
    }
}
