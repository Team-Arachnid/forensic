//! Windows collectors. Read-only: every call here is a query API or a file read,
//! and the registry is opened with `KEY_READ` only.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use windows::Win32::Foundation::{CloseHandle, MAX_PATH};
use windows::Win32::System::ProcessStatus::{
    EnumDeviceDrivers, EnumProcessModulesEx, GetDeviceDriverFileNameW, GetModuleFileNameExW,
    LIST_MODULES_ALL,
};
use windows::Win32::System::RemoteDesktop::{
    WTSClientName, WTSConnectState, WTSEnumerateSessionsW, WTSFreeMemory,
    WTSQuerySessionInformationW, WTSUserName, WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
};

use crate::{hash_file_opt, KernelModule, PersistenceItem, Session};

fn wide_to_string(buf: &[u16]) -> String {
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

/// Modules loaded into a process image (`EnumProcessModulesEx`).
///
/// Returns `None` when the process cannot be opened: protected processes and
/// cross-session processes are expected failures even for an administrator, and
/// must not cost the caller the rest of the process record.
pub fn loaded_modules(pid: u32) -> Option<Vec<String>> {
    unsafe {
        let handle = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
            false,
            pid,
        )
        .ok()?;

        let mut modules = vec![Default::default(); 1024];
        let mut needed = 0u32;
        let ok = EnumProcessModulesEx(
            handle,
            modules.as_mut_ptr(),
            (std::mem::size_of_val(&modules[..])) as u32,
            &mut needed,
            LIST_MODULES_ALL,
        )
        .is_ok();

        let mut out = BTreeSet::new();
        if ok {
            let count =
                (needed as usize / std::mem::size_of::<*mut std::ffi::c_void>()).min(modules.len());
            let mut name = [0u16; MAX_PATH as usize];
            for &m in &modules[..count] {
                let n = GetModuleFileNameExW(Some(handle), Some(m), &mut name);
                if n > 0 {
                    out.insert(wide_to_string(&name[..n as usize]));
                }
            }
        }
        let _ = CloseHandle(handle);
        Some(out.into_iter().collect())
    }
}

/// Interactive and remote sessions via the Terminal Services API. Covers console,
/// RDP, and disconnected-but-live sessions.
pub fn sessions() -> Result<Vec<Session>> {
    unsafe {
        let mut info: *mut WTS_SESSION_INFOW = std::ptr::null_mut();
        let mut count = 0u32;
        WTSEnumerateSessionsW(Some(WTS_CURRENT_SERVER_HANDLE), 0, 1, &mut info, &mut count)
            .context("WTSEnumerateSessions")?;

        let mut out = Vec::new();
        for s in std::slice::from_raw_parts(info, count as usize) {
            let user = query_session_string(s.SessionId, WTSUserName).unwrap_or_default();
            if user.is_empty() {
                continue; // Services and the listener pseudo-sessions have no user.
            }
            out.push(Session {
                user,
                terminal: Some(s.pWinStationName.to_string().unwrap_or_default())
                    .filter(|t| !t.is_empty()),
                remote_host: query_session_string(s.SessionId, WTSClientName)
                    .filter(|h| !h.is_empty()),
                // WTS exposes no login timestamp on this struct; the analyst gets
                // it from the Security event log, which is a separate artifact.
                login_time: None,
                session_id: Some(s.SessionId.to_string()),
                state: Some(format!("{:?}", s.State)),
            });
        }
        let _ = WTSFreeMemory(info as *mut std::ffi::c_void);
        let _ = WTSConnectState; // documents the state enum used above
        Ok(out)
    }
}

fn query_session_string(
    session: u32,
    class: windows::Win32::System::RemoteDesktop::WTS_INFO_CLASS,
) -> Option<String> {
    unsafe {
        let mut buf = windows::core::PWSTR::null();
        let mut len = 0u32;
        WTSQuerySessionInformationW(
            Some(WTS_CURRENT_SERVER_HANDLE),
            session,
            class,
            &mut buf,
            &mut len,
        )
        .ok()?;
        let s = buf.to_string().ok();
        WTSFreeMemory(buf.as_ptr() as *mut std::ffi::c_void);
        s
    }
}

/// Loaded kernel-mode drivers via `EnumDeviceDrivers`, hashed against their
/// on-disk image where the path resolves.
pub fn kernel_modules() -> Result<Vec<KernelModule>> {
    unsafe {
        let mut needed = 0u32;
        EnumDeviceDrivers(std::ptr::null_mut(), 0, &mut needed)
            .context("EnumDeviceDrivers size")?;

        let count = needed as usize / std::mem::size_of::<*mut std::ffi::c_void>();
        let mut bases: Vec<*mut std::ffi::c_void> = vec![std::ptr::null_mut(); count + 16];
        EnumDeviceDrivers(
            bases.as_mut_ptr(),
            (std::mem::size_of_val(&bases[..])) as u32,
            &mut needed,
        )
        .context("EnumDeviceDrivers")?;
        let count =
            (needed as usize / std::mem::size_of::<*mut std::ffi::c_void>()).min(bases.len());

        let mut out = Vec::new();
        let mut name = [0u16; MAX_PATH as usize];
        for &base in &bases[..count] {
            let n = GetDeviceDriverFileNameW(base, &mut name);
            if n == 0 {
                continue;
            }
            let raw = wide_to_string(&name[..n as usize]);
            let path = resolve_driver_path(&raw);
            out.push(KernelModule {
                name: Path::new(&raw)
                    .file_name()
                    .map(|f| f.to_string_lossy().into_owned())
                    .unwrap_or_else(|| raw.clone()),
                size: path
                    .as_ref()
                    .and_then(|p| fs::metadata(p).ok())
                    .map(|m| m.len()),
                sha256: path.as_deref().and_then(hash_file_opt),
                path: Some(path.map_or(raw, |p| p.display().to_string())),
                used_by: Vec::new(),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }
}

/// `EnumDeviceDrivers` returns NT-namespace paths (`\SystemRoot\...`,
/// `\??\C:\...`). Map them to Win32 paths so the image can be hashed.
fn resolve_driver_path(raw: &str) -> Option<PathBuf> {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let mapped = if let Some(rest) = raw.strip_prefix(r"\SystemRoot\") {
        format!(r"{sysroot}\{rest}")
    } else if let Some(rest) = raw.strip_prefix(r"\??\") {
        rest.to_string()
    } else if let Some(rest) = raw.strip_prefix(r"\Windows\") {
        format!(r"{sysroot}\{rest}")
    } else {
        raw.to_string()
    };
    let p = PathBuf::from(mapped);
    p.is_file().then_some(p)
}

/// Enumerate persistence locations. Read-only: no key is created, deleted, or
/// rewritten, and no scheduled task is registered or removed.
pub fn persistence() -> Result<Vec<PersistenceItem>> {
    let mut out = Vec::new();
    run_keys(&mut out);
    scheduled_tasks(&mut out);
    startup_folders(&mut out);
    out.sort_by(|a, b| (&a.kind, &a.location, &a.name).cmp(&(&b.kind, &b.location, &b.name)));
    Ok(out)
}

fn run_keys(out: &mut Vec<PersistenceItem>) {
    const SUBKEYS: &[&str] = &[
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"Software\Microsoft\Windows\CurrentVersion\RunServices",
        r"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
        r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
        r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    ];

    for (hive_name, hive) in [
        ("HKLM", windows_registry::LOCAL_MACHINE),
        ("HKCU", windows_registry::CURRENT_USER),
    ] {
        for sub in SUBKEYS {
            let Ok(key) = hive.open(sub) else {
                continue; // Absent key is the norm, not an error.
            };
            let Ok(values) = key.values() else { continue };
            for (name, value) in values {
                // A non-string Run value (REG_BINARY, REG_DWORD) is itself worth
                // recording, so describe it rather than dropping the entry.
                let cmd = String::try_from(value.clone()).unwrap_or_else(|_| {
                    format!(
                        "<non-string value: {:?}, {} bytes>",
                        value.ty(),
                        value.len()
                    )
                });
                out.push(PersistenceItem {
                    kind: "registry_run".into(),
                    location: format!(r"{hive_name}\{sub}"),
                    sha256: image_from_command(&cmd).as_deref().and_then(hash_file_opt),
                    name,
                    value: Some(cmd),
                });
            }
        }
    }
}

/// Scheduled tasks, read from the on-disk task store under `System32\Tasks`.
///
// ponytail: reads the task XML files directly instead of driving the Task
// Scheduler COM API. Ceiling: misses a task registered only in the registry
// store with no matching file (a known anti-forensics trick). Upgrade path:
// ITaskService::GetFolder enumeration, or cross-check against
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks.
fn scheduled_tasks(out: &mut Vec<PersistenceItem>) {
    let sysroot = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    let root = PathBuf::from(&sysroot).join(r"System32\Tasks");
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            let command = fs::read_to_string(&path)
                .ok()
                .and_then(|x| xml_tag(&x, "Command"));
            out.push(PersistenceItem {
                kind: "scheduled_task".into(),
                location: dir.display().to_string(),
                name,
                sha256: hash_file_opt(&path),
                value: command,
            });
        }
    }
}

/// Extract one element's text. Task XML is machine-generated and flat here, so a
/// full parser would be a dependency for a single field.
fn xml_tag(xml: &str, tag: &str) -> Option<String> {
    let start = xml.find(&format!("<{tag}>"))? + tag.len() + 2;
    let end = xml[start..].find(&format!("</{tag}>"))?;
    Some(xml[start..start + end].trim().to_string())
}
