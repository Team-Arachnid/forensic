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
