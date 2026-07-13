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
