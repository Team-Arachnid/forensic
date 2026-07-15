//! Fallback for platforms without a dedicated collector module (macOS is a
//! stretch goal, not a blocker).
//!
//! `sysinfo` and `netstat2` still deliver processes and network state here; the
//! host-specific collectors report a gap rather than silently returning empty
//! lists, so an analyst is never shown "no persistence entries" when the truth
//! is "nobody looked".

use anyhow::{bail, Result};

use crate::{KernelModule, PersistenceItem, Session};

pub fn loaded_modules(_pid: u32) -> Option<Vec<String>> {
    None
}

pub fn sessions() -> Result<Vec<Session>> {
    bail!(
        "session enumeration is not implemented on {}",
        std::env::consts::OS
    )
}

pub fn kernel_modules() -> Result<Vec<KernelModule>> {
    bail!(
        "kernel module enumeration is not implemented on {}",
        std::env::consts::OS
    )
}

pub fn persistence() -> Result<Vec<PersistenceItem>> {
    bail!(
        "persistence enumeration is not implemented on {}",
        std::env::consts::OS
    )
}
