//! Arachnid Core — live triage and network forensics.
//!
//! Part of the Arachnid Forensic suite. For use by authorized analysts on
//! systems they have permission to examine.
//!
//! Every subcommand is read-only against the target system; the only writes go
//! to the evidence container the operator names. See `docs/SOC-ALLOWLISTING.md`
//! for the full list of paths and APIs this binary touches.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use arachnid_collect as collect;
use arachnid_evidence::{Container, VerifyReport};
use arachnid_netcap as netcap;
use arachnid_report::{to_html, to_markdown, Report};
use clap::{Args, Parser, Subcommand, ValueEnum};

/// Exit codes, stable across releases so SOAR playbooks can branch on them.
mod exit {
    /// Everything requested completed.
    pub const OK: u8 = 0;
    /// Runtime failure: I/O, permission, missing device, unusable input.
    pub const ERROR: u8 = 1;
    /// Reserved: clap uses 2 for argument and usage errors.
    pub const _USAGE: u8 = 2;
}
