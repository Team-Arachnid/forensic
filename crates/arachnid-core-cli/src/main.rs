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
