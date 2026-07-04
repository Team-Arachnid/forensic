//! Evidence container: tamper-evident storage for a single collection run.
//!
//! Layout on disk:
//!
//! ```text
//! <container>/
//!   manifest.json   run metadata + Ed25519 public key
//!   custody.log     append-only, one signed record per line: "<sig-hex> <record-json>"
//!   artifacts/      the collected data
//! ```
//!
//! Each custody record carries `prev`, the SHA-256 of the *previous line's exact
//! bytes*, so the log is a hash chain: removing or reordering a record breaks it.
//! Each line is individually signed, so editing one breaks that line's signature.
//! Artifacts are hashed at the moment of collection, so editing an artifact after
//! the fact breaks the recorded digest. See [`verify`].
//!
//! Signing is over the raw bytes that follow the first space on the line. Nothing
//! is ever re-serialized during verification, so canonicalization is a non-issue.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// Bumped when the on-disk container layout changes incompatibly.
pub const SCHEMA_VERSION: &str = "1.0.0";
const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("odd-length hex string");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("bad hex digit"))
        .collect()
}

pub fn sha256(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Streaming hash, so a multi-gigabyte memory image never lands in RAM.
pub fn sha256_file(path: &Path) -> Result<(String, u64)> {
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((hex(&hasher.finalize()), total))
}

/// One line of the chain-of-custody log.
///
/// Field order is the serialization order and is part of the signed bytes; do not
/// reorder without bumping [`SCHEMA_VERSION`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Record {
    pub seq: u64,
    /// Wall clock, RFC 3339 UTC. Subject to clock adjustment; pair with `mono_ns`.
    pub ts_utc: String,
    /// Nanoseconds since container creation, from a monotonic clock. Immune to
    /// wall-clock adjustment, so relative ordering survives an NTP step.
    pub mono_ns: u128,
    pub operator: String,
    /// `run_start` | `artifact` | `note` | `run_end`
    pub event: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// SHA-256 of the previous log line's exact bytes; zeroes for the first record.
    pub prev: String,
}
