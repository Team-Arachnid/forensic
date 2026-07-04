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
