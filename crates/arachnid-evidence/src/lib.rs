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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub schema_version: String,
    pub tool: String,
    pub tool_version: String,
    pub container_id: String,
    pub created_utc: String,
    pub operator: String,
    pub host: String,
    pub platform: String,
    /// Ed25519 verifying key, hex. Trust this out-of-band: an attacker who can
    /// rewrite the container can also swap this key and re-sign. Record the
    /// fingerprint printed at the end of the run.
    pub public_key: String,
}

/// An open container. Writes are suppressed in `dry_run`, but hashing and the
/// custody chain still run, so a dry run exercises the same code path.
pub struct Container {
    root: PathBuf,
    key: SigningKey,
    operator: String,
    seq: u64,
    prev: String,
    started: Instant,
    dry_run: bool,
    manifest: Manifest,
}

impl Container {
    /// Create a new container. `signing_key` is an existing operator key, or
    /// `None` to generate an ephemeral one for this run.
    pub fn create(
        root: &Path,
        operator: &str,
        signing_key: Option<SigningKey>,
        dry_run: bool,
    ) -> Result<Self> {
        let key = match signing_key {
            Some(k) => k,
            None => {
                let mut seed = [0u8; 32];
                getrandom::fill(&mut seed).context("gather entropy for signing key")?;
                SigningKey::from_bytes(&seed)
            }
        };
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).context("gather entropy for container id")?;

        let manifest = Manifest {
            schema_version: SCHEMA_VERSION.into(),
            tool: "arachnid-core".into(),
            tool_version: env!("CARGO_PKG_VERSION").into(),
            container_id: hex(&id),
            created_utc: now_utc(),
            operator: operator.into(),
            host: hostname(),
            platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
            public_key: hex(key.verifying_key().as_bytes()),
        };

        if !dry_run {
            fs::create_dir_all(root.join("artifacts"))
                .with_context(|| format!("create container at {}", root.display()))?;
            if root.join("custody.log").exists() {
                bail!(
                    "{} already contains a custody log; refusing to append to an existing container",
                    root.display()
                );
            }
            fs::write(
                root.join("manifest.json"),
                serde_json::to_vec_pretty(&manifest)?,
            )?;
        }

        let mut c = Container {
            root: root.to_path_buf(),
            key,
            operator: operator.into(),
            seq: 0,
            prev: GENESIS_PREV.into(),
            started: Instant::now(),
            dry_run,
            manifest,
        };
        let mhash = sha256(&serde_json::to_vec_pretty(&c.manifest)?);
        c.append("run_start", Some("manifest.json"), Some(mhash), None, None)?;
        Ok(c)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Hex SHA-256 of the public key: the value an operator records out-of-band
    /// so the container can be trusted later.
    pub fn key_fingerprint(&self) -> String {
        sha256(self.key.verifying_key().as_bytes())
    }

    /// Where an artifact must be written for [`Container::seal`] to pick it up.
    /// Used by collectors that hand a path to an external writer (pcap, AVML).
    pub fn artifact_path(&self, name: &str) -> PathBuf {
        self.root.join("artifacts").join(name)
    }

    /// Write `bytes` as an artifact and record its digest.
    pub fn add_bytes(&mut self, name: &str, bytes: &[u8]) -> Result<String> {
        let digest = sha256(bytes);
        if !self.dry_run {
            let path = self.artifact_path(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, bytes).with_context(|| format!("write {}", path.display()))?;
        }
        self.append(
            "artifact",
            Some(name),
            Some(digest.clone()),
            Some(bytes.len() as u64),
            None,
        )?;
        Ok(digest)
    }

    /// Serialize `value` as pretty JSON and store it as an artifact.
    pub fn add_json<T: Serialize>(&mut self, name: &str, value: &T) -> Result<String> {
        let bytes = serde_json::to_vec_pretty(value)?;
        self.add_bytes(name, &bytes)
    }

    /// Record an artifact that was already written to [`Container::artifact_path`]
    /// by something else (packet capture, memory acquisition subprocess).
    pub fn seal(&mut self, name: &str) -> Result<String> {
        if self.dry_run {
            self.append("artifact", Some(name), None, None, Some("dry-run".into()))?;
            return Ok(String::new());
        }
        let (digest, size) = sha256_file(&self.artifact_path(name))?;
        self.append(
            "artifact",
            Some(name),
            Some(digest.clone()),
            Some(size),
            None,
        )?;
        Ok(digest)
    }

    /// Record something that happened but produced no artifact.
    pub fn note(&mut self, detail: impl Into<String>) -> Result<()> {
        self.append("note", None, None, None, Some(detail.into()))
    }

    /// Close the run. Consumes the container so nothing can be appended after.
    pub fn finish(mut self) -> Result<()> {
        self.append("run_end", None, None, None, None)?;
        Ok(())
    }

    fn append(
        &mut self,
        event: &str,
        name: Option<&str>,
        digest: Option<String>,
        size: Option<u64>,
        detail: Option<String>,
    ) -> Result<()> {
        let rec = Record {
            seq: self.seq,
            ts_utc: now_utc(),
            mono_ns: self.started.elapsed().as_nanos(),
            operator: self.operator.clone(),
            event: event.into(),
            name: name.map(String::from),
            sha256: digest,
            size,
            detail,
            prev: self.prev.clone(),
        };
        let body = serde_json::to_vec(&rec)?;
        let sig = self.key.sign(&body);
        let mut line = Vec::with_capacity(body.len() + 130);
        line.extend_from_slice(hex(&sig.to_bytes()).as_bytes());
        line.push(b' ');
        line.extend_from_slice(&body);

        if !self.dry_run {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.root.join("custody.log"))?;
            f.write_all(&line)?;
            f.write_all(b"\n")?;
            // Custody entries must survive a crash mid-collection.
            f.sync_all()?;
        }
        self.prev = sha256(&line);
        self.seq += 1;
        tracing::debug!(seq = rec.seq, event, name, "custody record");
        Ok(())
    }
}
