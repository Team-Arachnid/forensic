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

#[derive(Debug, Serialize)]
pub struct VerifyReport {
    pub container: String,
    pub schema_version: String,
    pub public_key: String,
    pub key_fingerprint: String,
    pub records: u64,
    pub artifacts_checked: u64,
    pub problems: Vec<String>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.problems.is_empty()
    }
}

/// Re-verify a container from disk.
///
/// Deliberately independent of [`Container`]: it re-reads and re-hashes rather
/// than sharing any writer state, so a bug in the collection path cannot make a
/// broken container verify clean.
pub fn verify(root: &Path) -> Result<VerifyReport> {
    let manifest: Manifest = serde_json::from_slice(
        &fs::read(root.join("manifest.json")).context("read manifest.json")?,
    )
    .context("parse manifest.json")?;

    let pk_bytes: [u8; 32] = unhex(&manifest.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public_key is not 32 bytes"))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes).context("malformed public key")?;

    let mut problems = Vec::new();
    let mut expect_prev = GENESIS_PREV.to_string();
    let mut expect_seq = 0u64;
    let mut records = 0u64;
    let mut artifacts_checked = 0u64;
    let mut logged: Vec<String> = Vec::new();

    let f = File::open(root.join("custody.log")).context("read custody.log")?;
    for (i, line) in BufReader::new(f).lines().enumerate() {
        let line = line?;
        let raw = line.as_bytes();
        records += 1;

        let Some(sp) = raw.iter().position(|&b| b == b' ') else {
            problems.push(format!("line {}: malformed, no signature separator", i + 1));
            continue;
        };
        let (sig_hex, body) = (&line[..sp], &raw[sp + 1..]);

        match unhex(sig_hex)
            .ok()
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
        {
            Some(sb) if vk.verify(body, &Signature::from_bytes(&sb)).is_ok() => {}
            _ => problems.push(format!("line {}: signature does not verify", i + 1)),
        }

        let rec: Record = match serde_json::from_slice(body) {
            Ok(r) => r,
            Err(e) => {
                problems.push(format!("line {}: unparseable record: {e}", i + 1));
                continue;
            }
        };
        if rec.seq != expect_seq {
            problems.push(format!(
                "line {}: sequence {} out of order, expected {}",
                i + 1,
                rec.seq,
                expect_seq
            ));
        }
        if rec.prev != expect_prev {
            problems.push(format!(
                "line {}: hash chain broken (record removed, reordered, or edited)",
                i + 1
            ));
        }
        expect_prev = sha256(raw);
        expect_seq = rec.seq + 1;

        if rec.event == "artifact" {
            let Some(name) = rec.name.clone() else {
                problems.push(format!("line {}: artifact record without a name", i + 1));
                continue;
            };
            logged.push(name.clone());
            let Some(want) = rec.sha256.as_deref() else {
                continue; // dry-run placeholder; nothing was written
            };
            let path = root.join("artifacts").join(&name);
            match sha256_file(&path) {
                Ok((got, size)) => {
                    artifacts_checked += 1;
                    if got != want {
                        problems.push(format!(
                            "artifact {name}: content modified since collection"
                        ));
                    }
                    if rec.size.is_some_and(|s| s != size) {
                        problems.push(format!("artifact {name}: size differs from record"));
                    }
                }
                Err(_) => problems.push(format!("artifact {name}: missing")),
            }
        }
    }

    // A file nobody logged is as much a tamper signal as a modified one.
    let adir = root.join("artifacts");
    if adir.is_dir() {
        for entry in walk(&adir)? {
            let rel = entry
                .strip_prefix(&adir)
                .unwrap_or(&entry)
                .to_string_lossy()
                .replace('\\', "/");
            if !logged.contains(&rel) {
                problems.push(format!(
                    "artifact {rel}: present on disk but not in custody log"
                ));
            }
        }
    }

    Ok(VerifyReport {
        container: root.display().to_string(),
        schema_version: manifest.schema_version,
        key_fingerprint: sha256(&pk_bytes),
        public_key: manifest.public_key,
        records,
        artifacts_checked,
        problems,
    })
}

fn walk(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)? {
            let p = entry?.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.push(p);
            }
        }
    }
    Ok(out)
}

/// Load an Ed25519 signing key from a 32-byte seed file (raw or hex).
pub fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let raw = fs::read(path).with_context(|| format!("read signing key {}", path.display()))?;
    let seed: [u8; 32] = if raw.len() == 32 {
        raw.try_into().unwrap()
    } else {
        let text = String::from_utf8(raw).context("signing key is neither 32 raw bytes nor hex")?;
        unhex(text.trim())?
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing key must decode to 32 bytes"))?
    };
    Ok(SigningKey::from_bytes(&seed))
}

pub fn now_utc() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

fn hostname() -> String {
    // Read-only, no libc dependency, works on both target families.
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("arachnid-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    fn populated(tag: &str) -> PathBuf {
        let root = tmpdir(tag);
        let mut c = Container::create(&root, "tester", None, false).unwrap();
        c.add_bytes("a.txt", b"hello").unwrap();
        c.add_json("b.json", &serde_json::json!({"k": 1})).unwrap();
        c.note("collector finished").unwrap();
        c.finish().unwrap();
        root
    }

    #[test]
    fn clean_container_verifies() {
        let root = populated("clean");
        let r = verify(&root).unwrap();
        assert!(r.ok(), "unexpected problems: {:?}", r.problems);
        assert_eq!(r.artifacts_checked, 2);
        assert_eq!(r.records, 5); // run_start, 2 artifacts, note, run_end
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn modified_artifact_is_detected() {
        let root = populated("modify");
        fs::write(root.join("artifacts/a.txt"), b"hellp").unwrap();
        let r = verify(&root).unwrap();
        assert!(
            r.problems.iter().any(|p| p.contains("content modified")),
            "{:?}",
            r.problems
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn deleted_artifact_is_detected() {
        let root = populated("delete");
        fs::remove_file(root.join("artifacts/a.txt")).unwrap();
        let r = verify(&root).unwrap();
        assert!(
            r.problems.iter().any(|p| p.contains("missing")),
            "{:?}",
            r.problems
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn planted_artifact_is_detected() {
        let root = populated("plant");
        fs::write(root.join("artifacts/evil.txt"), b"x").unwrap();
        let r = verify(&root).unwrap();
        assert!(
            r.problems.iter().any(|p| p.contains("not in custody log")),
            "{:?}",
            r.problems
        );
        fs::remove_dir_all(&root).unwrap();
    }
}
