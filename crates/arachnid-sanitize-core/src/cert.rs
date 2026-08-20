//! Erasure certificates: the signed statement that a device was wiped.
//!
//! Same shape as the evidence container's custody log, for the same reason and
//! with the same properties: each certificate is signed with Ed25519 over the
//! exact bytes on the line, and each line carries the SHA-256 of the previous
//! line, so the register is a hash chain. Removing a certificate breaks the
//! chain; editing one breaks its signature.
//!
//! A certificate is only issued for a wipe that completed *and* verified. That
//! rule lives in [`issue`] rather than in the callers, so a caller cannot forget
//! it — see [`Refused`].

use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use anyhow::{Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::device::Device;
use crate::engine::WipeOutcome;
use crate::safety::Clearance;
use crate::verify::VerifyReport;

/// Bumped when the certificate layout changes incompatibly.
pub const SCHEMA_VERSION: &str = "1.0.0";
const GENESIS_PREV: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The signed body of a certificate. Field order is serialization order and is
/// part of the signed bytes; do not reorder without bumping [`SCHEMA_VERSION`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub schema_version: String,
    pub certificate_id: String,
    pub tool: String,
    pub tool_version: String,

    pub device_path: String,
    pub device_model: String,
    pub device_serial: String,
    pub device_size_bytes: u64,
    pub device_bus: String,
    pub device_removable: bool,

    pub method: String,
    /// The claim an auditor reads. States plainly whether a hardware purge ran
    /// or a software overwrite stood in for one.
    pub method_detail: String,
    pub pass_count: u32,
    /// Per pass: the fixed byte, or the seed a random pass was generated from,
    /// so the pattern can be recomputed and re-checked independently.
    pub passes: Vec<String>,

    pub started_utc: String,
    pub finished_utc: String,
    pub duration_secs: f64,
    pub bytes_written: u64,

    pub verification_passed: bool,
    pub verification_samples: u32,
    pub verification_bytes_sampled: u64,
    pub verification_coverage_percent: f64,

    pub operator: String,
    pub host: String,
    pub platform: String,
    /// Recorded when the operator overrode the system-volume block, because an
    /// auditor reading this certificate needs to know that happened.
    pub forced_system_volume: bool,

    pub public_key: String,
    /// SHA-256 of the previous line in the register; zeroes for the first.
    pub prev: String,
}

/// Why a certificate was not issued. Every variant means the device may still
/// hold recoverable data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    WipeIncomplete(String),
    VerificationFailed(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::WipeIncomplete(why) => {
                write!(f, "no certificate: the wipe did not complete ({why})")
            }
            Refused::VerificationFailed(why) => {
                write!(f, "no certificate: verification failed ({why})")
            }
        }
    }
}

impl std::error::Error for Refused {}

/// Build a signed certificate, or refuse.
///
/// The refusal is the point: [`Refused`] is returned for any wipe that did not
/// finish or did not verify, so there is no code path that produces a signed
/// certificate for a device that might still hold data.
pub fn issue(
    clearance: &Clearance,
    outcome: &WipeOutcome,
    verification: &VerifyReport,
    key: &SigningKey,
    prev: &str,
) -> std::result::Result<Certificate, Refused> {
    if !outcome.complete() {
        return Err(Refused::WipeIncomplete(if outcome.dry_run {
            "dry run: nothing was written".into()
        } else if outcome.cancelled {
            "cancelled before completion".into()
        } else if outcome.bad_region_count > 0 {
            format!(
                "{} region(s) could not be written",
                outcome.bad_region_count
            )
        } else {
            format!(
                "{} of {} bytes written",
                outcome.bytes_written, outcome.bytes_total
            )
        }));
    }
    if !verification.passed {
        return Err(Refused::VerificationFailed(
            verification.blocked.clone().unwrap_or_else(|| {
                format!(
                    "{} sampled region(s) mismatched",
                    verification.failures().count()
                )
            }),
        ));
    }

    let d: &Device = clearance.device();
    let mut id = [0u8; 16];
    // A certificate id that collides is a filing problem, not a safety one, so a
    // failed entropy read falls back to the finish timestamp rather than
    // aborting a wipe that has already succeeded.
    let certificate_id = match getrandom::fill(&mut id) {
        Ok(()) => arachnid_evidence::hex(&id),
        Err(_) => arachnid_evidence::sha256(outcome.finished_utc.as_bytes()),
    };

    Ok(Certificate {
        schema_version: SCHEMA_VERSION.into(),
        certificate_id,
        tool: "arachnid-sanitize".into(),
        tool_version: env!("CARGO_PKG_VERSION").into(),

        device_path: d.path.clone(),
        device_model: d.model.clone(),
        device_serial: d.serial.clone(),
        device_size_bytes: d.size_bytes,
        device_bus: d.bus.label().into(),
        device_removable: d.removable,

        method: outcome.method.label().into(),
        method_detail: method_detail(outcome),
        pass_count: outcome.passes.len() as u32,
        passes: outcome
            .passes
            .iter()
            .map(|p| match (&p.pass, &p.seed_hex) {
                (crate::pattern::Pass::Fixed(b), _) => format!("fixed 0x{b:02X}"),
                (crate::pattern::Pass::Random, Some(seed)) => format!("random seed {seed}"),
                (crate::pattern::Pass::Random, None) => "random (seed not recorded)".into(),
            })
            .collect(),

        started_utc: outcome.started_utc.clone(),
        finished_utc: outcome.finished_utc.clone(),
        duration_secs: outcome.duration_secs,
        bytes_written: outcome.bytes_written,

        verification_passed: verification.passed,
        verification_samples: verification.samples.len() as u32,
        verification_bytes_sampled: verification.bytes_sampled,
        verification_coverage_percent: verification.coverage() * 100.0,

        operator: clearance.request().operator.clone(),
        host: hostname(),
        platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        forced_system_volume: clearance.overrode_system_volume,

        public_key: arachnid_evidence::hex(key.verifying_key().as_bytes()),
        prev: prev.to_string(),
    })
}

/// A signing key for this run alone.
///
/// A certificate signed with one can only ever be checked against the
/// fingerprint printed when it was issued, so every front end that calls this
/// has to show that fingerprint rather than log it. Preferred over each front
/// end rolling its own so the CLI and the TUI cannot drift on key handling.
pub fn ephemeral_key() -> Result<SigningKey> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("gather entropy for an ephemeral signing key")?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Hex SHA-256 of a key's public half: the value an operator records
/// out-of-band so a certificate can be trusted later.
pub fn key_fingerprint(key: &SigningKey) -> String {
    arachnid_evidence::sha256(key.verifying_key().as_bytes())
}

/// The sentence an auditor reads to know what standard was actually met.
fn method_detail(outcome: &WipeOutcome) -> String {
    use crate::purge::PurgeOutcome;
    match &outcome.purge_path {
        PurgeOutcome::HardwareCompleted { command } => {
            format!("hardware purge: {command} completed by the device")
        }
        PurgeOutcome::NotAttempted { capability } => {
            if outcome.method.tries_hardware_first() {
                format!(
                    "SOFTWARE OVERWRITE, not a hardware purge — {}. {} pass(es) written and \
                     verified. Assess against NIST 800-88 Clear, not Purge.",
                    capability.describe(),
                    outcome.passes.len()
                )
            } else {
                format!(
                    "software overwrite, {} pass(es), written and verified",
                    outcome.passes.len()
                )
            }
        }
    }
}

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| std::env::var("COMPUTERNAME").ok())
        .or_else(|| std::fs::read_to_string("/proc/sys/kernel/hostname").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

// ---------------------------------------------------------------------------
// The append-only register
// ---------------------------------------------------------------------------

/// SHA-256 of the register's last line, or the genesis value when it is empty.
/// This is the `prev` a new certificate must carry.
pub fn head(path: &Path) -> Result<String> {
    let Ok(file) = std::fs::File::open(path) else {
        return Ok(GENESIS_PREV.to_string());
    };
    let mut last = None;
    for line in BufReader::new(file).lines() {
        let line = line?;
        if !line.trim().is_empty() {
            last = Some(arachnid_evidence::sha256(line.as_bytes()));
        }
    }
    Ok(last.unwrap_or_else(|| GENESIS_PREV.to_string()))
}

/// Sign `cert` and append it to the register at `path`.
///
/// Returns the line's own hash, which becomes the next certificate's `prev`.
pub fn append(path: &Path, cert: &Certificate, key: &SigningKey) -> Result<String> {
    let body = serde_json::to_vec(cert)?;
    let sig = key.sign(&body);
    let mut line = Vec::with_capacity(body.len() + 130);
    line.extend_from_slice(arachnid_evidence::hex(&sig.to_bytes()).as_bytes());
    line.push(b' ');
    line.extend_from_slice(&body);

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open certificate register {}", path.display()))?;
    f.write_all(&line)?;
    f.write_all(b"\n")?;
    // A certificate that does not survive a crash is not a record.
    f.sync_all()?;

    Ok(arachnid_evidence::sha256(&line))
}

/// One register entry's verification result.
#[derive(Debug, Serialize)]
pub struct RegisterCheck {
    pub certificate_id: String,
    pub device_serial: String,
    pub signature_ok: bool,
    pub chain_ok: bool,
}

/// Re-verify a register from disk: every signature, and the hash chain.
///
/// Independent of [`append`] — it re-reads and re-hashes rather than sharing
/// writer state, so a bug in the issuing path cannot make a broken register
/// verify clean.
pub fn verify_register(path: &Path) -> Result<(Vec<RegisterCheck>, Vec<String>)> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("read certificate register {}", path.display()))?;
    let mut checks = Vec::new();
    let mut problems = Vec::new();
    let mut expect_prev = GENESIS_PREV.to_string();

    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let raw = line.as_bytes();
        let Some((sig_hex, body)) = line.split_once(' ') else {
            problems.push(format!("line {}: malformed, no signature separator", i + 1));
            continue;
        };
        let cert: Certificate = match serde_json::from_str(body) {
            Ok(c) => c,
            Err(e) => {
                problems.push(format!("line {}: unparseable certificate: {e}", i + 1));
                continue;
            }
        };

        let signature_ok = arachnid_evidence::unhex(&cert.public_key)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|b| VerifyingKey::from_bytes(&b).ok())
            .zip(
                arachnid_evidence::unhex(sig_hex)
                    .ok()
                    .and_then(|b| <[u8; 64]>::try_from(b).ok()),
            )
            .is_some_and(|(vk, sb)| {
                vk.verify(body.as_bytes(), &Signature::from_bytes(&sb))
                    .is_ok()
            });
        if !signature_ok {
            problems.push(format!("line {}: signature does not verify", i + 1));
        }

        let chain_ok = cert.prev == expect_prev;
        if !chain_ok {
            problems.push(format!(
                "line {}: hash chain broken (a certificate was removed, reordered, or edited)",
                i + 1
            ));
        }
        expect_prev = arachnid_evidence::sha256(raw);

        checks.push(RegisterCheck {
            certificate_id: cert.certificate_id,
            device_serial: cert.device_serial,
            signature_ok,
            chain_ok,
        });
    }
    Ok((checks, problems))
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

/// Human-readable certificate, for an auditor who will not read JSON.
pub fn to_markdown(c: &Certificate) -> String {
    let mut s = String::new();
    s.push_str("# Certificate of Data Erasure\n\n");
    s.push_str(&format!("**Certificate ID:** `{}`\n\n", c.certificate_id));
    s.push_str(&format!(
        "Issued by {} {} on {} ({}).\n\n",
        c.tool, c.tool_version, c.host, c.platform
    ));

    s.push_str("## Device\n\n");
    s.push_str("| Field | Value |\n|---|---|\n");
    s.push_str(&format!("| Model | {} |\n", c.device_model));
    s.push_str(&format!("| Serial number | `{}` |\n", c.device_serial));
    s.push_str(&format!(
        "| Capacity | {} ({} bytes) |\n",
        crate::device::human_bytes(c.device_size_bytes),
        c.device_size_bytes
    ));
    s.push_str(&format!("| Interface | {} |\n", c.device_bus));
    s.push_str(&format!(
        "| Removable | {} |\n",
        if c.device_removable { "yes" } else { "no" }
    ));
    s.push_str(&format!(
        "| OS path at wipe time | `{}` |\n\n",
        c.device_path
    ));

    s.push_str("## Erasure\n\n");
    s.push_str("| Field | Value |\n|---|---|\n");
    s.push_str(&format!("| Method requested | {} |\n", c.method));
    s.push_str(&format!("| What actually ran | {} |\n", c.method_detail));
    s.push_str(&format!("| Passes | {} |\n", c.pass_count));
    s.push_str(&format!("| Started (UTC) | {} |\n", c.started_utc));
    s.push_str(&format!("| Finished (UTC) | {} |\n", c.finished_utc));
    s.push_str(&format!("| Duration | {:.1} s |\n", c.duration_secs));
    s.push_str(&format!(
        "| Bytes written | {} |\n\n",
        crate::device::human_bytes(c.bytes_written)
    ));

    s.push_str("### Pass sequence\n\n");
    for (i, p) in c.passes.iter().enumerate() {
        s.push_str(&format!("{}. {}\n", i + 1, p));
    }
    s.push_str(
        "\nA random pass is generated from the seed recorded above, so its content can be \
         recomputed and independently re-checked at any offset.\n\n",
    );

    s.push_str("## Verification\n\n");
    s.push_str(&format!(
        "**{}** — {} region(s) sampled, {} read back ({:.4}% of the device), every sampled byte \
         matched the expected pattern.\n\n",
        if c.verification_passed {
            "PASSED"
        } else {
            "FAILED"
        },
        c.verification_samples,
        crate::device::human_bytes(c.verification_bytes_sampled),
        c.verification_coverage_percent
    ));

    if c.forced_system_volume {
        s.push_str(
            "> **Note:** this device was identified as hosting the running operating system. \
             The operator explicitly overrode that block.\n\n",
        );
    }

    s.push_str("## Attestation\n\n");
    s.push_str(&format!("**Operator:** {}\n\n", c.operator));
    s.push_str(&format!(
        "**Signing key (Ed25519):** `{}`\n\n",
        c.public_key
    ));
    s.push_str(&format!("**Previous register entry:** `{}`\n\n", c.prev));
    s.push_str(
        "This certificate is signed and chained into an append-only register. Verify it with \
         `arachnid-sanitize verify-cert`. The signature proves the certificate has not been \
         altered; it proves origin only against a key fingerprint recorded out of band.\n",
    );
    s
}

/// Standalone HTML, for printing or filing. No external assets: an auditor
/// opening this in five years should not depend on a CDN still existing.
pub fn to_html(c: &Certificate) -> String {
    let body = to_markdown(c);
    let mut html = String::from(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <title>Certificate of Data Erasure</title>\n<style>\n\
         body{font-family:system-ui,-apple-system,Segoe UI,sans-serif;max-width:52rem;\
         margin:3rem auto;padding:0 1.5rem;line-height:1.6;color:#111}\n\
         h1{border-bottom:3px solid #111;padding-bottom:.4rem}\n\
         table{border-collapse:collapse;width:100%;margin:1rem 0}\n\
         td,th{border:1px solid #ccc;padding:.45rem .7rem;text-align:left}\n\
         th{background:#f4f4f4}\n\
         code{background:#f4f4f4;padding:.1rem .3rem;border-radius:3px;word-break:break-all}\n\
         blockquote{border-left:4px solid #b00;background:#fff4f4;margin:1rem 0;padding:.6rem 1rem}\n\
         </style>\n</head>\n<body>\n",
    );
    // Minimal markdown-to-HTML: this document's own subset, nothing more. A
    // markdown crate would be a dependency for one page of known shape.
    let mut in_table = false;
    for line in body.lines() {
        let t = line.trim();
        if t.starts_with("|---") {
            continue;
        }
        if t.starts_with('|') {
            if !in_table {
                html.push_str("<table>\n");
                in_table = true;
            }
            let cells: Vec<&str> = t.trim_matches('|').split('|').map(str::trim).collect();
            html.push_str("<tr>");
            for c in cells {
                html.push_str(&format!("<td>{}</td>", inline(c)));
            }
            html.push_str("</tr>\n");
            continue;
        }
        if in_table {
            html.push_str("</table>\n");
            in_table = false;
        }
        if let Some(h) = t.strip_prefix("### ") {
            html.push_str(&format!("<h3>{}</h3>\n", inline(h)));
        } else if let Some(h) = t.strip_prefix("## ") {
            html.push_str(&format!("<h2>{}</h2>\n", inline(h)));
        } else if let Some(h) = t.strip_prefix("# ") {
            html.push_str(&format!("<h1>{}</h1>\n", inline(h)));
        } else if let Some(q) = t.strip_prefix("> ") {
            html.push_str(&format!("<blockquote>{}</blockquote>\n", inline(q)));
        } else if !t.is_empty() {
            html.push_str(&format!("<p>{}</p>\n", inline(t)));
        }
    }
    if in_table {
        html.push_str("</table>\n");
    }
    html.push_str("</body>\n</html>\n");
    html
}

/// Escape HTML, then apply the two inline markers this document uses.
fn inline(s: &str) -> String {
    let escaped = s
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    // Pairs only: an odd marker is left as a literal rather than opening a tag
    // that never closes.
    let mut out = escaped;
    for (marker, open, close) in [("**", "<strong>", "</strong>"), ("`", "<code>", "</code>")] {
        if out.matches(marker).count() % 2 != 0 {
            continue;
        }
        let mut result = String::with_capacity(out.len());
        let mut open_next = true;
        let mut rest = out.as_str();
        while let Some(i) = rest.find(marker) {
            result.push_str(&rest[..i]);
            result.push_str(if open_next { open } else { close });
            open_next = !open_next;
            rest = &rest[i + marker.len()..];
        }
        result.push_str(rest);
        out = result;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{BusType, Device};
    use crate::engine::{self, Progress};
    use crate::pattern::WipeMethod;
    use crate::safety::{authorize, WipeRequest};
    use crate::target::{FileBackedTarget, WipeTarget};
    use crate::verify::{self, VerifyOptions};
    use std::sync::atomic::AtomicBool;
    use tempfile::tempdir;

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[42u8; 32])
    }

    fn device(size: u64) -> Device {
        Device {
            path: "/dev/virtual".into(),
            model: "VIRTUAL DISK".into(),
            serial: "VIRT-0001".into(),
            size_bytes: size,
            bus: BusType::Sata,
            removable: false,
            is_system: false,
            system_reason: None,
        }
    }

    fn run(
        method: WipeMethod,
        dry_run: bool,
        tamper: bool,
    ) -> (Clearance, WipeOutcome, VerifyReport) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = 500_000u64;
        let mut t = FileBackedTarget::create(&path, size).unwrap();
        let d = device(size);
        let c = authorize(
            WipeRequest {
                device: d.clone(),
                method,
                typed_serial: d.serial.clone(),
                force_system_volume: false,
                dry_run,
                operator: "analyst@lab".into(),
            },
            Some(&d),
        )
        .unwrap();
        let outcome =
            engine::wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(false)).unwrap();
        if tamper {
            t.write_at(2048, b"STILL HERE").unwrap();
            t.flush().unwrap();
        }
        let opts = VerifyOptions {
            head_bytes: 4096,
            tail_bytes: 4096,
            samples: 4,
            sample_bytes: 512,
        };
        let report = verify::verify(&mut t, &outcome, &opts).unwrap();
        (c, outcome, report)
    }

    #[test]
    fn a_clean_wipe_is_certified() {
        let (c, o, v) = run(WipeMethod::Dod3Pass, false, false);
        let cert = issue(&c, &o, &v, &key(), GENESIS_PREV).expect("should issue");
        assert_eq!(cert.device_serial, "VIRT-0001");
        assert_eq!(cert.pass_count, 3);
        assert!(cert.verification_passed);
        assert!(!cert.forced_system_volume);
    }

    #[test]
    fn a_failed_verification_blocks_the_certificate() {
        let (c, o, v) = run(WipeMethod::NistClear, false, true);
        assert!(matches!(
            issue(&c, &o, &v, &key(), GENESIS_PREV),
            Err(Refused::VerificationFailed(_))
        ));
    }

    #[test]
    fn a_dry_run_blocks_the_certificate() {
        let (c, o, v) = run(WipeMethod::NistClear, true, false);
        assert!(matches!(
            issue(&c, &o, &v, &key(), GENESIS_PREV),
            Err(Refused::WipeIncomplete(_))
        ));
    }

    /// A Purge that fell back to software must say so on the certificate, in
    /// terms an auditor cannot misread as a hardware purge.
    #[test]
    fn a_software_fallback_is_stated_on_the_certificate() {
        let (c, o, v) = run(WipeMethod::NistPurge, false, false);
        let cert = issue(&c, &o, &v, &key(), GENESIS_PREV).unwrap();
        assert!(
            cert.method_detail.contains("SOFTWARE OVERWRITE"),
            "detail was: {}",
            cert.method_detail
        );
        assert!(cert.method_detail.contains("not Purge"));
    }

    #[test]
    fn the_register_chains_and_verifies() {
        let dir = tempdir().unwrap();
        let reg = dir.path().join("certificates.log");
        let k = key();

        let mut prev = head(&reg).unwrap();
        assert_eq!(prev, GENESIS_PREV);
        for _ in 0..3 {
            let (c, o, v) = run(WipeMethod::NistClear, false, false);
            let cert = issue(&c, &o, &v, &k, &prev).unwrap();
            prev = append(&reg, &cert, &k).unwrap();
        }

        let (checks, problems) = verify_register(&reg).unwrap();
        assert_eq!(checks.len(), 3);
        assert!(problems.is_empty(), "{problems:?}");
        assert!(checks.iter().all(|c| c.signature_ok && c.chain_ok));
    }

    #[test]
    fn editing_a_certificate_breaks_its_signature() {
        let dir = tempdir().unwrap();
        let reg = dir.path().join("certificates.log");
        let k = key();
        let (c, o, v) = run(WipeMethod::NistClear, false, false);
        let cert = issue(&c, &o, &v, &k, GENESIS_PREV).unwrap();
        append(&reg, &cert, &k).unwrap();

        let text = std::fs::read_to_string(&reg).unwrap();
        std::fs::write(&reg, text.replace("VIRT-0001", "VIRT-9999")).unwrap();

        let (_, problems) = verify_register(&reg).unwrap();
        assert!(
            problems.iter().any(|p| p.contains("signature")),
            "{problems:?}"
        );
    }

    #[test]
    fn removing_a_certificate_breaks_the_chain() {
        let dir = tempdir().unwrap();
        let reg = dir.path().join("certificates.log");
        let k = key();
        let mut prev = GENESIS_PREV.to_string();
        for _ in 0..3 {
            let (c, o, v) = run(WipeMethod::NistClear, false, false);
            let cert = issue(&c, &o, &v, &k, &prev).unwrap();
            prev = append(&reg, &cert, &k).unwrap();
        }
        let text = std::fs::read_to_string(&reg).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&reg, kept.join("\n") + "\n").unwrap();

        let (_, problems) = verify_register(&reg).unwrap();
        assert!(
            problems.iter().any(|p| p.contains("hash chain broken")),
            "{problems:?}"
        );
    }

    #[test]
    fn html_escapes_and_renders() {
        let (c, o, v) = run(WipeMethod::NistClear, false, false);
        let mut cert = issue(&c, &o, &v, &key(), GENESIS_PREV).unwrap();
        cert.operator = "<script>alert(1)</script>".into();
        let html = to_html(&cert);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("<h1>Certificate of Data Erasure</h1>"));
    }
}
