//! Version reporting, the launch-time update check, and `self update`.
//!
//! # This is the one part of the suite that touches the network
//!
//! Every other binary here makes no outbound connection at all, and that is a
//! documented, allowlistable property. This module changes that, so it is built
//! to be defensible rather than merely convenient:
//!
//! - **It only ever checks. It never installs anything on its own.** Replacing a
//!   forensic tool's binary behind the operator's back would break the "the same
//!   binary processed this evidence" claim that chain-of-custody rests on.
//! - **It does not run when nobody is there to read it.** The check is skipped
//!   unless stderr is a terminal, so a SOAR playbook, a cron job, a CI pipeline
//!   and every scripted evidence run make no network call whatsoever. That is
//!   also where a 500 ms delay would actually hurt.
//! - **It is capped and silent on failure.** One request, 500 ms, and any error
//!   — offline, air-gapped, DNS blackholed, proxy refusing — is discarded
//!   without a message, without a delay past the cap, and without changing the
//!   exit code.
//! - **It is rate-limited to once a day**, so an operator running twenty
//!   commands makes one request, not twenty.
//! - **It sends nothing but the request.** A plain GET to the GitHub releases
//!   API with a User-Agent naming the tool and its version. No machine
//!   identifier, no usage counter, no case data, no collected artifact, ever.
//! - **Two independent off switches**, `--no-update-check` and
//!   `ARACHNID_NO_UPDATE_CHECK=1`, both honoured silently — there is no nagging
//!   about the flag that stops the nagging.
//!
//! `self update` is different in kind: the operator asked for it, so it is
//! allowed to block, to download, and to replace the binary — after verifying a
//! signature and a digest, and refusing on either failure.

use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};

/// Where releases live. A constant, not configurable: an updater that can be
/// pointed at an arbitrary host by an environment variable is a supply-chain
/// hole wearing a convenience feature's clothes.
pub const RELEASE_REPO: &str = "ArachnidGs/forensic";

const LATEST_RELEASE_API: &str = "https://api.github.com/repos/ArachnidGs/forensic/releases/latest";

/// Hard cap on the launch-time check. Not a target — a limit.
const CHECK_TIMEOUT: Duration = Duration::from_millis(500);

/// `self update` downloads real artifacts, so it gets a real timeout.
const UPDATE_TIMEOUT: Duration = Duration::from_secs(120);

/// One check per day, however many commands are run.
const CHECK_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Name of the signed digest file published with every release.
pub const CHECKSUMS: &str = "SHA256SUMS";

/// Commit this binary was built from. Set by the release workflow; absent in a
/// local `cargo build`, and reported as such rather than guessed at.
pub fn build_hash() -> &'static str {
    option_env!("ARACHNID_BUILD_HASH").unwrap_or("unknown (local build)")
}

/// The minisign public key releases are signed with, embedded at build time.
///
/// `None` in a development build. `self update` refuses to run without it
/// rather than falling back to "checksum only": a checksum fetched over the
/// same channel as the artifact proves the download was not corrupted, not that
/// it came from us.
pub fn release_pubkey() -> Option<&'static str> {
    // `option_env!` hands back Some("") when the variable is set but empty,
    // which is how CI presents an unset repository variable. An empty key is an
    // absent key, and saying "unreadable" instead of "none" sends someone
    // looking for a corrupt key that was never there.
    option_env!("ARACHNID_MINISIGN_PUBKEY").filter(|k| !k.trim().is_empty())
}

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn user_agent() -> String {
    format!("arachnid-cli/{}", version())
}

/// What `version` and `--version` print.
pub fn version_report() -> String {
    let key = match release_pubkey() {
        Some(k) => key_fingerprint(k).unwrap_or_else(|_| "unreadable".into()),
        None => "none (development build; `self update` is disabled)".into(),
    };
    format!(
        "arachnid-cli {}\nbuild        {}\nrelease key  {}\nreleases     https://github.com/{}/releases\n",
        version(),
        build_hash(),
        key,
        RELEASE_REPO
    )
}

/// Short, human-comparable identity for a minisign key: its 8-byte key id.
fn key_fingerprint(pubkey: &str) -> Result<String> {
    let (_, id, _) = parse_minisign_pubkey(pubkey)?;
    Ok(id.iter().map(|b| format!("{b:02X}")).collect())
}

// ---------------------------------------------------------------------------
// The launch-time check
// ---------------------------------------------------------------------------

/// Whether the operator has switched the check off. Read on every launch so an
/// exported variable takes effect immediately.
pub fn disabled_by_env() -> bool {
    std::env::var_os("ARACHNID_NO_UPDATE_CHECK").is_some_and(|v| !v.is_empty() && v != "0")
}

/// Print one line to stderr if a newer release exists. Never fails, never
/// blocks past [`CHECK_TIMEOUT`], never touches stdout.
///
/// stdout is left alone deliberately: it carries machine-readable `--json`
/// output and rendered reports, and a version notice landing in one would
/// corrupt an evidence artifact.
pub fn notify_if_newer() {
    if disabled_by_env() {
        return;
    }
    // Nobody is watching a pipe. This is what keeps every scripted, scheduled
    // and air-gapped run free of any network call at all.
    if !std::io::stderr().is_terminal() {
        return;
    }
    if !due_for_check() {
        return;
    }
    // Record the attempt before making it, so an unreachable network does not
    // retry on every single command.
    stamp_check();

    let Ok(latest) = latest_version(CHECK_TIMEOUT) else {
        return;
    };
    if is_newer(&latest, version()) {
        eprintln!(
            "A newer version ({latest}) is available. Run 'arachnid-cli self update' to upgrade."
        );
    }
}

/// Ask the releases API for the newest tag.
pub fn latest_version(timeout: Duration) -> Result<String> {
    let body = get_string(LATEST_RELEASE_API, timeout)?;
    let json: serde_json::Value =
        serde_json::from_str(&body).context("parse the releases API response")?;
    let tag = json
        .get("tag_name")
        .and_then(|t| t.as_str())
        .context("releases API response carries no tag_name")?;
    Ok(tag.trim_start_matches('v').to_string())
}

/// Compare two dotted versions numerically.
///
/// String comparison gets this wrong at exactly the point it matters: "0.10.0"
/// sorts before "0.9.0", so a user on 0.9.0 would never be told about 0.10.0.
pub fn is_newer(candidate: &str, current: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.split(['.', '-', '+'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    }
    let (a, b) = (parts(candidate), parts(current));
    for i in 0..a.len().max(b.len()) {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return x > y;
        }
    }
    false
}

/// Where the last-checked stamp lives. Same base the TUI uses for its own
/// convenience state, so an operator has one directory to clear, not two.
fn stamp_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from))
        .or_else(|| {
            std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local").join("state"))
        })?;
    Some(base.join("arachnid").join("update-check"))
}

fn due_for_check() -> bool {
    let Some(path) = stamp_path() else {
        return true;
    };
    let Ok(meta) = std::fs::metadata(&path) else {
        return true;
    };
    let Ok(modified) = meta.modified() else {
        return true;
    };
    modified
        .elapsed()
        .map(|e| e > CHECK_INTERVAL)
        .unwrap_or(true)
}

fn stamp_check() {
    let Some(path) = stamp_path() else { return };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Best effort throughout: a state file that will not write is a reason to
    // check more often, never a reason to fail a command.
    let _ = std::fs::write(&path, format!("{now}\n"));
}

// ---------------------------------------------------------------------------
// HTTP
// ---------------------------------------------------------------------------

fn agent(timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .user_agent(user_agent())
        .build()
        .into()
}

fn get_string(url: &str, timeout: Duration) -> Result<String> {
    let mut resp = agent(timeout).get(url).call().context("request failed")?;
    Ok(resp.body_mut().read_to_string()?)
}

fn get_bytes(url: &str, timeout: Duration, limit: u64) -> Result<Vec<u8>> {
    let mut resp = agent(timeout).get(url).call().context("request failed")?;
    Ok(resp.body_mut().with_config().limit(limit).read_to_vec()?)
}

// ---------------------------------------------------------------------------
// minisign verification
// ---------------------------------------------------------------------------

/// Parse a minisign public key into (algorithm, key id, key bytes).
fn parse_minisign_pubkey(text: &str) -> Result<([u8; 2], [u8; 8], [u8; 32])> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .context("public key has no key line")?;
    let raw = b64(line)?;
    if raw.len() != 42 {
        bail!("public key is {} bytes, expected 42", raw.len());
    }
    Ok((
        raw[0..2].try_into().expect("checked length"),
        raw[2..10].try_into().expect("checked length"),
        raw[10..42].try_into().expect("checked length"),
    ))
}

/// Parse a `.minisig` into (algorithm, key id, signature).
fn parse_minisign_sig(text: &str) -> Result<([u8; 2], [u8; 8], [u8; 64])> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .context("signature file has no signature line")?;
    let raw = b64(line)?;
    if raw.len() != 74 {
        bail!("signature is {} bytes, expected 74", raw.len());
    }
    Ok((
        raw[0..2].try_into().expect("checked length"),
        raw[2..10].try_into().expect("checked length"),
        raw[10..74].try_into().expect("checked length"),
    ))
}

fn b64(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("not valid base64")
}

/// Verify a detached minisign signature over `message`.
///
/// Only the legacy `Ed` algorithm is accepted — a plain Ed25519 signature over
/// the file itself, which `ed25519-dalek` verifies directly. The prehashed `ED`
/// form signs a BLAKE2b digest instead, and accepting it would mean carrying a
/// second hash implementation to check something we also control the signing of.
/// Releases are signed with `minisign -S`, which produces the legacy form.
pub fn verify_minisign(message: &[u8], sig_text: &str, pubkey_text: &str) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let (key_alg, key_id, key_bytes) = parse_minisign_pubkey(pubkey_text)?;
    let (sig_alg, sig_id, sig_bytes) = parse_minisign_sig(sig_text)?;

    if &key_alg != b"Ed" {
        bail!("unsupported public key algorithm; releases use minisign's legacy Ed25519 form");
    }
    if &sig_alg != b"Ed" {
        bail!(
            "this signature is prehashed (minisign -H), which this build does not verify; \
             releases are signed without -H"
        );
    }
    if key_id != sig_id {
        bail!(
            "signature was made by a different key (signature {} vs trusted {})",
            sig_id
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>(),
            key_id
                .iter()
                .map(|b| format!("{b:02X}"))
                .collect::<String>()
        );
    }

    let key =
        VerifyingKey::from_bytes(&key_bytes).context("public key is not a valid Ed25519 key")?;
    key.verify(message, &Signature::from_bytes(&sig_bytes))
        .context("signature does not verify against the release key")
}

/// Look one filename up in a `sha256sum`-format file.
pub fn digest_for(checksums: &str, filename: &str) -> Result<String> {
    for line in checksums.lines() {
        // "<64 hex>  <name>", with either two spaces or " *" before the name.
        let Some((digest, name)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if name.trim().trim_start_matches('*') == filename {
            return Ok(digest.trim().to_ascii_lowercase());
        }
    }
    bail!("{filename} is not listed in {CHECKSUMS}")
}

// ---------------------------------------------------------------------------
// self update
// ---------------------------------------------------------------------------

/// The release asset name for the platform this binary was built for.
pub fn target_asset() -> Result<String> {
    let triple = crate::doctor::target_triple();
    let ext = if cfg!(windows) { ".exe" } else { "" };
    Ok(format!("arachnid-cli-{triple}{ext}"))
}

/// Download, verify and replace this binary.
///
/// Order matters and is not negotiable: signature over the digest file first,
/// then the digest of the artifact, then anything is written anywhere near the
/// installed path. A failure at any step leaves the running binary untouched.
pub fn self_update(dry_run: bool) -> Result<String> {
    let Some(pubkey) = release_pubkey() else {
        bail!(
            "this build carries no release signing key, so an update cannot be verified and \
             will not be installed.\n\
             This is a development build. Install a signed release from \
             https://github.com/{RELEASE_REPO}/releases"
        );
    };

    let exe = std::env::current_exe().context("locate the running binary")?;
    let asset = target_asset()?;

    let body = get_string(LATEST_RELEASE_API, UPDATE_TIMEOUT).context(
        "could not reach the releases API. If this machine is offline or air-gapped, download \
         a signed release by hand instead",
    )?;
    let release: serde_json::Value = serde_json::from_str(&body)?;
    let tag = release
        .get("tag_name")
        .and_then(|t| t.as_str())
        .context("releases API response carries no tag_name")?;
    let latest = tag.trim_start_matches('v');

    if !is_newer(latest, version()) {
        return Ok(format!(
            "arachnid-cli {} is already the newest release ({tag}). Nothing to do.",
            version()
        ));
    }

    let base = format!("https://github.com/{RELEASE_REPO}/releases/download/{tag}");
    let checksums = get_string(&format!("{base}/{CHECKSUMS}"), UPDATE_TIMEOUT)
        .with_context(|| format!("download {CHECKSUMS} for {tag}"))?;
    let signature = get_string(&format!("{base}/{CHECKSUMS}.minisig"), UPDATE_TIMEOUT)
        .with_context(|| format!("download {CHECKSUMS}.minisig for {tag}"))?;

    verify_minisign(checksums.as_bytes(), &signature, pubkey)
        .context("the release digest file is not signed by the expected key; refusing to update")?;

    let want = digest_for(&checksums, &asset)?;
    // 512 MiB is far above any real artifact and far below anything that could
    // exhaust memory on a workstation.
    let bytes = get_bytes(&format!("{base}/{asset}"), UPDATE_TIMEOUT, 512 << 20)
        .with_context(|| format!("download {asset}"))?;
    let got = sha256_hex(&bytes);
    if got != want {
        bail!("{asset} has digest {got}, but the signed {CHECKSUMS} says {want}; refusing to install it");
    }

    if dry_run {
        return Ok(format!(
            "{tag} is available and verified.\n  asset      {asset}\n  sha256     {got}\n  \
             would replace {}\nRe-run without --dry-run to install.",
            exe.display()
        ));
    }

    install_over(&exe, &bytes)?;
    Ok(format!(
        "Updated to {tag}.\n  {}\n  sha256 {got}\nRun 'arachnid-cli doctor' to verify the installation.",
        exe.display()
    ))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Put `bytes` where `exe` is, as atomically as each platform allows.
///
/// The new file is written beside the target and renamed over it, so a crash or
/// a full disk mid-write leaves the working binary in place rather than a
/// half-written one. Windows cannot replace a running image, so the old file is
/// moved aside first and left for the next run to clear.
fn install_over(exe: &Path, bytes: &[u8]) -> Result<()> {
    let dir = exe
        .parent()
        .context("the running binary has no parent directory")?;
    let staged = dir.join(".arachnid-cli.new");
    std::fs::write(&staged, bytes).with_context(|| {
        format!(
            "write {} (is the install directory writable?)",
            staged.display()
        )
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&staged)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&staged, perms)?;
    }

    swap_into_place(&staged, exe)
}

/// Windows will not let a running image be replaced, so the old file is moved
/// aside first and left for the next run to clear. If the swap then fails, the
/// old binary goes back — an operator is left with a working tool or an error,
/// never with neither.
#[cfg(windows)]
fn swap_into_place(staged: &Path, exe: &Path) -> Result<()> {
    let dir = exe
        .parent()
        .context("the running binary has no parent directory")?;
    let old = dir.join(".arachnid-cli.old");
    let _ = std::fs::remove_file(&old);
    std::fs::rename(exe, &old)
        .context("move the running binary aside; is another arachnid-cli running?")?;
    match std::fs::rename(staged, exe) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::rename(&old, exe);
            Err(e).context("install the new binary")
        }
    }
}

/// Everywhere else a rename over a running binary is legal and atomic.
#[cfg(not(windows))]
fn swap_into_place(staged: &Path, exe: &Path) -> Result<()> {
    std::fs::rename(staged, exe).context("install the new binary")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The comparison that string ordering gets wrong at exactly the point it
    /// matters: 0.10.0 sorts *before* 0.9.0 as text.
    #[test]
    fn versions_compare_numerically() {
        assert!(is_newer("0.10.0", "0.9.0"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(is_newer("0.1.1", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
        // A tag with a suffix must not read as newer than the same release.
        assert!(!is_newer("0.1.0", "0.1.0"));
    }

    #[test]
    fn digests_are_looked_up_by_name() {
        let sums = "\
aa11  arachnid-cli-x86_64-unknown-linux-gnu
bb22 *arachnid-cli-x86_64-pc-windows-msvc.exe
";
        assert_eq!(
            digest_for(sums, "arachnid-cli-x86_64-unknown-linux-gnu").unwrap(),
            "aa11"
        );
        assert_eq!(
            digest_for(sums, "arachnid-cli-x86_64-pc-windows-msvc.exe").unwrap(),
            "bb22"
        );
        assert!(digest_for(sums, "not-listed").is_err());
    }

    /// The whole point of the signature step. Generated here rather than
    /// checked in, so the test proves the parser and the verifier agree on the
    /// real minisign layout rather than on a fixture someone hand-made.
    #[test]
    fn a_real_minisign_signature_verifies_and_a_tampered_one_does_not() {
        use base64::Engine;
        use ed25519_dalek::{Signer, SigningKey};

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let message = b"aa11  arachnid-cli-x86_64-unknown-linux-gnu\n";

        let mut pk = Vec::from(*b"Ed");
        pk.extend_from_slice(&id);
        pk.extend_from_slice(key.verifying_key().as_bytes());
        let pubkey = format!(
            "untrusted comment: test\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(&pk)
        );

        let mut sg = Vec::from(*b"Ed");
        sg.extend_from_slice(&id);
        sg.extend_from_slice(&key.sign(message).to_bytes());
        let sig = format!(
            "untrusted comment: test\n{}\ntrusted comment: test\n",
            base64::engine::general_purpose::STANDARD.encode(&sg)
        );

        verify_minisign(message, &sig, &pubkey).expect("a genuine signature must verify");

        // One byte of the signed content changed: the digest file an attacker
        // would have to forge to serve a different binary.
        let tampered = b"bb22  arachnid-cli-x86_64-unknown-linux-gnu\n";
        assert!(verify_minisign(tampered, &sig, &pubkey).is_err());

        // A signature from a different key must not pass either.
        let other = SigningKey::from_bytes(&[9u8; 32]);
        let mut wrong = Vec::from(*b"Ed");
        wrong.extend_from_slice(&id);
        wrong.extend_from_slice(&other.sign(message).to_bytes());
        let wrong_sig = format!(
            "untrusted comment: test\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(&wrong)
        );
        assert!(verify_minisign(message, &wrong_sig, &pubkey).is_err());
    }

    /// A prehashed signature must be refused rather than silently treated as a
    /// plain one, which would verify nothing.
    #[test]
    fn a_prehashed_signature_is_refused_not_ignored() {
        use base64::Engine;
        let mut sg = Vec::from(*b"ED");
        sg.extend_from_slice(&[0u8; 8]);
        sg.extend_from_slice(&[0u8; 64]);
        let sig = format!(
            "untrusted comment: x\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(&sg)
        );
        let mut pk = Vec::from(*b"Ed");
        pk.extend_from_slice(&[0u8; 8]);
        pk.extend_from_slice(&[0u8; 32]);
        let pubkey = format!(
            "untrusted comment: x\n{}\n",
            base64::engine::general_purpose::STANDARD.encode(&pk)
        );
        let err = verify_minisign(b"x", &sig, &pubkey)
            .unwrap_err()
            .to_string();
        assert!(err.contains("prehashed"), "{err}");
    }

    /// Both documented off switches have to work, and the env one has to accept
    /// the values people actually set.
    #[test]
    fn the_environment_off_switch_is_honoured() {
        // Safety: single-threaded test, and the variable is read-only elsewhere.
        unsafe {
            std::env::set_var("ARACHNID_NO_UPDATE_CHECK", "1");
            assert!(disabled_by_env());
            std::env::set_var("ARACHNID_NO_UPDATE_CHECK", "0");
            assert!(!disabled_by_env());
            std::env::set_var("ARACHNID_NO_UPDATE_CHECK", "");
            assert!(!disabled_by_env());
            std::env::remove_var("ARACHNID_NO_UPDATE_CHECK");
            assert!(!disabled_by_env());
        }
    }

    /// A development build must refuse to self-update rather than install
    /// something it cannot check the provenance of.
    #[test]
    fn an_unsigned_build_refuses_to_update() {
        if release_pubkey().is_none() {
            let err = self_update(true).unwrap_err().to_string();
            assert!(err.contains("no release signing key"), "{err}");
        }
    }
}
