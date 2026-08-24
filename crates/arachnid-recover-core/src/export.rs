//! Writing recovered files out, and logging them as evidence.
//!
//! A directory full of recovered files is not evidence: nothing ties those bytes
//! to the media they came from, and nothing would show if one were edited
//! afterwards. So export goes through the same tamper-evident container the rest
//! of the suite uses — every exported file is hashed as it is written and its
//! digest goes into the signed, hash-chained custody log, exactly as a collected
//! artifact does. `arachnid-core verify` then checks a recovery export the same
//! way it checks a triage collection, with no second implementation of anything.
//!
//! **The filenames are hostile input.** An original path comes out of the
//! filesystem under examination, which on a compromised host is attacker-
//! controlled. A path of `../../../../etc/cron.d/backdoor` must land inside the
//! output directory or nowhere; see [`safe_relative_path`], which is the only
//! function here allowed to decide where a byte lands.

use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use arachnid_evidence::Container;
use sha2::{Digest, Sha256};

use crate::results::{Confidence, RecoveredFile, ScanResults};
use crate::source::Source;

/// Bytes moved per read while streaming a recovered file to disk. A multi-
/// gigabyte video must not land in RAM to be exported.
const COPY_CHUNK: usize = 1 << 20;

/// What one export run did.
#[derive(Debug)]
pub struct ExportReport {
    pub output_dir: PathBuf,
    pub exported: Vec<ExportedFile>,
    pub skipped: Vec<(String, String)>,
    /// Path of the container the custody log lives in.
    pub container: PathBuf,
    pub key_fingerprint: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ExportedFile {
    pub id: String,
    /// Path relative to the output directory, as written.
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
    pub confidence: Confidence,
    /// Set when the file could not be read in full and what was written is
    /// short of the size the filesystem declared.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub short_by: Option<u64>,
}

/// Export `files` from `source` into `output_dir`, logging every one into a new
/// evidence container rooted there.
///
/// Filesystem-recovered files keep their directory structure under
/// `recovered/`; carved files go flat into `carved/`, because they have no
/// structure to keep and mixing them would imply one.
pub fn export(
    source: &mut dyn Source,
    results: &ScanResults,
    files: &[&RecoveredFile],
    output_dir: &Path,
    operator: &str,
) -> Result<ExportReport> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("create output directory {}", output_dir.display()))?;

    let mut container = Container::create(output_dir, operator, None, false)
        .with_context(|| format!("open an evidence container at {}", output_dir.display()))?;
    container.note(format!(
        "arachnid-recover export from {} ({} byte source); {} of {} result(s) selected",
        results.source,
        results.source_size,
        files.len(),
        results.files.len()
    ))?;

    // The results index goes in first, so the custody log records what the
    // export was selected *from* before it records what came out.
    container.add_json("results.json", results)?;

    let mut exported = Vec::new();
    let mut skipped = Vec::new();

    for file in files {
        if let Some(why) = &file.encrypted {
            // Encrypted content is written out as the ciphertext it is — that is
            // still evidence — but it is recorded as encrypted so nothing
            // downstream treats a failed open as a corrupt recovery.
            container.note(format!("{}: {why}", file.id))?;
        }

        let relative = match placement(file) {
            Ok(p) => p,
            Err(e) => {
                skipped.push((file.id.clone(), e));
                continue;
            }
        };
        let target = container.artifact_path(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }

        match write_one(source, file, &target) {
            Ok((digest, bytes)) => {
                // Seal it through the container so the digest in the custody log
                // is one the container computed off the file on disk, not one
                // this module handed it.
                container.seal(&relative)?;
                exported.push(ExportedFile {
                    id: file.id.clone(),
                    path: relative,
                    sha256: digest,
                    bytes,
                    confidence: file.confidence(),
                    short_by: (bytes < file.size).then_some(file.size - bytes),
                });
            }
            Err(e) => {
                let why = format!("{e:#}");
                container.note(format!("{}: export failed: {why}", file.id))?;
                skipped.push((file.id.clone(), why));
            }
        }
    }

    let summary = export_summary(results, &exported, &skipped);
    container.add_bytes("export-summary.txt", summary.as_bytes())?;
    let fingerprint = container.key_fingerprint();
    container.finish()?;

    Ok(ExportReport {
        output_dir: output_dir.to_path_buf(),
        exported,
        skipped,
        container: output_dir.to_path_buf(),
        key_fingerprint: fingerprint,
    })
}

/// Where a file goes inside the container's artifact tree.
fn placement(file: &RecoveredFile) -> std::result::Result<String, String> {
    if file.method.is_carved() {
        // Carved files are flat and named after where they were found. Nothing
        // about a carved file justifies a directory.
        return Ok(format!("carved/{}", sanitize_component(&file.export_name)));
    }
    let path = file
        .original_path
        .as_deref()
        .unwrap_or(&file.export_name);
    let safe = safe_relative_path(path)?;
    Ok(format!("recovered/{safe}"))
}

/// Reduce a path from the examined filesystem to something that can only ever
/// land inside the output directory.
///
/// Every component is checked, not just the first: `a/../../b` is as dangerous
/// as `../b`. Absolute roots, Windows drive prefixes, `..`, and empty or
/// dot components are all dropped rather than rejected, so a file with an
/// awkward path is still recovered — under a path that is merely awkward.
pub fn safe_relative_path(path: &str) -> std::result::Result<String, String> {
    // NUL cannot appear in a path on either platform and is the classic
    // truncation trick; a name carrying one is refused outright.
    if path.contains('\0') {
        return Err("path contains a NUL byte".into());
    }
    let normalized = path.replace('\\', "/");
    let mut parts: Vec<String> = Vec::new();
    for raw in normalized.split('/') {
        match raw {
            "" | "." => continue,
            ".." => {
                // Drop it. Popping the parent would let a crafted path climb
                // back out one component at a time.
                continue;
            }
            other => {
                // A Windows drive prefix ("C:") is not a directory name.
                if other.len() == 2 && other.ends_with(':') && other.as_bytes()[0].is_ascii_alphabetic() {
                    continue;
                }
                parts.push(sanitize_component(other));
            }
        }
    }
    if parts.is_empty() {
        return Err(format!("path {path:?} reduces to nothing safe to write"));
    }
    Ok(parts.join("/"))
}

/// Make one path component safe to write on both platforms.
///
/// Reserved characters become `_`, control bytes are dropped, and the result is
/// length-capped: a 4000-character filename out of a corrupted MFT record
/// otherwise fails the write with a confusing OS error.
fn sanitize_component(name: &str) -> String {
    let mut out: String = name
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '<' | '>' | ':' | '"' | '|' | '?' | '*' | '/' | '\\' => '_',
            c => c,
        })
        .collect();
    // Windows refuses a name ending in a dot or a space.
    while out.ends_with('.') || out.ends_with(' ') {
        out.pop();
    }
    if out.is_empty() {
        out.push('_');
    }
    // 200 leaves room for the container prefix inside a 255-byte limit.
    if out.chars().count() > 200 {
        out = out.chars().take(200).collect();
    }
    // The Windows reserved device names are refused whatever the extension.
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = out.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        out.insert(0, '_');
    }
    out
}

/// Stream one file's extents to disk, hashing as it goes.
///
/// Returns the digest and the number of bytes actually written, which is short
/// of the declared size when the media would not give the whole file back. The
/// short file is kept: a partial document is evidence, and deleting it because
/// it was incomplete would destroy what the recovery found.
fn write_one(
    source: &mut dyn Source,
    file: &RecoveredFile,
    target: &Path,
) -> Result<(String, u64)> {
    use std::io::Write;

    let mut out = fs::File::create(target)
        .with_context(|| format!("create {}", target.display()))?;
    let mut hasher = Sha256::new();
    let mut written = 0u64;
    let mut buf = vec![0u8; COPY_CHUNK];

    for extent in &file.extents {
        let mut left = extent.length;
        let mut at = extent.offset;
        while left > 0 {
            let want = (left as usize).min(buf.len());
            let n = source.read_at(at, &mut buf[..want])?;
            if n == 0 {
                // The media stopped giving. Keep what was written and let the
                // caller report the shortfall.
                break;
            }
            hasher.update(&buf[..n]);
            out.write_all(&buf[..n])?;
            written += n as u64;
            at += n as u64;
            left -= n as u64;
        }
    }
    out.flush()?;
    Ok((
        arachnid_evidence::hex(&hasher.finalize()),
        written,
    ))
}

fn export_summary(
    results: &ScanResults,
    exported: &[ExportedFile],
    skipped: &[(String, String)],
) -> String {
    let mut s = String::new();
    s.push_str("Arachnid Recover — export summary\n");
    s.push_str("=================================\n\n");
    s.push_str(&format!("Source     {}\n", results.source));
    s.push_str(&format!("Exported   {} file(s)\n", exported.len()));
    let bytes: u64 = exported.iter().map(|e| e.bytes).sum();
    s.push_str(&format!("Bytes      {bytes}\n"));

    let short: Vec<_> = exported.iter().filter(|e| e.short_by.is_some()).collect();
    if !short.is_empty() {
        s.push_str(&format!(
            "\n{} file(s) exported short of their declared size — the media did not return the \
             whole allocation:\n",
            short.len()
        ));
        for e in short.iter().take(20) {
            s.push_str(&format!(
                "  {} — {} byte(s) missing\n",
                e.path,
                e.short_by.unwrap_or(0)
            ));
        }
    }

    if !skipped.is_empty() {
        s.push_str(&format!("\n{} file(s) were not exported:\n", skipped.len()));
        for (id, why) in skipped.iter().take(20) {
            s.push_str(&format!("  {id}: {why}\n"));
        }
    }

    s.push_str("\nEvery file above is hashed in this container's custody.log, which is signed \n");
    s.push_str("and hash-chained. Re-check it at any time with:\n\n");
    s.push_str("  arachnid-core verify <this directory>\n");
    s
}

/// Absolute path of the output directory, resolved so a report cannot be
/// ambiguous about where files went.
pub fn resolve_output(dir: &Path) -> PathBuf {
    dir.canonicalize().unwrap_or_else(|_| {
        // Not yet created: build the absolute path by hand rather than
        // reporting a relative one.
        let mut out = std::env::current_dir().unwrap_or_default();
        for c in dir.components() {
            match c {
                Component::RootDir | Component::Prefix(_) => out = PathBuf::from(c.as_os_str()),
                Component::CurDir => {}
                Component::ParentDir => {
                    out.pop();
                }
                Component::Normal(p) => out.push(p),
            }
        }
        out
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The single most important test in this module. An original path is
    /// attacker-controlled on a compromised host.
    #[test]
    fn traversal_cannot_escape_the_output_directory() {
        for evil in [
            "../../../../etc/cron.d/backdoor",
            "/etc/shadow",
            "a/../../b",
            "..\\..\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\Windows\\System32\\config\\SAM",
        ] {
            let safe = safe_relative_path(evil).expect("should reduce, not fail");
            assert!(!safe.starts_with('/'), "{evil} -> {safe}");
            assert!(!safe.contains(".."), "{evil} -> {safe}");
            assert!(!safe.contains(':'), "{evil} -> {safe}");
            // And the decisive check: joined onto a root, it stays under it.
            let joined = Path::new("/out").join(&safe);
            assert!(joined.starts_with("/out"), "{evil} -> {}", joined.display());
        }
    }

    #[test]
    fn a_nul_byte_is_refused_outright() {
        assert!(safe_relative_path("evil\0.txt").is_err());
    }

    #[test]
    fn an_ordinary_path_survives_intact() {
        assert_eq!(
            safe_relative_path("Users/jsharma/Documents/report.pdf").unwrap(),
            "Users/jsharma/Documents/report.pdf"
        );
        assert_eq!(
            safe_relative_path("Windows\\Temp\\note.txt").unwrap(),
            "Windows/Temp/note.txt"
        );
    }

    #[test]
    fn a_path_that_reduces_to_nothing_is_an_error_not_an_empty_write() {
        assert!(safe_relative_path("../..").is_err());
        assert!(safe_relative_path("").is_err());
    }

    #[test]
    fn reserved_and_awkward_names_are_made_writable() {
        assert_eq!(sanitize_component("CON"), "_CON");
        assert_eq!(sanitize_component("NUL.txt"), "_NUL.txt");
        assert_eq!(sanitize_component("trailing."), "trailing");
        assert_eq!(sanitize_component("a:b|c?"), "a_b_c_");
        assert_eq!(sanitize_component(&"x".repeat(500)).chars().count(), 200);
        assert_eq!(sanitize_component(""), "_");
    }
}
