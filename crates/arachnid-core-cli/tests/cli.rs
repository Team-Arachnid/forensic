//! Full-binary integration tests: run the shipped executable the way an IR
//! playbook would, and assert on exit codes and on-disk state.
//!
//! These run unprivileged. Anything needing root (live capture, memory
//! acquisition) is exercised only on its refusal path here; the privileged
//! paths belong to the disposable-VM suite in `docs/`.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_arachnid-core");

const OK: i32 = 0;
const ERROR: i32 = 1;
const USAGE: i32 = 2;
const INTEGRITY: i32 = 3;

struct Workspace(PathBuf);

impl Workspace {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("arachnid-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Workspace(d)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("ARACHNID_LOG", "warn")
        .output()
        .expect("run arachnid-core")
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("process exited normally")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn collect_into(dir: &Path) -> Output {
    run(&[
        "collect",
        "-o",
        &dir.display().to_string(),
        "--no-hash-binaries",
    ])
}

#[test]
fn collect_produces_a_container_that_verifies() {
    let ws = Workspace::new("roundtrip");
    let ev = ws.path("ev");

    let out = collect_into(&ev);
    assert!(
        matches!(code(&out), OK | 4),
        "collect failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    for f in [
        "manifest.json",
        "custody.log",
        "artifacts/processes.json",
        "artifacts/connections.json",
        "artifacts/report.json",
        "artifacts/report.md",
        "artifacts/report.html",
    ] {
        assert!(ev.join(f).exists(), "missing {f}");
    }

    let v = run(&["verify", &ev.display().to_string()]);
    assert_eq!(code(&v), OK, "verify failed: {}", stdout(&v));
    assert!(stdout(&v).contains("VERIFIED"));

    // The fingerprint the operator is told to record must be the one verify reports.
    let printed = stdout(&out);
    let fp = printed
        .lines()
        .find_map(|l| l.strip_prefix("Signing key fingerprint: "))
        .expect("collect prints a key fingerprint");
    assert!(
        stdout(&v).contains(fp.trim()),
        "fingerprint mismatch between collect and verify"
    );
}

#[test]
fn a_modified_artifact_fails_verification() {
    let ws = Workspace::new("tamper");
    let ev = ws.path("ev");
    collect_into(&ev);

    let target = ev.join("artifacts/connections.json");
    let mut data = std::fs::read(&target).unwrap();
    data.extend_from_slice(b"\n");
    std::fs::write(&target, data).unwrap();

    let v = run(&["verify", &ev.display().to_string()]);
    assert_eq!(code(&v), INTEGRITY, "tampering must exit {INTEGRITY}");
    assert!(
        stdout(&v).contains("content modified since collection"),
        "{}",
        stdout(&v)
    );
}

#[test]
fn a_planted_artifact_fails_verification() {
    let ws = Workspace::new("plant");
    let ev = ws.path("ev");
    collect_into(&ev);
    std::fs::write(ev.join("artifacts/extra.json"), b"{}").unwrap();

    let v = run(&["verify", &ev.display().to_string()]);
    assert_eq!(code(&v), INTEGRITY);
    assert!(stdout(&v).contains("not in custody log"), "{}", stdout(&v));
}

#[test]
fn a_truncated_custody_log_fails_verification() {
    let ws = Workspace::new("truncate");
    let ev = ws.path("ev");
    collect_into(&ev);

    let log = std::fs::read_to_string(ev.join("custody.log")).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    let without_middle: Vec<&str> = lines
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 2)
        .map(|(_, l)| *l)
        .collect();
    std::fs::write(ev.join("custody.log"), without_middle.join("\n") + "\n").unwrap();

    let v = run(&["verify", &ev.display().to_string()]);
    assert_eq!(code(&v), INTEGRITY);
    assert!(stdout(&v).contains("hash chain broken"), "{}", stdout(&v));
}

#[test]
fn dry_run_writes_nothing() {
    let ws = Workspace::new("dryrun");
    let ev = ws.path("ev");

    let out = run(&[
        "collect",
        "-o",
        &ev.display().to_string(),
        "--no-hash-binaries",
        "--dry-run",
    ]);
    assert!(matches!(code(&out), OK | 4));
    assert!(!ev.exists(), "dry run created {}", ev.display());
}
