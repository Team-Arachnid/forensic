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

#[test]
fn a_supplied_signing_key_is_used_and_is_reproducible() {
    let ws = Workspace::new("key");
    let key = ws.path("operator.key");
    std::fs::write(&key, "11".repeat(32)).unwrap();

    let mut fingerprints = Vec::new();
    for tag in ["a", "b"] {
        let ev = ws.path(tag);
        let out = run(&[
            "collect",
            "-o",
            &ev.display().to_string(),
            "--no-hash-binaries",
            "--signing-key",
            &key.display().to_string(),
            "--operator",
            "analyst-7",
        ]);
        assert!(
            matches!(code(&out), OK | 4),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );

        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(ev.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["operator"], "analyst-7");
        fingerprints.push(manifest["public_key"].as_str().unwrap().to_string());

        assert_eq!(code(&run(&["verify", &ev.display().to_string()])), OK);
    }
    // Same key across runs: the two containers are attributable to one operator.
    assert_eq!(fingerprints[0], fingerprints[1]);
}

#[test]
fn report_re_renders_from_the_container() {
    let ws = Workspace::new("report");
    let ev = ws.path("ev");
    collect_into(&ev);
    let evs = ev.display().to_string();

    let md = run(&["report", &evs]);
    assert_eq!(code(&md), OK);
    assert!(stdout(&md).contains("Arachnid Forensic"));

    let html = run(&["report", &evs, "--format", "html"]);
    assert_eq!(code(&html), OK);
    assert!(stdout(&html).starts_with("<!doctype html>"));

    let json = run(&["report", &evs, "--format", "json"]);
    assert_eq!(code(&json), OK);
    let parsed: serde_json::Value = serde_json::from_str(&stdout(&json)).expect("valid JSON");
    assert_eq!(parsed["schema_version"], "1.0.0");
    assert!(parsed["collection"]["processes"].as_array().unwrap().len() > 1);

    // Re-rendering must not disturb the container it read from.
    assert_eq!(code(&run(&["verify", &evs])), OK);
}

#[test]
fn json_mode_emits_only_json_on_stdout() {
    let ws = Workspace::new("jsonmode");
    let ev = ws.path("ev");
    collect_into(&ev);

    let v = run(&["--json", "verify", &ev.display().to_string()]);
    let parsed: serde_json::Value =
        serde_json::from_str(&stdout(&v)).expect("valid JSON on stdout");
    assert_eq!(parsed["problems"].as_array().unwrap().len(), 0);
}

#[test]
fn collecting_into_an_existing_container_is_refused() {
    let ws = Workspace::new("existing");
    let ev = ws.path("ev");
    collect_into(&ev);

    let second = collect_into(&ev);
    assert_eq!(
        code(&second),
        ERROR,
        "must not append to an existing container"
    );
    assert!(String::from_utf8_lossy(&second.stderr).contains("existing container"));
    // The original evidence is untouched.
    assert_eq!(code(&run(&["verify", &ev.display().to_string()])), OK);
}

#[test]
fn memory_acquisition_refuses_an_unverified_tool() {
    let ws = Workspace::new("memtool");
    let ev = ws.path("ev");
    let tool = ws.path("fake-avml");
    std::fs::write(&tool, b"#!/bin/sh\nexit 0\n").unwrap();

    let out = run(&[
        "collect",
        "-o",
        &ev.display().to_string(),
        "--no-hash-binaries",
        "--memory-tool",
        &tool.display().to_string(),
        "--memory-tool-sha256",
        &"0".repeat(64),
    ]);
    assert_eq!(code(&out), ERROR);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("hash mismatch"), "{err}");
    assert!(
        !ev.join("artifacts/memory.raw").exists(),
        "must not run an unverified tool"
    );
}

#[test]
fn memory_tool_without_its_hash_is_a_usage_error() {
    let ws = Workspace::new("memnohash");
    let out = run(&[
        "collect",
        "-o",
        &ws.path("ev").display().to_string(),
        "--memory-tool",
        "/bin/true",
    ]);
    assert_eq!(
        code(&out),
        USAGE,
        "--memory-tool must require --memory-tool-sha256"
    );
}

#[test]
fn verifying_a_nonexistent_container_is_a_runtime_error() {
    assert_eq!(
        code(&run(&["verify", "/nonexistent/arachnid-container"])),
        ERROR
    );
}

#[test]
fn parse_pcap_rejects_a_missing_input() {
    let ws = Workspace::new("nopcap");
    let out = run(&[
        "parse-pcap",
        "/nonexistent/capture.pcap",
        "-o",
        &ws.path("ev").display().to_string(),
    ]);
    assert_eq!(code(&out), ERROR);
}

#[test]
fn capture_without_a_device_is_a_runtime_error() {
    let ws = Workspace::new("nodev");
    let out = run(&["capture", "-o", &ws.path("ev").display().to_string()]);
    assert_eq!(code(&out), ERROR);
    assert!(String::from_utf8_lossy(&out.stderr).contains("--device is required"));
}
