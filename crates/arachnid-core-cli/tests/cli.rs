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
