//! Embeds the release signing key at build time.
//!
//! The key can come from either of two places, and the order matters:
//!
//! 1. `ARACHNID_MINISIGN_PUBKEY`, which the release workflow sets from the
//!    repository variable. This is what a published binary carries.
//! 2. `release/minisign.pub`, the same key committed to the repository.
//!
//! Without the fallback, anything built with `cargo install` or `cargo build`
//! reports "this build carries no release signing key" and refuses to
//! `self update` — while the key it needs sits in the tree it was just built
//! from. That reads as a bug even though the refusal is correct, and the honest
//! fix is to give the build the key rather than to soften the refusal.
//!
//! A build with neither still produces a binary that refuses to self-update.
//! That is the intended behaviour for a key-less build, not a failure mode.

use std::path::Path;

fn main() {
    println!("cargo::rerun-if-env-changed=ARACHNID_MINISIGN_PUBKEY");

    if std::env::var_os("ARACHNID_MINISIGN_PUBKEY").is_some() {
        // Set explicitly; option_env! in the crate picks it up as-is.
        return;
    }

    // <workspace>/crates/arachnid-cli/build.rs -> <workspace>/release/minisign.pub
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("cargo sets this");
    let pubkey = Path::new(&manifest)
        .parent()
        .and_then(Path::parent)
        .map(|root| root.join("release").join("minisign.pub"));

    let Some(path) = pubkey else { return };
    println!("cargo::rerun-if-changed={}", path.display());

    let Ok(text) = std::fs::read_to_string(&path) else {
        return;
    };
    // The file is two lines: an untrusted comment, then the key. Take the key.
    let Some(key) = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
    else {
        return;
    };
    println!("cargo::rustc-env=ARACHNID_MINISIGN_PUBKEY={key}");
}
