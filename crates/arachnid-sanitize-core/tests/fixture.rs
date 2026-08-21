//! Regenerates the checked-in sample certificate.
//!
//! Ignored by default: it writes into the repository, which a normal `cargo
//! test` run must not do. Run it deliberately after changing the certificate
//! layout:
//!
//! ```text
//! cargo test -p arachnid-sanitize-core --test fixture -- --ignored
//! ```
//!
//! The fixture is generated rather than hand-written so it cannot drift from
//! what the code actually emits — a sample certificate that no longer matches
//! the real output is worse than none, because it is what a reviewer reads
//! instead of running the tool.

use std::sync::atomic::AtomicBool;

use arachnid_sanitize_core::{
    cert, engine,
    pattern::WipeMethod,
    safety::{self, WipeRequest},
    target::FileBackedTarget,
    verify::{self, VerifyOptions},
    BusType, Device,
};
use ed25519_dalek::SigningKey;

/// A fixed key, so regenerating the fixture produces a stable public key and
/// the diff shows only what actually changed. Never use a constant key for a
/// real wipe: anyone can forge a certificate under it.
const FIXTURE_KEY: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];

#[test]
#[ignore = "writes into the repository; run explicitly with --ignored"]
fn regenerate_sample_certificate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let image = dir.path().join("virtual.img");
    let size = 4 * 1024 * 1024;
    FileBackedTarget::create(&image, size).expect("create virtual device");

    let device = Device {
        path: "/dev/sdb".into(),
        model: "SAMSUNG MZ7LH480HAHQ-00005".into(),
        serial: "S4EVNF0M123456".into(),
        size_bytes: size,
        bus: BusType::Sata,
        removable: false,
        is_system: false,
        system_reason: None,
    };

    let clearance = safety::authorize(
        WipeRequest {
            typed_serial: device.serial.clone(),
            device: device.clone(),
            method: WipeMethod::Dod3Pass,
            force_system_volume: false,
            dry_run: false,
            operator: "analyst@forensics-lab".into(),
        },
        Some(&device),
    )
    .expect("the fixture request clears every rail");

    let mut target = FileBackedTarget::open(&image).expect("open");
    let outcome = engine::wipe(
        &mut target,
        &clearance,
        &engine::Progress::default(),
        &AtomicBool::new(false),
    )
    .expect("wipe");
    let report = verify::verify(
        &mut target,
        &outcome,
        &VerifyOptions {
            head_bytes: 512 * 1024,
            tail_bytes: 512 * 1024,
            samples: 32,
            sample_bytes: 16 * 1024,
        },
    )
    .expect("verify");
    assert!(report.passed, "the fixture wipe must verify");

    let key = SigningKey::from_bytes(&FIXTURE_KEY);
    let mut certificate = cert::issue(
        &clearance,
        &outcome,
        &report,
        &key,
        &"0".repeat(64), // first entry in a fresh register
    )
    .expect("certificate");

    // `issue` reads the real hostname, and this sample is checked into a public
    // repository. Substitute an obviously fictional one rather than committing
    // whichever workstation last regenerated the fixture.
    certificate.host = "forensics-lab-01".into();

    let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("schema")
        .join("samples");
    std::fs::create_dir_all(&out).expect("create sample dir");

    std::fs::write(
        out.join("erasure-certificate.json"),
        serde_json::to_vec_pretty(&certificate).expect("serialize"),
    )
    .expect("write json");
    std::fs::write(
        out.join("erasure-certificate.md"),
        cert::to_markdown(&certificate),
    )
    .expect("write markdown");
    std::fs::write(
        out.join("erasure-certificate.html"),
        cert::to_html(&certificate),
    )
    .expect("write html");

    eprintln!("wrote sample certificates to {}", out.display());
}
