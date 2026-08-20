//! End-to-end tests for the safety rails and the wipe-verify-certify flow,
//! driven against file-backed virtual devices.
//!
//! These run the *real* engine, the real verification pass and the real
//! certificate issuer through the same `WipeTarget` trait a physical drive uses.
//! Nothing here is stubbed except the medium itself, so a rail that stops
//! working stops these tests too.
//!
//! No test in this file touches real hardware, by design: a test suite that
//! needs a spare disk is a test suite that does not run.

use std::sync::atomic::AtomicBool;

use arachnid_sanitize_core::{
    cert, engine,
    pattern::WipeMethod,
    safety::{self, Refusal, WipeRequest},
    target::{FileBackedTarget, WipeTarget},
    verify::{self, VerifyOptions},
    BusType, Device,
};
use tempfile::TempDir;

/// A virtual device plus the file standing in for its medium.
struct Fixture {
    _dir: TempDir,
    path: std::path::PathBuf,
    device: Device,
}

fn fixture(size: u64) -> Fixture {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("virtual.img");
    FileBackedTarget::create(&path, size).expect("create virtual device");
    Fixture {
        _dir: dir,
        path,
        device: Device {
            path: "/dev/virtual0".into(),
            model: "ARACHNID VIRTUAL".into(),
            serial: "AVX-0000-0001".into(),
            size_bytes: size,
            bus: BusType::Sata,
            removable: false,
            is_system: false,
            system_reason: None,
        },
    }
}

impl Fixture {
    fn open(&self) -> FileBackedTarget {
        FileBackedTarget::open(&self.path).expect("open virtual device")
    }

    /// Write recognisable "user data" so a test can prove it is gone rather
    /// than assuming an empty file was already zeroed.
    fn seed(&self, marker: &[u8]) {
        let mut t = self.open();
        let mut offset = 0;
        while offset < self.device.size_bytes {
            t.write_at(offset, marker).expect("seed");
            offset += 64 * 1024;
        }
        t.flush().expect("flush seed");
    }

    fn contains(&self, needle: &[u8]) -> bool {
        std::fs::read(&self.path)
            .expect("read back")
            .windows(needle.len())
            .any(|w| w == needle)
    }

    fn request(&self, method: WipeMethod) -> WipeRequest {
        WipeRequest {
            device: self.device.clone(),
            method,
            typed_serial: self.device.serial.clone(),
            force_system_volume: false,
            dry_run: false,
            operator: "integration-test".into(),
        }
    }
}

fn sample_options() -> VerifyOptions {
    VerifyOptions {
        head_bytes: 32 * 1024,
        tail_bytes: 32 * 1024,
        samples: 16,
        sample_bytes: 4096,
    }
}

// ---------------------------------------------------------------------------
// The happy path, end to end
// ---------------------------------------------------------------------------

#[test]
fn a_full_wipe_destroys_the_data_verifies_and_certifies() {
    let f = fixture(2 * 1024 * 1024);
    f.seed(b"CONFIDENTIAL-CASE-EVIDENCE");
    assert!(
        f.contains(b"CONFIDENTIAL-CASE-EVIDENCE"),
        "seed did not land"
    );

    let clearance =
        safety::authorize(f.request(WipeMethod::Dod3Pass), Some(&f.device)).expect("clears");
    let mut target = f.open();
    let outcome = engine::wipe(
        &mut target,
        &clearance,
        &engine::Progress::default(),
        &AtomicBool::new(false),
    )
    .expect("wipe runs");

    assert!(outcome.complete());
    assert!(
        !f.contains(b"CONFIDENTIAL-CASE-EVIDENCE"),
        "the marker survived a completed wipe"
    );

    let report = verify::verify(&mut target, &outcome, &sample_options()).expect("verify runs");
    assert!(report.passed, "{:?}", report.failures().collect::<Vec<_>>());

    let key = cert::ephemeral_key().expect("key");
    let register = f._dir.path().join("certificates.log");
    let prev = cert::head(&register).expect("head");
    let certificate = cert::issue(&clearance, &outcome, &report, &key, &prev).expect("certificate");

    assert_eq!(certificate.device_serial, "AVX-0000-0001");
    assert_eq!(certificate.pass_count, 3);
    assert!(certificate.verification_passed);
    assert!(!certificate.forced_system_volume);

    cert::append(&register, &certificate, &key).expect("append");
    let (checks, problems) = cert::verify_register(&register).expect("verify register");
    assert_eq!(checks.len(), 1);
    assert!(problems.is_empty(), "{problems:?}");
}

// ---------------------------------------------------------------------------
// Rails
// ---------------------------------------------------------------------------

#[test]
fn a_serial_mismatch_is_refused_and_writes_nothing() {
    let f = fixture(512 * 1024);
    f.seed(b"UNTOUCHED-MARKER");

    let mut request = f.request(WipeMethod::NistClear);
    request.typed_serial = "AVX-0000-0002".into(); // one digit out

    match safety::authorize(request, Some(&f.device)) {
        Err(Refusal::SerialMismatch { .. }) => {}
        other => panic!("expected a serial mismatch, got {other:?}"),
    }
    // There is no Clearance, so there is nothing to hand the engine. The medium
    // is necessarily untouched -- this asserts it anyway, because that is the
    // property the rail exists to guarantee.
    assert!(f.contains(b"UNTOUCHED-MARKER"));
}

#[test]
fn a_system_device_is_refused_without_the_force_flag() {
    let mut f = fixture(512 * 1024);
    f.device.is_system = true;
    f.device.system_reason = Some("hosts the running OS".into());
    f.seed(b"SYSTEM-MARKER");

    match safety::authorize(f.request(WipeMethod::NistClear), Some(&f.device)) {
        Err(Refusal::SystemVolume { .. }) => {}
        other => panic!("expected a system-volume refusal, got {other:?}"),
    }
    assert!(f.contains(b"SYSTEM-MARKER"));
}

#[test]
fn forcing_a_system_device_clears_and_is_recorded_on_the_certificate() {
    let mut f = fixture(1024 * 1024);
    f.device.is_system = true;
    f.device.system_reason = Some("hosts the running OS".into());

    let mut request = f.request(WipeMethod::NistClear);
    request.force_system_volume = true;
    let clearance = safety::authorize(request, Some(&f.device)).expect("force clears the block");
    assert!(clearance.overrode_system_volume);

    let mut target = f.open();
    let outcome = engine::wipe(
        &mut target,
        &clearance,
        &engine::Progress::default(),
        &AtomicBool::new(false),
    )
    .expect("wipe runs");
    let report = verify::verify(&mut target, &outcome, &sample_options()).expect("verify");
    let key = cert::ephemeral_key().expect("key");
    let certificate = cert::issue(&clearance, &outcome, &report, &key, "0".repeat(64).as_str())
        .expect("certificate");

    assert!(
        certificate.forced_system_volume,
        "the override must appear on the certificate an auditor reads"
    );
}

#[test]
fn a_hot_swapped_device_is_refused_even_with_the_right_serial() {
    let f = fixture(512 * 1024);
    f.seed(b"OTHER-DRIVE-DATA");

    // Same path, different drive: the classic unplug-and-replace during a
    // session, where the path is reused for a device the operator never chose.
    let mut now = f.device.clone();
    now.serial = "DIFFERENT-DRIVE".into();
    now.model = "SOME OTHER DISK".into();

    match safety::authorize(f.request(WipeMethod::NistClear), Some(&now)) {
        Err(Refusal::DeviceChanged { .. }) => {}
        other => panic!("expected a device-changed refusal, got {other:?}"),
    }
    assert!(f.contains(b"OTHER-DRIVE-DATA"));
}

#[test]
fn a_device_that_vanished_is_refused() {
    let f = fixture(512 * 1024);
    match safety::authorize(f.request(WipeMethod::NistClear), None) {
        Err(Refusal::DeviceChanged { .. }) => {}
        other => panic!("expected a device-changed refusal, got {other:?}"),
    }
}

#[test]
fn a_device_without_a_serial_cannot_be_wiped_at_all() {
    let mut f = fixture(512 * 1024);
    f.device.serial = String::new();
    let mut request = f.request(WipeMethod::NistClear);
    request.typed_serial = String::new();

    match safety::authorize(request, Some(&f.device)) {
        Err(Refusal::NoSerial { .. }) => {}
        other => panic!("expected a no-serial refusal, got {other:?}"),
    }
}

#[test]
fn crypto_erase_is_refused_because_this_build_cannot_confirm_an_sed() {
    let f = fixture(512 * 1024);
    match safety::authorize(f.request(WipeMethod::CryptoErase), Some(&f.device)) {
        Err(Refusal::CryptoEraseUnsupported { .. }) => {}
        other => panic!("expected a crypto-erase refusal, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Dry run
// ---------------------------------------------------------------------------

#[test]
fn a_dry_run_writes_not_one_byte_and_earns_no_certificate() {
    let f = fixture(1024 * 1024);
    f.seed(b"DRY-RUN-MARKER");
    let before = std::fs::read(&f.path).expect("read before");

    let mut request = f.request(WipeMethod::Dod7Pass);
    request.dry_run = true;
    let clearance = safety::authorize(request, Some(&f.device)).expect("clears");

    let mut target = f.open();
    let outcome = engine::wipe(
        &mut target,
        &clearance,
        &engine::Progress::default(),
        &AtomicBool::new(false),
    )
    .expect("dry run");

    assert!(outcome.dry_run);
    assert_eq!(outcome.bytes_written, 0);
    assert_eq!(
        std::fs::read(&f.path).expect("read after"),
        before,
        "a dry run modified the medium"
    );
    assert!(f.contains(b"DRY-RUN-MARKER"));

    let report = verify::verify(&mut target, &outcome, &sample_options()).expect("verify");
    assert!(!report.passed);

    let key = cert::ephemeral_key().expect("key");
    assert!(
        matches!(
            cert::issue(&clearance, &outcome, &report, &key, "0".repeat(64).as_str()),
            Err(cert::Refused::WipeIncomplete(_))
        ),
        "a dry run must never produce a certificate"
    );
}

// ---------------------------------------------------------------------------
// Failure paths that must not certify
// ---------------------------------------------------------------------------

#[test]
fn surviving_data_fails_verification_and_blocks_the_certificate() {
    let f = fixture(1024 * 1024);
    let clearance =
        safety::authorize(f.request(WipeMethod::NistClear), Some(&f.device)).expect("clears");

    let mut target = f.open();
    let outcome = engine::wipe(
        &mut target,
        &clearance,
        &engine::Progress::default(),
        &AtomicBool::new(false),
    )
    .expect("wipe");

    // A sector the wipe did not take, standing in for a drive that silently
    // failed to commit part of a pass.
    target.write_at(4096, b"RECOVERABLE").expect("plant");
    target.flush().expect("flush");

    let report = verify::verify(&mut target, &outcome, &sample_options()).expect("verify");
    assert!(!report.passed);

    let key = cert::ephemeral_key().expect("key");
    assert!(matches!(
        cert::issue(&clearance, &outcome, &report, &key, "0".repeat(64).as_str()),
        Err(cert::Refused::VerificationFailed(_))
    ));
}

#[test]
fn a_cancelled_wipe_cannot_be_certified() {
    let f = fixture(1024 * 1024);
    let clearance =
        safety::authorize(f.request(WipeMethod::Dod3Pass), Some(&f.device)).expect("clears");

    let mut target = f.open();
    let outcome = engine::wipe(
        &mut target,
        &clearance,
        &engine::Progress::default(),
        &AtomicBool::new(true), // cancelled before the first chunk
    )
    .expect("wipe returns");

    assert!(outcome.cancelled);
    let report = verify::verify(&mut target, &outcome, &sample_options()).expect("verify");
    assert!(!report.passed);
    assert!(report.blocked.as_deref().unwrap().contains("cancelled"));

    let key = cert::ephemeral_key().expect("key");
    assert!(matches!(
        cert::issue(&clearance, &outcome, &report, &key, "0".repeat(64).as_str()),
        Err(cert::Refused::WipeIncomplete(_))
    ));
}

// ---------------------------------------------------------------------------
// Pattern correctness
// ---------------------------------------------------------------------------

/// Byte-for-byte, over the whole device, for every overwrite method. Sampling
/// is what verification does in the field; a test has the luxury of checking
/// all of it, and the pass sequences are the thing an auditor is relying on.
#[test]
fn every_method_leaves_exactly_its_final_pass_across_the_whole_device() {
    for method in [
        WipeMethod::NistClear,
        WipeMethod::NistPurge,
        WipeMethod::Dod3Pass,
        WipeMethod::Dod7Pass,
    ] {
        // Deliberately not a multiple of the 4 MiB chunk, so the tail
        // short-write is exercised on every method.
        let f = fixture(1_000_003);
        f.seed(b"BEFORE");

        let clearance = safety::authorize(f.request(method), Some(&f.device)).expect("clears");
        let mut target = f.open();
        let outcome = engine::wipe(
            &mut target,
            &clearance,
            &engine::Progress::default(),
            &AtomicBool::new(false),
        )
        .expect("wipe");

        assert!(outcome.complete(), "{method:?} did not complete");
        assert_eq!(
            outcome.passes.len(),
            method.passes().len(),
            "{method:?} ran the wrong number of passes"
        );

        let last = outcome.passes.last().expect("a final pass");
        let mut expected = vec![0u8; 1_000_003];
        last.fill(&mut expected, 0);
        assert_eq!(
            std::fs::read(&f.path).expect("read back"),
            expected,
            "{method:?} did not leave its final pass across the whole device"
        );
    }
}

/// A Purge that fell back to software must say so on the certificate in terms
/// an auditor cannot skim as a hardware purge. This is the compliance claim the
/// whole module is built around not overstating.
#[test]
fn a_purge_that_fell_back_says_so_on_the_certificate() {
    let f = fixture(512 * 1024);
    let clearance =
        safety::authorize(f.request(WipeMethod::NistPurge), Some(&f.device)).expect("clears");

    let mut target = f.open();
    let outcome = engine::wipe(
        &mut target,
        &clearance,
        &engine::Progress::default(),
        &AtomicBool::new(false),
    )
    .expect("wipe");
    assert!(
        !outcome.purge_path.is_hardware(),
        "this build performs no hardware purge and must not claim one"
    );

    let report = verify::verify(&mut target, &outcome, &sample_options()).expect("verify");
    let key = cert::ephemeral_key().expect("key");
    let certificate = cert::issue(&clearance, &outcome, &report, &key, "0".repeat(64).as_str())
        .expect("certificate");

    assert!(certificate.method_detail.contains("SOFTWARE OVERWRITE"));
    assert!(certificate.method_detail.contains("not Purge"));
}

// ---------------------------------------------------------------------------
// The register
// ---------------------------------------------------------------------------

#[test]
fn the_register_detects_a_removed_certificate() {
    let dir = tempfile::tempdir().expect("tempdir");
    let register = dir.path().join("certificates.log");
    let key = cert::ephemeral_key().expect("key");

    let mut prev = cert::head(&register).expect("head");
    for _ in 0..3 {
        let f = fixture(256 * 1024);
        let clearance =
            safety::authorize(f.request(WipeMethod::NistClear), Some(&f.device)).expect("clears");
        let mut target = f.open();
        let outcome = engine::wipe(
            &mut target,
            &clearance,
            &engine::Progress::default(),
            &AtomicBool::new(false),
        )
        .expect("wipe");
        let report = verify::verify(&mut target, &outcome, &sample_options()).expect("verify");
        let certificate =
            cert::issue(&clearance, &outcome, &report, &key, &prev).expect("certificate");
        prev = cert::append(&register, &certificate, &key).expect("append");
    }

    let (_, problems) = cert::verify_register(&register).expect("verify");
    assert!(problems.is_empty(), "clean register reported {problems:?}");

    let text = std::fs::read_to_string(&register).expect("read");
    let kept: Vec<&str> = text
        .lines()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, l)| l)
        .collect();
    std::fs::write(&register, kept.join("\n") + "\n").expect("write");

    let (_, problems) = cert::verify_register(&register).expect("verify");
    assert!(
        problems.iter().any(|p| p.contains("hash chain broken")),
        "a removed certificate went undetected: {problems:?}"
    );
}
