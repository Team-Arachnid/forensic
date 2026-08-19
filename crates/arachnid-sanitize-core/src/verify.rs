//! Read-back verification.
//!
//! Reading a whole multi-terabyte disk to confirm a wipe doubles the job's
//! duration, so this samples: the head and tail in full — where partition
//! tables, superblocks and journals live, and where a half-completed wipe shows
//! first — plus regions spread across the rest of the range.
//!
//! The comparison is exact, not statistical. Because a random pass is generated
//! from a recorded seed (see [`crate::rng`]), the expected bytes at any offset
//! can be recomputed, so "random pass" verification is a byte-for-byte match
//! rather than an entropy estimate. An entropy check cannot tell a wiped disk
//! from an encrypted one that was never touched; this can.

use serde::{Deserialize, Serialize};

use crate::engine::WipeOutcome;
use crate::target::WipeTarget;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyOptions {
    /// Bytes read in full from the start of the device.
    pub head_bytes: u64,
    /// Bytes read in full from the end of the device.
    pub tail_bytes: u64,
    /// Evenly spaced samples taken across the middle of the range.
    pub samples: u32,
    /// Bytes per spaced sample.
    pub sample_bytes: u64,
}

impl Default for VerifyOptions {
    fn default() -> Self {
        // 64 MiB of head and tail plus 256 spread samples: on a 1 TB drive this
        // reads ~192 MiB, a few seconds, and covers every structure that would
        // let a filesystem be reconstructed.
        VerifyOptions {
            head_bytes: 64 * 1024 * 1024,
            tail_bytes: 64 * 1024 * 1024,
            samples: 256,
            sample_bytes: 256 * 1024,
        }
    }
}

impl VerifyOptions {
    /// A fast profile for large drives under time pressure. Still covers the
    /// head and tail, which is where a failed wipe is visible.
    pub fn quick() -> Self {
        VerifyOptions {
            head_bytes: 16 * 1024 * 1024,
            tail_bytes: 16 * 1024 * 1024,
            samples: 32,
            sample_bytes: 64 * 1024,
        }
    }
}

/// One sampled region and what was found there.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sample {
    pub offset: u64,
    pub length: u64,
    pub ok: bool,
    /// Byte offset of the first mismatch within the device, when `ok` is false.
    pub first_mismatch_at: Option<u64>,
    /// The expected and observed bytes at the mismatch, hex, for the report.
    /// Short by design: an auditor needs the discrepancy, not the payload.
    pub expected_hex: Option<String>,
    pub observed_hex: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyReport {
    pub passed: bool,
    pub bytes_sampled: u64,
    pub device_size: u64,
    pub samples: Vec<Sample>,
    /// Why the whole verification failed, when it is not simply a bad sample.
    pub blocked: Option<String>,
}

impl VerifyReport {
    pub fn failures(&self) -> impl Iterator<Item = &Sample> {
        self.samples.iter().filter(|s| !s.ok)
    }

    /// Fraction of the device actually read back.
    pub fn coverage(&self) -> f64 {
        if self.device_size == 0 {
            return 0.0;
        }
        self.bytes_sampled as f64 / self.device_size as f64
    }
}

/// Bytes shown either side of a mismatch in the report.
const EXCERPT: usize = 16;

/// Read back sampled regions and compare them against what the last pass wrote.
///
/// Refuses outright — rather than reporting a pass — when the wipe it is being
/// asked to verify never completed. Certifying a sampled read of a cancelled
/// wipe would be the single easiest way to issue a certificate for a disk that
/// still holds data.
pub fn verify(
    target: &mut dyn WipeTarget,
    outcome: &WipeOutcome,
    options: &VerifyOptions,
) -> anyhow::Result<VerifyReport> {
    let size = target.size()?;

    let blocked = if outcome.dry_run {
        Some("dry run: nothing was written, so there is nothing to verify".to_string())
    } else if outcome.cancelled {
        Some(
            "the wipe was cancelled before completing; the device is only partially overwritten"
                .to_string(),
        )
    } else if outcome.bad_region_count > 0 {
        Some(format!(
            "{} region(s) could not be written; the device still holds data at those offsets",
            outcome.bad_region_count
        ))
    } else if outcome.purge_path.is_hardware() {
        // A hardware purge leaves no predictable pattern to compare against, so
        // pattern verification does not apply. Unreachable in this build.
        Some("hardware purge: no software pattern to read back".to_string())
    } else {
        None
    };

    if let Some(reason) = blocked {
        return Ok(VerifyReport {
            passed: false,
            bytes_sampled: 0,
            device_size: size,
            samples: Vec::new(),
            blocked: Some(reason),
        });
    }

    let Some(last) = outcome.passes.last() else {
        return Ok(VerifyReport {
            passed: false,
            bytes_sampled: 0,
            device_size: size,
            samples: Vec::new(),
            blocked: Some(
                "this method performs no overwrite, so there is no pattern to verify".into(),
            ),
        });
    };

    let mut samples = Vec::new();
    let mut bytes_sampled = 0u64;
    let mut buf = Vec::new();
    let mut expected = Vec::new();

    for (offset, length) in regions(size, options) {
        let len = length as usize;
        buf.resize(len, 0);
        expected.resize(len, 0);

        if let Err(e) = target.read_at(offset, &mut buf) {
            samples.push(Sample {
                offset,
                length,
                ok: false,
                first_mismatch_at: None,
                expected_hex: None,
                observed_hex: None,
                error: Some(e.to_string()),
            });
            continue;
        }
        last.fill(&mut expected, offset);
        bytes_sampled += length;

        let mismatch = buf.iter().zip(expected.iter()).position(|(a, b)| a != b);
        match mismatch {
            None => samples.push(Sample {
                offset,
                length,
                ok: true,
                first_mismatch_at: None,
                expected_hex: None,
                observed_hex: None,
                error: None,
            }),
            Some(i) => {
                let end = (i + EXCERPT).min(len);
                samples.push(Sample {
                    offset,
                    length,
                    ok: false,
                    first_mismatch_at: Some(offset + i as u64),
                    expected_hex: Some(arachnid_evidence::hex(&expected[i..end])),
                    observed_hex: Some(arachnid_evidence::hex(&buf[i..end])),
                    error: None,
                });
            }
        }
    }

    let passed = !samples.is_empty() && samples.iter().all(|s| s.ok);
    if !passed {
        tracing::error!(
            failures = samples.iter().filter(|s| !s.ok).count(),
            "verification failed; the device still holds recoverable data"
        );
    }

    Ok(VerifyReport {
        passed,
        bytes_sampled,
        device_size: size,
        samples,
        blocked: None,
    })
}

/// The regions to read: head, spaced middle samples, tail. Clamped and
/// deduplicated so a device smaller than the head+tail window is simply read in
/// full rather than producing overlapping or out-of-range reads.
fn regions(size: u64, o: &VerifyOptions) -> Vec<(u64, u64)> {
    if size == 0 {
        return Vec::new();
    }
    let head = o.head_bytes.min(size);
    let tail = o.tail_bytes.min(size - head);

    let mut out = vec![(0, head)];

    let middle_start = head;
    let middle_end = size - tail;
    if middle_end > middle_start && o.samples > 0 && o.sample_bytes > 0 {
        let span = middle_end - middle_start;
        let step = span / o.samples as u64;
        if step > 0 {
            for i in 0..o.samples as u64 {
                let offset = middle_start + i * step;
                let len = o.sample_bytes.min(middle_end - offset);
                if len > 0 {
                    out.push((offset, len));
                }
            }
        } else {
            // Device too small to space the samples out: read the middle whole.
            out.push((middle_start, span));
        }
    }
    if tail > 0 {
        out.push((size - tail, tail));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{BusType, Device};
    use crate::engine::{self, Progress};
    use crate::pattern::WipeMethod;
    use crate::safety::{authorize, Clearance, WipeRequest};
    use crate::target::FileBackedTarget;
    use std::sync::atomic::AtomicBool;
    use tempfile::tempdir;

    fn device(size: u64) -> Device {
        Device {
            path: "/dev/virtual".into(),
            model: "VIRTUAL".into(),
            serial: "VIRT-0001".into(),
            size_bytes: size,
            bus: BusType::Sata,
            removable: false,
            is_system: false,
            system_reason: None,
        }
    }

    fn clearance(d: &Device, method: WipeMethod, dry_run: bool) -> Clearance {
        authorize(
            WipeRequest {
                device: d.clone(),
                method,
                typed_serial: d.serial.clone(),
                force_system_volume: false,
                dry_run,
                operator: "tester".into(),
            },
            Some(d),
        )
        .unwrap()
    }

    fn opts() -> VerifyOptions {
        VerifyOptions {
            head_bytes: 4096,
            tail_bytes: 4096,
            samples: 8,
            sample_bytes: 512,
        }
    }

    #[test]
    fn a_real_wipe_verifies() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = 1_000_000u64;
        let mut t = FileBackedTarget::create(&path, size).unwrap();

        let d = device(size);
        let c = clearance(&d, WipeMethod::Dod3Pass, false);
        let outcome =
            engine::wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(false)).unwrap();

        let r = verify(&mut t, &outcome, &opts()).unwrap();
        assert!(r.passed, "failures: {:?}", r.failures().collect::<Vec<_>>());
        assert!(r.bytes_sampled > 0);
    }

    #[test]
    fn surviving_data_fails_verification_and_names_the_offset() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = 1_000_000u64;
        let mut t = FileBackedTarget::create(&path, size).unwrap();

        let d = device(size);
        let c = clearance(&d, WipeMethod::NistClear, false);
        let outcome =
            engine::wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(false)).unwrap();

        // A sector the wipe missed — exactly what verification exists to catch.
        t.write_at(1024, b"SECRET").unwrap();
        t.flush().unwrap();

        let r = verify(&mut t, &outcome, &opts()).unwrap();
        assert!(!r.passed);
        let f = r.failures().next().expect("a failing sample");
        assert_eq!(f.first_mismatch_at, Some(1024));
        assert!(f.observed_hex.as_deref().unwrap().starts_with("53")); // 'S'
    }

    #[test]
    fn a_dry_run_cannot_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let mut t = FileBackedTarget::create(&path, 100_000).unwrap();

        let d = device(100_000);
        let c = clearance(&d, WipeMethod::NistClear, true);
        let outcome =
            engine::wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(false)).unwrap();

        let r = verify(&mut t, &outcome, &opts()).unwrap();
        assert!(!r.passed);
        assert!(r.blocked.as_deref().unwrap().contains("dry run"));
    }

    #[test]
    fn a_cancelled_wipe_cannot_verify() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let mut t = FileBackedTarget::create(&path, 100_000).unwrap();

        let d = device(100_000);
        let c = clearance(&d, WipeMethod::NistClear, false);
        let outcome =
            engine::wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(true)).unwrap();

        let r = verify(&mut t, &outcome, &opts()).unwrap();
        assert!(!r.passed);
        assert!(r.blocked.as_deref().unwrap().contains("cancelled"));
    }

    #[test]
    fn regions_stay_inside_a_tiny_device() {
        let size = 1000u64;
        for (off, len) in regions(size, &VerifyOptions::default()) {
            assert!(off + len <= size, "region {off}+{len} runs past {size}");
        }
    }

    #[test]
    fn regions_cover_head_and_tail() {
        let size = 10_000_000u64;
        let r = regions(size, &opts());
        assert_eq!(r.first().unwrap().0, 0);
        let (last_off, last_len) = *r.last().unwrap();
        assert_eq!(last_off + last_len, size);
    }
}
