//! The overwrite engine: chunked, resumable, cancellable, and honest about
//! what it could not write.
//!
//! A wipe that aborts on the first bad sector leaves a mostly-readable disk and
//! no record of how far it got, which is the worst of both outcomes. So an I/O
//! error here records the failed region and moves on, and the certificate
//! carries the list. A disk that is failing outright still stops the job — see
//! [`CONSECUTIVE_FAILURE_LIMIT`] — because at that point the drive is not being
//! wiped, it is being waited on.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::pattern::PassPlan;
use crate::purge::{self, PurgeOutcome};
use crate::safety::Clearance;
use crate::target::WipeTarget;

/// Bytes per write call. Large enough that syscall overhead disappears against
/// media throughput, small enough that a cancel is noticed promptly and a single
/// I/O failure only costs this much of the range.
pub const CHUNK: usize = 4 * 1024 * 1024;

/// Failed chunks in a row before the job gives up. A drive that has refused
/// ~400 MiB of consecutive writes is not going to finish.
pub const CONSECUTIVE_FAILURE_LIMIT: u32 = 100;

/// Recorded bad regions before the list stops growing. The count keeps rising;
/// only the detail is capped, so a disk with millions of bad sectors cannot
/// exhaust memory through its own error log.
const MAX_RECORDED_REGIONS: usize = 1000;

/// Live counters for a running job, shared with whatever is drawing progress.
/// Mirrors `arachnid_netcap::Progress` so the TUI reads both the same way.
#[derive(Debug, Default)]
pub struct Progress {
    pub bytes_written: AtomicU64,
    pub bytes_total: AtomicU64,
    /// 1-based, so it reads as "pass 2 of 3" without adjustment.
    pub pass: AtomicU64,
    pub passes_total: AtomicU64,
    pub bad_regions: AtomicU64,
}

impl Progress {
    pub fn fraction(&self) -> f64 {
        let total = self.bytes_total.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        self.bytes_written.load(Ordering::Relaxed) as f64 / total as f64
    }

    /// Throughput-based estimate. `None` until enough has been written to make
    /// the number mean anything — an ETA computed off the first chunk is noise
    /// an operator will plan around.
    pub fn eta(&self, elapsed: Duration) -> Option<Duration> {
        let done = self.bytes_written.load(Ordering::Relaxed);
        let total = self.bytes_total.load(Ordering::Relaxed);
        if done < CHUNK as u64 * 4 || done >= total {
            return None;
        }
        let rate = done as f64 / elapsed.as_secs_f64().max(0.001);
        if rate <= 0.0 {
            return None;
        }
        Some(Duration::from_secs_f64((total - done) as f64 / rate))
    }

    pub fn throughput_bytes_per_sec(&self, elapsed: Duration) -> f64 {
        self.bytes_written.load(Ordering::Relaxed) as f64 / elapsed.as_secs_f64().max(0.001)
    }
}

/// A contiguous range the engine could not write.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BadRegion {
    pub offset: u64,
    pub length: u64,
    pub pass: u32,
    pub error: String,
}

/// What actually happened, as opposed to what was asked for. This is the struct
/// the certificate is built from, so every claim it makes has to be one the
/// engine observed rather than one the caller requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeOutcome {
    pub method: crate::pattern::WipeMethod,
    /// Which path ran. A `NistPurge` job that fell back to software says so here.
    pub purge_path: PurgeOutcome,
    pub passes: Vec<PassPlan>,
    pub bytes_written: u64,
    pub bytes_total: u64,
    pub started_utc: String,
    pub finished_utc: String,
    pub duration_secs: f64,
    /// Total failed chunks, which may exceed `bad_regions.len()`.
    pub bad_region_count: u64,
    pub bad_regions: Vec<BadRegion>,
    pub cancelled: bool,
    /// True when nothing was written because this was a dry run.
    pub dry_run: bool,
}

impl WipeOutcome {
    /// A wipe is only complete if every byte was written and nothing cancelled
    /// it. [`crate::verify`] refuses to certify anything else.
    pub fn complete(&self) -> bool {
        !self.dry_run
            && !self.cancelled
            && self.bad_region_count == 0
            && self.bytes_written >= self.bytes_total
    }
}

/// Estimate how long a job will take, for the confirmation screen.
///
/// Deliberately pessimistic: 80 MB/s for spinning-rust-era SATA unless the bus
/// suggests better. An operator who is told four hours and gets three is fine;
/// the reverse gets a drive unplugged mid-wipe.
pub fn estimate(clearance: &Clearance) -> Duration {
    use crate::device::BusType;
    let d = clearance.device();
    let passes = clearance.method().passes().len().max(1) as u64;
    let bytes_per_sec: u64 = match d.bus {
        BusType::Nvme => 1_200_000_000,
        BusType::Sata | BusType::Sas => 400_000_000,
        BusType::Scsi => 200_000_000,
        BusType::Usb => 80_000_000,
        BusType::Virtual | BusType::Unknown => 200_000_000,
    };
    if !clearance.method().is_overwrite() {
        return Duration::from_secs(1);
    }
    Duration::from_secs(d.size_bytes.saturating_mul(passes) / bytes_per_sec.max(1))
}

/// Run the wipe.
///
/// Takes a [`Clearance`] rather than a request, so there is no path into this
/// function that has not passed [`crate::safety::authorize`].
pub fn wipe(
    target: &mut dyn WipeTarget,
    clearance: &Clearance,
    progress: &Progress,
    cancel: &AtomicBool,
) -> Result<WipeOutcome> {
    let started = Instant::now();
    let started_utc = arachnid_evidence::now_utc();
    let method = clearance.method();
    let device = clearance.device();

    // Hardware purge first, where the method calls for it. The outcome is
    // recorded either way; a fallback that is not reported is a false claim.
    let purge_path = if method.tries_hardware_first() {
        purge::attempt(device)
    } else {
        PurgeOutcome::NotAttempted {
            capability: purge::probe(device),
        }
    };

    let passes = PassPlan::plan(method)?;
    let size = target.size()?;
    let total = size.saturating_mul(passes.len() as u64);

    progress.bytes_total.store(total, Ordering::Relaxed);
    progress.bytes_written.store(0, Ordering::Relaxed);
    progress
        .passes_total
        .store(passes.len() as u64, Ordering::Relaxed);
    progress.pass.store(0, Ordering::Relaxed);
    progress.bad_regions.store(0, Ordering::Relaxed);

    let finish = |bytes_written: u64,
                  bad_regions: Vec<BadRegion>,
                  bad_region_count: u64,
                  cancelled: bool| WipeOutcome {
        method,
        purge_path: purge_path.clone(),
        passes: passes.clone(),
        bytes_written,
        bytes_total: total,
        started_utc: started_utc.clone(),
        finished_utc: arachnid_evidence::now_utc(),
        duration_secs: started.elapsed().as_secs_f64(),
        bad_region_count,
        bad_regions,
        cancelled,
        dry_run: clearance.is_dry_run(),
    };

    if clearance.is_dry_run() {
        tracing::warn!(
            device = %device.path,
            method = method.label(),
            passes = passes.len(),
            bytes = total,
            "dry run: no bytes will be written"
        );
        return Ok(finish(0, Vec::new(), 0, false));
    }

    if purge_path.is_hardware() {
        // Unreachable in this build; kept so the software path is skipped
        // correctly the day the hardware path lands.
        return Ok(finish(total, Vec::new(), 0, false));
    }

    tracing::info!(
        device = %device.path,
        method = method.label(),
        passes = passes.len(),
        bytes = size,
        "starting overwrite"
    );

    let mut buf = vec![0u8; CHUNK];
    let mut bad_regions: Vec<BadRegion> = Vec::new();
    let mut bad_region_count = 0u64;
    let mut written = 0u64;

    for (index, plan) in passes.iter().enumerate() {
        progress.pass.store(index as u64 + 1, Ordering::Relaxed);
        let mut consecutive_failures = 0u32;
        let mut offset = 0u64;

        while offset < size {
            if cancel.load(Ordering::Relaxed) {
                tracing::warn!(
                    device = %device.path,
                    pass = index + 1,
                    offset,
                    "wipe cancelled; the device is now partially overwritten"
                );
                return Ok(finish(written, bad_regions, bad_region_count, true));
            }

            let len = CHUNK.min((size - offset) as usize);
            let chunk = &mut buf[..len];
            plan.fill(chunk, offset);

            match target.write_at(offset, chunk) {
                Ok(()) => {
                    consecutive_failures = 0;
                    written += len as u64;
                    progress.bytes_written.store(written, Ordering::Relaxed);
                }
                Err(e) => {
                    consecutive_failures += 1;
                    bad_region_count += 1;
                    progress
                        .bad_regions
                        .store(bad_region_count, Ordering::Relaxed);
                    if bad_regions.len() < MAX_RECORDED_REGIONS {
                        bad_regions.push(BadRegion {
                            offset,
                            length: len as u64,
                            pass: index as u32 + 1,
                            error: e.to_string(),
                        });
                    }
                    tracing::warn!(
                        device = %device.path,
                        pass = index + 1,
                        offset,
                        error = %e,
                        "write failed; recording bad region and continuing"
                    );
                    if consecutive_failures >= CONSECUTIVE_FAILURE_LIMIT {
                        anyhow::bail!(
                            "{} refused {} consecutive writes ending at offset {}; the device is \
                             failing and the wipe cannot complete. {} bad region(s) recorded.",
                            device.path,
                            consecutive_failures,
                            offset,
                            bad_region_count
                        );
                    }
                }
            }
            offset += len as u64;
        }

        // Per pass, not per chunk: the point is that pass N is on the media
        // before pass N+1 starts, so a crash cannot leave the passes reordered.
        target.flush()?;
        tracing::info!(device = %device.path, pass = index + 1, of = passes.len(), "pass complete");
    }

    Ok(finish(written, bad_regions, bad_region_count, false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{BusType, Device};
    use crate::pattern::WipeMethod;
    use crate::safety::{authorize, WipeRequest};
    use crate::target::FileBackedTarget;
    use std::io;
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
        .expect("test request should clear")
    }

    /// The core correctness claim: after a wipe, every byte on the device is the
    /// last pass's pattern, checked byte for byte rather than by sampling.
    #[test]
    fn nist_clear_zeroes_every_byte() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = CHUNK as u64 + 5000; // deliberately not chunk-aligned
        let mut t = FileBackedTarget::create(&path, size).unwrap();
        t.write_at(0, &[0xAA; 1024]).unwrap();

        let d = device(size);
        let c = clearance(&d, WipeMethod::NistClear, false);
        let outcome = wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(false)).unwrap();

        assert!(outcome.complete());
        assert_eq!(outcome.bytes_written, size);
        let written = std::fs::read(&path).unwrap();
        assert_eq!(written.len() as u64, size);
        assert!(written.iter().all(|&b| b == 0x00), "device is not all-zero");
    }

    /// DoD 3-pass ends on a random pass, so the final state must match the
    /// recorded seed exactly — which is what makes the pass verifiable at all.
    #[test]
    fn dod_3pass_leaves_the_recorded_random_stream() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = 300_000u64;
        let mut t = FileBackedTarget::create(&path, size).unwrap();

        let d = device(size);
        let c = clearance(&d, WipeMethod::Dod3Pass, false);
        let outcome = wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(false)).unwrap();

        assert_eq!(outcome.passes.len(), 3);
        let last = outcome.passes.last().unwrap();
        let mut expected = vec![0u8; size as usize];
        last.fill(&mut expected, 0);
        assert_eq!(std::fs::read(&path).unwrap(), expected);
    }

    #[test]
    fn progress_reaches_every_byte_of_every_pass() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = 200_000u64;
        let mut t = FileBackedTarget::create(&path, size).unwrap();

        let d = device(size);
        let c = clearance(&d, WipeMethod::Dod7Pass, false);
        let p = Progress::default();
        wipe(&mut t, &c, &p, &AtomicBool::new(false)).unwrap();

        assert_eq!(p.bytes_total.load(Ordering::Relaxed), size * 7);
        assert_eq!(p.bytes_written.load(Ordering::Relaxed), size * 7);
        assert_eq!(p.pass.load(Ordering::Relaxed), 7);
    }

    #[test]
    fn a_dry_run_writes_nothing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = 100_000u64;
        let mut t = FileBackedTarget::create(&path, size).unwrap();
        t.write_at(0, &[0x5A; 4096]).unwrap();
        t.flush().unwrap();
        let before = std::fs::read(&path).unwrap();

        let d = device(size);
        let c = clearance(&d, WipeMethod::Dod7Pass, true);
        let outcome = wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(false)).unwrap();

        assert!(outcome.dry_run);
        assert_eq!(outcome.bytes_written, 0);
        assert!(!outcome.complete(), "a dry run must never read as complete");
        assert_eq!(std::fs::read(&path).unwrap(), before, "dry run wrote bytes");
    }

    #[test]
    fn cancelling_stops_and_reports_partial() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = 50_000_000u64;
        let mut t = FileBackedTarget::create(&path, size).unwrap();

        let d = device(size);
        let c = clearance(&d, WipeMethod::NistClear, false);
        let cancel = AtomicBool::new(true); // cancelled before the first chunk
        let outcome = wipe(&mut t, &c, &Progress::default(), &cancel).unwrap();

        assert!(outcome.cancelled);
        assert!(!outcome.complete());
    }

    /// A target that fails a window of writes, to exercise the bad-sector path
    /// without needing a dying disk.
    struct FlakyTarget {
        inner: FileBackedTarget,
        fail_from: u64,
        fail_to: u64,
    }

    impl WipeTarget for FlakyTarget {
        fn size(&mut self) -> Result<u64> {
            self.inner.size()
        }
        fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
            if offset >= self.fail_from && offset < self.fail_to {
                return Err(io::Error::other("simulated medium error"));
            }
            self.inner.write_at(offset, buf)
        }
        fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
            self.inner.read_at(offset, buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.inner.flush()
        }
    }

    #[test]
    fn bad_sectors_are_recorded_and_do_not_abort_the_wipe() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = CHUNK as u64 * 6;
        let mut t = FlakyTarget {
            inner: FileBackedTarget::create(&path, size).unwrap(),
            fail_from: CHUNK as u64 * 2,
            fail_to: CHUNK as u64 * 3,
        };

        let d = device(size);
        let c = clearance(&d, WipeMethod::NistClear, false);
        let outcome = wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(false)).unwrap();

        assert_eq!(outcome.bad_region_count, 1);
        assert_eq!(outcome.bad_regions[0].offset, CHUNK as u64 * 2);
        assert_eq!(outcome.bad_regions[0].pass, 1);
        // It kept going and wrote everything else.
        assert_eq!(outcome.bytes_written, size - CHUNK as u64);
        // But a disk with an unwritten region is not a completed wipe.
        assert!(!outcome.complete());
    }

    #[test]
    fn a_totally_failing_device_stops_the_job() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = CHUNK as u64 * (CONSECUTIVE_FAILURE_LIMIT as u64 + 5);
        let mut t = FlakyTarget {
            inner: FileBackedTarget::create(&path, size).unwrap(),
            fail_from: 0,
            fail_to: size,
        };

        let d = device(size);
        let c = clearance(&d, WipeMethod::NistClear, false);
        let err = wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(false))
            .expect_err("a device refusing every write must fail the job");
        assert!(err.to_string().contains("consecutive writes"));
    }

    #[test]
    fn a_purge_job_records_that_it_fell_back_to_software() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("d.img");
        let size = 100_000u64;
        let mut t = FileBackedTarget::create(&path, size).unwrap();

        let d = device(size);
        let c = clearance(&d, WipeMethod::NistPurge, false);
        let outcome = wipe(&mut t, &c, &Progress::default(), &AtomicBool::new(false)).unwrap();

        assert!(
            !outcome.purge_path.is_hardware(),
            "this build performs no hardware purge, so it must not claim one"
        );
        assert_eq!(outcome.passes.len(), 3, "purge falls back to 3 passes");
    }
}
