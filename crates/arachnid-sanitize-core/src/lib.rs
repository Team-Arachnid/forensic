//! Arachnid Sanitize — NIST SP 800-88 / DoD 5220.22-M secure erasure.
//!
//! Part of the Arachnid Forensic suite. **This crate destroys data.** Unlike
//! `arachnid-collect`, whose hard rule is that it never writes to the target,
//! every code path here exists to make a device unreadable.
//!
//! That inversion is why the safety rails are structural rather than advisory:
//!
//! - [`engine::wipe`] takes a [`safety::Clearance`], and the only way to build
//!   one is [`safety::authorize`], which runs every rail. There is no path to
//!   the write loop that skips them.
//! - [`cert::issue`] refuses to sign a certificate for a wipe that did not
//!   complete or did not verify, so an unverified erasure cannot be filed as a
//!   verified one.
//! - [`purge`] never claims a hardware purge this build did not perform; a
//!   fallback to software overwrite is stated on the certificate in terms an
//!   auditor cannot misread.
//! - A device whose system-volume status cannot be determined is reported as
//!   system-hosting. "Unsure" and "yes" mean the same thing here.
//!
//! The order of operations for a real job:
//!
//! ```no_run
//! # use arachnid_sanitize_core::*;
//! # fn main() -> anyhow::Result<()> {
//! let devices = device::enumerate()?;
//! let chosen = devices.first().expect("a device").clone();
//!
//! let request = safety::WipeRequest {
//!     device: chosen.clone(),
//!     method: pattern::WipeMethod::NistClear,
//!     typed_serial: chosen.serial.clone(), // the operator types this
//!     force_system_volume: false,
//!     dry_run: true,
//!     operator: "analyst@lab".into(),
//! };
//!
//! // Re-enumerate: the device at that path may not be the one selected.
//! let present = device::enumerate()?.into_iter().find(|d| d.path == chosen.path);
//! let clearance = safety::authorize(request, present.as_ref())?;
//!
//! let mut target = target::RawDeviceTarget::open(&chosen.path)?;
//! let progress = engine::Progress::default();
//! let cancel = std::sync::atomic::AtomicBool::new(false);
//! let outcome = engine::wipe(&mut target, &clearance, &progress, &cancel)?;
//! let report = verify::verify(&mut target, &outcome, &verify::VerifyOptions::default())?;
//! # Ok(())
//! # }
//! ```

pub mod cert;
pub mod device;
pub mod engine;
pub mod pattern;
pub mod purge;
pub mod rng;
pub mod safety;
pub mod target;
pub mod verify;

pub use device::{BusType, Device};
pub use pattern::WipeMethod;
pub use safety::{Clearance, Refusal, WipeRequest};

/// Default filename for the append-only certificate register.
pub const REGISTER_FILE: &str = "certificates.log";
