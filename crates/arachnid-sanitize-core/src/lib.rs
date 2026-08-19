//! Arachnid Sanitize — NIST SP 800-88 / DoD 5220.22-M secure erasure.
//!
//! Part of the Arachnid Forensic suite. **This crate destroys data.** Unlike
//! `arachnid-collect`, whose hard rule is that it never writes to the target,
//! every code path here exists to make a device unreadable. That inversion is
//! why the safety rails in this crate are structural rather than advisory.

pub mod pattern;
pub mod rng;

pub use pattern::WipeMethod;
