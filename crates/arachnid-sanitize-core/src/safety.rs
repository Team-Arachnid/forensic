//! The safety rails, and the only door through them.
//!
//! [`Clearance`] has no public constructor. The only way to obtain one is
//! [`authorize`], which runs every check below; [`crate::engine::wipe`] takes one
//! by reference and cannot be called without it. A future caller — a new CLI
//! subcommand, another TUI screen, a batch runner — therefore cannot reach the
//! write path without passing the same rails, because there is no other way to
//! build the token it needs.
//!
//! Each rail exists for a failure that has actually destroyed data in the field:
//!
//! - **System-volume block** — the operator wipes the machine they are standing at.
//! - **Typed serial** — the operator confirms a wipe while the selection is on
//!   the row above the one they were reading.
//! - **Re-enumeration check** — a USB drive is unplugged mid-session and a
//!   different one takes its path, so the confirmed serial and the device at
//!   that path are no longer the same drive.
//! - **Cooldown** — the operator holds Enter through a confirm they did not read.

use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::device::Device;
use crate::pattern::WipeMethod;

/// How long the final confirmation must be on screen before a keypress is
/// accepted. Long enough to break muscle memory, short enough that an operator
/// wiping a rack of drives does not start ignoring it.
pub const CONFIRM_COOLDOWN: Duration = Duration::from_secs(3);

/// A refusal to start a wipe. Every variant is a hard stop; the only one with an
/// override is [`Refusal::SystemVolume`], and it is deliberately not a boolean
/// on this type — the override lives in [`WipeRequest::force_system_volume`],
/// so declining it requires editing the request rather than ignoring an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    SystemVolume {
        path: String,
        reason: String,
    },
    /// The typed serial did not match the device's.
    SerialMismatch {
        expected: String,
        typed: String,
    },
    /// The device has no serial to confirm against, so the typed-serial rail
    /// cannot protect this wipe at all.
    NoSerial {
        path: String,
    },
    /// The device now at this path is not the one that was selected.
    DeviceChanged {
        path: String,
        selected: String,
        found: String,
    },
    /// Crypto-erase was asked for on a device that cannot do it.
    CryptoEraseUnsupported {
        path: String,
    },
    EmptyDevice {
        path: String,
    },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refusal::SystemVolume { path, reason } => write!(
                f,
                "{path} hosts the running operating system ({reason}). Wiping it will destroy \
                 the system you are working from. Pass --force-system-volume if that is genuinely \
                 what you intend."
            ),
            Refusal::SerialMismatch { expected, typed } => write!(
                f,
                "serial confirmation failed: you typed {typed:?}, the selected device reports \
                 {expected:?}. Nothing was written."
            ),
            Refusal::NoSerial { path } => write!(
                f,
                "{path} reports no serial number, so the typed-serial confirmation cannot \
                 identify it. This is common on USB bridges. Attach the drive over a direct \
                 SATA/NVMe connection, or wipe it from a host that can read its serial."
            ),
            Refusal::DeviceChanged {
                path,
                selected,
                found,
            } => write!(
                f,
                "{path} is no longer the device that was selected (selected {selected}, found \
                 {found}). A drive was probably unplugged and another attached. Re-enumerate and \
                 select again."
            ),
            Refusal::CryptoEraseUnsupported { path } => write!(
                f,
                "{path} does not report a crypto-erase capability. Choose an overwrite method, \
                 or verify the drive is a self-encrypting model."
            ),
            Refusal::EmptyDevice { path } => {
                write!(f, "{path} reports a size of zero bytes; nothing to wipe.")
            }
        }
    }
}

impl std::error::Error for Refusal {}

/// One device's wipe, fully specified. Built by the CLI or the TUI and handed to
/// [`authorize`]; there is no "wipe everything attached" shape it can express,
/// which is the no-bulk-select rail: a caller wanting several devices builds
/// several requests and confirms each one's serial separately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WipeRequest {
    pub device: Device,
    pub method: WipeMethod,
    /// What the operator typed when asked to confirm the device serial.
    pub typed_serial: String,
    /// Explicit acknowledgement that this device hosts the running OS.
    pub force_system_volume: bool,
    /// Walk the whole flow and report what would happen, writing nothing.
    pub dry_run: bool,
    pub operator: String,
}

/// Proof that every rail in [`authorize`] passed for one specific request.
///
/// Deliberately not `Clone` or `Copy`: a clearance is consumed by the wipe it
/// was issued for. Carrying one to a second device is exactly the mistake the
/// no-bulk-select rail exists to prevent.
#[derive(Debug)]
pub struct Clearance {
    request: WipeRequest,
    /// True when the operator overrode the system-volume block, so the
    /// certificate and the log can record that it happened.
    pub overrode_system_volume: bool,
}

impl Clearance {
    pub fn request(&self) -> &WipeRequest {
        &self.request
    }

    pub fn device(&self) -> &Device {
        &self.request.device
    }

    pub fn method(&self) -> WipeMethod {
        self.request.method
    }

    pub fn is_dry_run(&self) -> bool {
        self.request.dry_run
    }
}

/// Run every safety rail. Returns a [`Clearance`] only if all of them pass.
///
/// `present` is the device as found by a *fresh* enumeration at the moment of
/// confirmation, not the one cached when the operator made the selection. Pass
/// `None` when the device is no longer present at all.
pub fn authorize(request: WipeRequest, present: Option<&Device>) -> Result<Clearance, Refusal> {
    let d = &request.device;

    if d.size_bytes == 0 {
        return Err(Refusal::EmptyDevice {
            path: d.path.clone(),
        });
    }

    // Re-enumeration first: every check after this one is about a device, and
    // this is the check that the device is still the one being talked about.
    match present {
        Some(now) if now.identity() != d.identity() => {
            return Err(Refusal::DeviceChanged {
                path: d.path.clone(),
                selected: d.identity(),
                found: now.identity(),
            });
        }
        None => {
            return Err(Refusal::DeviceChanged {
                path: d.path.clone(),
                selected: d.identity(),
                found: "no device at this path".into(),
            });
        }
        Some(_) => {}
    }

    if d.serial.trim().is_empty() {
        return Err(Refusal::NoSerial {
            path: d.path.clone(),
        });
    }
    // Exact match, modulo surrounding whitespace only. Case folding a serial
    // would let "abc123" confirm a wipe of the drive labelled "ABC123", and
    // those are different drives on hosts that have both.
    if request.typed_serial.trim() != d.serial.trim() {
        return Err(Refusal::SerialMismatch {
            expected: d.serial.clone(),
            typed: request.typed_serial.trim().to_string(),
        });
    }

    let overrode_system_volume = d.is_system;
    if d.is_system && !request.force_system_volume {
        return Err(Refusal::SystemVolume {
            path: d.path.clone(),
            reason: d
                .system_reason
                .clone()
                .unwrap_or_else(|| "hosts a mounted system volume".into()),
        });
    }

    if request.method == WipeMethod::CryptoErase && !crate::purge::supports_crypto_erase(d) {
        return Err(Refusal::CryptoEraseUnsupported {
            path: d.path.clone(),
        });
    }

    Ok(Clearance {
        request,
        overrode_system_volume,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::BusType;

    fn device() -> Device {
        Device {
            path: "/dev/sdb".into(),
            model: "SAMSUNG MZ7LH".into(),
            serial: "S4EVNF0M12345".into(),
            size_bytes: 512 * 1024 * 1024,
            bus: BusType::Sata,
            removable: false,
            is_system: false,
            system_reason: None,
        }
    }

    fn request(d: Device) -> WipeRequest {
        WipeRequest {
            typed_serial: d.serial.clone(),
            device: d,
            method: WipeMethod::NistClear,
            force_system_volume: false,
            dry_run: false,
            operator: "tester".into(),
        }
    }

    #[test]
    fn a_matching_serial_clears() {
        let d = device();
        let r = request(d.clone());
        assert!(authorize(r, Some(&d)).is_ok());
    }

    #[test]
    fn a_mismatched_serial_is_refused() {
        let d = device();
        let mut r = request(d.clone());
        r.typed_serial = "S4EVNF0M12346".into();
        assert!(matches!(
            authorize(r, Some(&d)),
            Err(Refusal::SerialMismatch { .. })
        ));
    }

    #[test]
    fn serial_matching_is_case_sensitive() {
        let d = device();
        let mut r = request(d.clone());
        r.typed_serial = d.serial.to_lowercase();
        assert!(matches!(
            authorize(r, Some(&d)),
            Err(Refusal::SerialMismatch { .. })
        ));
    }

    #[test]
    fn surrounding_whitespace_is_forgiven() {
        let d = device();
        let mut r = request(d.clone());
        r.typed_serial = format!("  {}  ", d.serial);
        assert!(authorize(r, Some(&d)).is_ok());
    }

    #[test]
    fn a_system_device_is_blocked_without_the_force_flag() {
        let mut d = device();
        d.is_system = true;
        d.system_reason = Some("hosts /".into());
        let r = request(d.clone());
        assert!(matches!(
            authorize(r, Some(&d)),
            Err(Refusal::SystemVolume { .. })
        ));
    }

    #[test]
    fn the_force_flag_clears_a_system_device_and_is_recorded() {
        let mut d = device();
        d.is_system = true;
        let mut r = request(d.clone());
        r.force_system_volume = true;
        let c = authorize(r, Some(&d)).expect("force clears the block");
        assert!(c.overrode_system_volume);
    }

    #[test]
    fn the_force_flag_does_not_bypass_the_serial_check() {
        let mut d = device();
        d.is_system = true;
        let mut r = request(d.clone());
        r.force_system_volume = true;
        r.typed_serial = "wrong".into();
        assert!(matches!(
            authorize(r, Some(&d)),
            Err(Refusal::SerialMismatch { .. })
        ));
    }

    #[test]
    fn a_swapped_device_is_refused_even_with_the_right_serial() {
        let selected = device();
        let r = request(selected.clone());
        // Same path, different drive: the classic hot-plug reuse.
        let mut now = selected.clone();
        now.serial = "OTHER-DRIVE".into();
        now.model = "WD BLUE".into();
        assert!(matches!(
            authorize(r, Some(&now)),
            Err(Refusal::DeviceChanged { .. })
        ));
    }

    #[test]
    fn a_vanished_device_is_refused() {
        let d = device();
        let r = request(d.clone());
        assert!(matches!(
            authorize(r, None),
            Err(Refusal::DeviceChanged { .. })
        ));
    }

    #[test]
    fn a_device_without_a_serial_cannot_be_wiped() {
        let mut d = device();
        d.serial = String::new();
        let mut r = request(d.clone());
        r.typed_serial = String::new();
        assert!(matches!(
            authorize(r, Some(&d)),
            Err(Refusal::NoSerial { .. })
        ));
    }

    #[test]
    fn a_zero_size_device_is_refused() {
        let mut d = device();
        d.size_bytes = 0;
        let r = request(d.clone());
        assert!(matches!(
            authorize(r, Some(&d)),
            Err(Refusal::EmptyDevice { .. })
        ));
    }
}
