//! Hardware-backed purge: what the device claims it can do, and what this build
//! will actually attempt.
//!
//! NIST 800-88 Purge is only a Purge if a hardware sanitize command ran. If it
//! did not and a software overwrite ran instead, the resulting certificate is a
//! Clear-grade claim wearing a Purge label — which is precisely the kind of
//! quiet downgrade an auditor is looking for. So this module never guesses:
//! [`probe`] reports a capability with a stated reason, [`attempt`] reports what
//! it actually did, and the certificate records the path verbatim.
//!
//! ISSUING the hardware command (ATA SECURITY ERASE UNIT, ATA SANITIZE, NVMe
//! FORMAT NVM with SES=1) is deliberately **not implemented in this build**. Each
//! requires vendor-quirk-laden pass-through I/O — `IOCTL_ATA_PASS_THROUGH_DIRECT`
//! and `IOCTL_STORAGE_PROTOCOL_COMMAND` on Windows, `SG_IO`/`NVME_IOCTL_ADMIN_CMD`
//! on Linux — where a malformed command can brick a drive into a frozen or
//! password-locked state that needs a vendor tool to recover. Shipping a
//! half-tested version of that is worse than not shipping it, so [`attempt`]
//! returns [`PurgeOutcome::NotAttempted`] and the caller falls back to the
//! documented software sequence, *and says so*.

use serde::{Deserialize, Serialize};

use crate::device::{BusType, Device};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PurgeCapability {
    /// The bus and device type make a hardware purge plausible, but this build
    /// does not issue it. Carries the command that *would* apply.
    PlausibleNotImplemented { command: String },
    /// The transport is known not to pass sanitize commands through reliably.
    UnsupportedTransport { reason: String },
}

impl PurgeCapability {
    pub fn describe(&self) -> String {
        match self {
            PurgeCapability::PlausibleNotImplemented { command } => format!(
                "{command} is the applicable hardware purge for this device, but this build does \
                 not issue hardware sanitize commands; a software overwrite will run instead"
            ),
            PurgeCapability::UnsupportedTransport { reason } => reason.clone(),
        }
    }
}

/// What the device's transport suggests, with the reason recorded either way.
pub fn probe(device: &Device) -> PurgeCapability {
    match device.bus {
        BusType::Nvme => PurgeCapability::PlausibleNotImplemented {
            command: "NVMe FORMAT NVM (SES=1, cryptographic erase)".into(),
        },
        BusType::Sata => PurgeCapability::PlausibleNotImplemented {
            command: "ATA SANITIZE (BLOCK ERASE) or ATA SECURITY ERASE UNIT".into(),
        },
        BusType::Sas | BusType::Scsi => PurgeCapability::PlausibleNotImplemented {
            command: "SCSI SANITIZE".into(),
        },
        BusType::Usb => PurgeCapability::UnsupportedTransport {
            reason: "USB bridges rarely pass ATA/NVMe sanitize commands through to the drive; \
                     treat any purge claim over USB with suspicion"
                .into(),
        },
        BusType::Virtual => PurgeCapability::UnsupportedTransport {
            reason: "virtual disk: the hypervisor, not this tool, owns the underlying media".into(),
        },
        BusType::Unknown => PurgeCapability::UnsupportedTransport {
            reason: "transport could not be identified, so no hardware purge command applies"
                .into(),
        },
    }
}

/// Whether a crypto-erase can be honestly claimed for this device.
///
/// Always false in this build: proving a drive is a working SED means reading
/// its TCG Opal/security feature set over the same pass-through path that
/// [`attempt`] does not implement. Claiming a crypto-erase we cannot verify
/// would be the single most dangerous false statement this tool could put on a
/// certificate — the operator believes the data is gone and it is not.
pub fn supports_crypto_erase(_device: &Device) -> bool {
    false
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PurgeOutcome {
    /// A hardware sanitize command completed. Not reachable in this build.
    HardwareCompleted { command: String },
    /// No hardware command was issued; the caller must fall back and report it.
    NotAttempted { capability: PurgeCapability },
}

impl PurgeOutcome {
    pub fn is_hardware(&self) -> bool {
        matches!(self, PurgeOutcome::HardwareCompleted { .. })
    }
}

/// Try the hardware purge path for `device`.
///
/// See the module docs: this build never issues the command, so the return is
/// always [`PurgeOutcome::NotAttempted`]. It is a function rather than a
/// constant so the fallback-and-report plumbing in [`crate::engine`] is written,
/// tested, and correct on the day the pass-through path lands.
pub fn attempt(device: &Device) -> PurgeOutcome {
    let capability = probe(device);
    tracing::info!(
        device = %device.path,
        capability = %capability.describe(),
        "hardware purge not issued by this build; falling back to software overwrite"
    );
    PurgeOutcome::NotAttempted { capability }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(bus: BusType) -> Device {
        Device {
            path: "/dev/sdb".into(),
            model: "m".into(),
            serial: "s".into(),
            size_bytes: 1024,
            bus,
            removable: false,
            is_system: false,
            system_reason: None,
        }
    }

    #[test]
    fn usb_is_reported_as_an_unsupported_transport() {
        assert!(matches!(
            probe(&dev(BusType::Usb)),
            PurgeCapability::UnsupportedTransport { .. }
        ));
    }

    #[test]
    fn nvme_names_the_command_it_would_use() {
        let PurgeCapability::PlausibleNotImplemented { command } = probe(&dev(BusType::Nvme))
        else {
            panic!("nvme should name a plausible command");
        };
        assert!(command.contains("NVMe FORMAT"));
    }

    /// The whole point of this module: no path in this build may report that a
    /// hardware purge happened, because no path in this build performs one.
    #[test]
    fn no_bus_reports_a_completed_hardware_purge() {
        for bus in [
            BusType::Sata,
            BusType::Nvme,
            BusType::Usb,
            BusType::Scsi,
            BusType::Sas,
            BusType::Virtual,
            BusType::Unknown,
        ] {
            assert!(
                !attempt(&dev(bus)).is_hardware(),
                "{bus:?} must not claim a hardware purge"
            );
        }
    }

    #[test]
    fn crypto_erase_is_never_claimed() {
        assert!(!supports_crypto_erase(&dev(BusType::Nvme)));
    }
}
