//! Storage device enumeration.
//!
//! Everything downstream trusts [`Device::is_system`], so it is computed the
//! expensive way on both platforms: by asking the OS which physical disks back
//! the volumes the running system is mounted from, not by guessing from a device
//! path or a drive number. A device the cross-reference cannot resolve is marked
//! system-hosting rather than left clear — for a destructive tool, "unsure" and
//! "yes" have to mean the same thing.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BusType {
    Sata,
    Nvme,
    Usb,
    Scsi,
    Sas,
    Virtual,
    Unknown,
}

impl BusType {
    pub fn label(&self) -> &'static str {
        match self {
            BusType::Sata => "SATA",
            BusType::Nvme => "NVMe",
            BusType::Usb => "USB",
            BusType::Scsi => "SCSI",
            BusType::Sas => "SAS",
            BusType::Virtual => "virtual",
            BusType::Unknown => "unknown",
        }
    }

    /// Whether a hardware purge command is plausible on this bus. USB bridges
    /// almost never pass ATA Secure Erase through, which is exactly the case
    /// where an operator most needs to be told the software fallback ran.
    pub fn may_support_hardware_purge(&self) -> bool {
        matches!(self, BusType::Sata | BusType::Nvme | BusType::Sas)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    /// OS path a wipe would open: `\\.\PhysicalDrive0`, `/dev/sda`.
    pub path: String,
    pub model: String,
    /// As reported by the device. May be empty on USB bridges that do not pass
    /// the inquiry through; [`crate::safety`] refuses to run a wipe when it is,
    /// because the typed-serial confirmation has nothing to match against.
    pub serial: String,
    pub size_bytes: u64,
    pub bus: BusType,
    pub removable: bool,
    /// True when this device hosts a volume the running OS is using, or when
    /// that could not be determined. Never false on a doubt.
    pub is_system: bool,
    /// Why `is_system` is set, for the operator to read before overriding it.
    pub system_reason: Option<String>,
}

impl Device {
    pub fn size_human(&self) -> String {
        if self.size_bytes == 0 {
            // Enumeration lists a device whose size it could not read rather
            // than hiding it; see the Windows enumerate().
            return "unknown".into();
        }
        human_bytes(self.size_bytes)
    }

    /// A stable identity for re-enumeration checks. Device paths get reused when
    /// a drive is unplugged and another plugged in, so a job that started
    /// against one drive must confirm it is still looking at the same one.
    pub fn identity(&self) -> String {
        format!("{}|{}|{}", self.model, self.serial, self.size_bytes)
    }
}

pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Enumerate every attached storage device.
///
/// Read-only. Devices that cannot be interrogated are skipped with a log line
/// rather than failing the whole enumeration: an operator with one unreadable
/// drive still needs to see the others.
pub fn enumerate() -> anyhow::Result<Vec<Device>> {
    sys::enumerate()
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
pub mod windows {
    use std::collections::BTreeSet;
    use std::fs::{File, OpenOptions};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;

    use anyhow::{Context, Result};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Storage::FileSystem::{
        BusTypeAta, BusTypeAtapi, BusTypeFileBackedVirtual, BusTypeNvme, BusTypeRAID, BusTypeSas,
        BusTypeSata, BusTypeScsi, BusTypeUsb, BusTypeVirtual,
    };
    use windows::Win32::System::Ioctl::{
        PropertyStandardQuery, StorageDeviceProperty, GET_LENGTH_INFORMATION,
        IOCTL_DISK_GET_LENGTH_INFO, IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_DEVICE_DESCRIPTOR,
        STORAGE_PROPERTY_QUERY,
    };
    use windows::Win32::System::IO::DeviceIoControl;

    use super::{BusType, Device};

    /// Physical drive numbers probed. Well past any realistic attached count;
    /// absent numbers fail to open and cost one syscall each.
    const MAX_DRIVES: u32 = 64;

    /// `CTL_CODE(IOCTL_VOLUME_BASE, 0, METHOD_BUFFERED, FILE_ANY_ACCESS)` from
    /// `winioctl.h`. The `windows` crate does not export this one, and the
    /// macro that builds it is a compile-time expression rather than a symbol.
    const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x0056_0000;

    /// Open a device path for querying only. Zero desired access is what lets an
    /// unprivileged operator *list* drives; the wipe path reopens for write.
    fn open_for_query(path: &str) -> Result<File> {
        OpenOptions::new()
            .access_mode(0)
            .share_mode(0x01 | 0x02) // FILE_SHARE_READ | FILE_SHARE_WRITE
            .open(path)
            .with_context(|| format!("open {path} for query"))
    }

    /// Reopen with read access, for the ioctls that will not accept a
    /// zero-access handle. Fails for an unprivileged operator, which is why
    /// nothing that calls this may treat the failure as "no such device".
    fn open_for_read(path: &str) -> Result<File> {
        OpenOptions::new()
            .read(true)
            .share_mode(0x01 | 0x02)
            .open(path)
            .with_context(|| format!("open {path} for read"))
    }

    fn handle(file: &File) -> HANDLE {
        HANDLE(file.as_raw_handle())
    }

    pub fn drive_size(file: &File) -> Result<u64> {
        let mut info = GET_LENGTH_INFORMATION::default();
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                handle(file),
                IOCTL_DISK_GET_LENGTH_INFO,
                None,
                0,
                Some(&mut info as *mut _ as *mut _),
                std::mem::size_of::<GET_LENGTH_INFORMATION>() as u32,
                Some(&mut returned),
                None,
            )
            .context("IOCTL_DISK_GET_LENGTH_INFO")?;
        }
        Ok(info.Length as u64)
    }

    /// Model, serial, bus type and removable flag from the storage descriptor.
    ///
    /// The descriptor is variable-length: the fixed header carries byte offsets
    /// into the same buffer for the ID strings, so the buffer has to be read
    /// back as raw bytes rather than as the struct alone.
    fn descriptor(file: &File) -> Result<(String, String, BusType, bool)> {
        let query = STORAGE_PROPERTY_QUERY {
            PropertyId: StorageDeviceProperty,
            QueryType: PropertyStandardQuery,
            AdditionalParameters: [0],
        };
        let mut buf = vec![0u8; 1024];
        let mut returned = 0u32;
        unsafe {
            DeviceIoControl(
                handle(file),
                IOCTL_STORAGE_QUERY_PROPERTY,
                Some(&query as *const _ as *const _),
                std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                Some(buf.as_mut_ptr() as *mut _),
                buf.len() as u32,
                Some(&mut returned),
                None,
            )
            .context("IOCTL_STORAGE_QUERY_PROPERTY")?;
        }

        let d = unsafe { &*(buf.as_ptr() as *const STORAGE_DEVICE_DESCRIPTOR) };
        let at = |offset: u32| -> String {
            if offset == 0 || offset as usize >= buf.len() {
                return String::new();
            }
            let start = offset as usize;
            let end = buf[start..]
                .iter()
                .position(|&b| b == 0)
                .map(|p| start + p)
                .unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[start..end]).trim().to_string()
        };

        let vendor = at(d.VendorIdOffset);
        let product = at(d.ProductIdOffset);
        let model = match (vendor.is_empty(), product.is_empty()) {
            (true, true) => "unknown".to_string(),
            (true, false) => product,
            (false, true) => vendor,
            (false, false) => format!("{vendor} {product}"),
        };

        let mut bus = match d.BusType {
            b if b == BusTypeNvme => BusType::Nvme,
            b if b == BusTypeSata || b == BusTypeAta || b == BusTypeAtapi => BusType::Sata,
            b if b == BusTypeUsb => BusType::Usb,
            b if b == BusTypeSas => BusType::Sas,
            b if b == BusTypeScsi || b == BusTypeRAID => BusType::Scsi,
            b if b == BusTypeVirtual || b == BusTypeFileBackedVirtual => BusType::Virtual,
            _ => BusType::Unknown,
        };
        // StorNVMe presents NVMe drives through StorPort, so the descriptor
        // frequently reports SCSI or RAID for what is really an NVMe device.
        // The bus decides which hardware purge command gets named on a
        // certificate, so correct it off the model string, which Microsoft's
        // driver prefixes with "NVMe". Only ever narrows SCSI/RAID/unknown --
        // it never overrides a bus the descriptor stated positively.
        if matches!(bus, BusType::Scsi | BusType::Unknown)
            && model.to_ascii_uppercase().starts_with("NVME")
        {
            bus = BusType::Nvme;
        }

        Ok((model, at(d.SerialNumberOffset), bus, d.RemovableMedia))
    }

    /// Physical drive numbers backing the volume that holds the Windows
    /// directory, plus every other fixed volume the OS has mounted.
    ///
    /// Errors are deliberately swallowed *upward*: a caller that gets an empty
    /// set from a failed probe must treat every drive as system-hosting, which
    /// is what [`enumerate`] does with the `Err` case.
    fn system_drive_numbers() -> Result<BTreeSet<u32>> {
        let mut out = BTreeSet::new();
        let windows_dir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let system_letter = windows_dir.chars().next().unwrap_or('C');

        // The system volume is mandatory; other volumes are best-effort, since a
        // drive letter can disappear between the enumeration and the open.
        let mut probed_system = false;
        for letter in 'A'..='Z' {
            let path = format!("\\\\.\\{letter}:");
            let Ok(file) = open_for_query(&path) else {
                continue;
            };
            match volume_disk_numbers(&file) {
                Ok(disks) => {
                    out.extend(disks);
                    if letter == system_letter {
                        probed_system = true;
                    }
                }
                Err(e) => {
                    // Failing to resolve the *system* volume is fatal to the
                    // whole cross-reference: see the bail below. Any other
                    // volume is a warning, because a card reader with no media
                    // fails here routinely.
                    tracing::debug!(volume = %path, error = %format!("{e:#}"), "no disk extents");
                }
            }
        }

        if !probed_system {
            anyhow::bail!("could not resolve the volume holding {windows_dir} to a physical disk");
        }
        Ok(out)
    }

    /// Every physical disk backing one volume.
    ///
    /// A striped or spanned volume sits on more than one disk, and the ioctl
    /// signals that by failing with `ERROR_MORE_DATA` after writing only the
    /// extent count. Retrying with a buffer sized to that count is what stops a
    /// second disk backing the system volume from being missed — and being
    /// missed here would mark it wipeable.
    fn volume_disk_numbers(file: &File) -> Result<Vec<u32>> {
        // DISK_EXTENT is { u32 DiskNumber; <4 pad>; i64 StartingOffset; i64 ExtentLength }.
        const EXTENT_SIZE: usize = 24;
        const HEADER_SIZE: usize = 8; // u32 count + 4 bytes padding before the array
        const ERROR_MORE_DATA: i32 = 234;

        let mut buf = vec![0u8; HEADER_SIZE + EXTENT_SIZE * 4];
        for attempt in 0..2 {
            let mut returned = 0u32;
            let result = unsafe {
                DeviceIoControl(
                    handle(file),
                    IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                    None,
                    0,
                    Some(buf.as_mut_ptr() as *mut _),
                    buf.len() as u32,
                    Some(&mut returned),
                    None,
                )
            };
            let count = u32::from_ne_bytes(buf[..4].try_into().expect("4 bytes")) as usize;

            if let Err(e) = result {
                // Grow to the reported count and try once more. A second
                // failure falls through to the error below rather than looping.
                if attempt == 0 && e.code().0 & 0xFFFF == ERROR_MORE_DATA && count > 0 {
                    buf = vec![0u8; HEADER_SIZE + EXTENT_SIZE * count];
                    continue;
                }
                return Err(e).context("IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS");
            }

            let available = (buf.len() - HEADER_SIZE) / EXTENT_SIZE;
            if count > available {
                // Should not happen once the retry has sized the buffer, but a
                // silent truncation here would under-report system disks.
                anyhow::bail!("volume reports {count} extents, buffer holds {available}");
            }
            return Ok((0..count)
                .map(|i| {
                    let at = HEADER_SIZE + i * EXTENT_SIZE;
                    u32::from_ne_bytes(buf[at..at + 4].try_into().expect("4 bytes"))
                })
                .collect());
        }
        anyhow::bail!("volume disk extents could not be read")
    }

    pub fn enumerate() -> Result<Vec<Device>> {
        // A failure here means we do not know which disk is the system disk, so
        // every disk is treated as one. Enumeration still succeeds: the operator
        // needs the list, and the force path is what unblocks a wipe.
        let (system, unresolved) = match system_drive_numbers() {
            Ok(s) => (s, false),
            Err(e) => {
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "could not map system volumes to physical disks; treating every disk as system-hosting"
                );
                (BTreeSet::new(), true)
            }
        };

        let mut out = Vec::new();
        for n in 0..MAX_DRIVES {
            let path = format!("\\\\.\\PhysicalDrive{n}");
            let Ok(file) = open_for_query(&path) else {
                continue;
            };
            // IOCTL_DISK_GET_LENGTH_INFO needs read access, which an
            // unprivileged operator does not have on a physical drive. Falling
            // back to a read handle keeps the listing complete for an
            // Administrator; failing that, the device is still listed with an
            // unknown size, because "you need to elevate" is a far more useful
            // answer than an empty device list. A zero size is refused by
            // `safety::authorize`, so an unsized device cannot be wiped.
            let size = drive_size(&file)
                .or_else(|_| open_for_read(&path).and_then(|f| drive_size(&f)))
                .unwrap_or_else(|e| {
                    tracing::warn!(
                        device = %path,
                        error = %format!("{e:#}"),
                        "size unavailable; listing the device without it (elevation required)"
                    );
                    0
                });
            let (model, serial, bus, removable) = descriptor(&file).unwrap_or_else(|e| {
                tracing::warn!(device = %path, error = %format!("{e:#}"), "storage descriptor unavailable");
                ("unknown".into(), String::new(), BusType::Unknown, false)
            });

            let is_system = unresolved || system.contains(&n);
            out.push(Device {
                path,
                model,
                serial,
                size_bytes: size,
                bus,
                removable,
                is_system,
                system_reason: is_system.then(|| {
                    if unresolved {
                        "system volumes could not be resolved to physical disks".into()
                    } else {
                        format!("hosts a volume mounted by the running OS (disk {n})")
                    }
                }),
            });
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Linux
// ---------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub mod linux {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;

    use anyhow::Result;

    use super::{BusType, Device};

    /// Mount points whose backing disk is, by definition, hosting the running
    /// OS. Deliberately broad: a wipe that takes out `/var` mid-flight has
    /// destroyed the running system just as thoroughly as one that takes `/`.
    const OS_MOUNTS: &[&str] = &["/", "/boot", "/boot/efi", "/usr", "/var", "/etc"];

    fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
        fs::read_to_string(path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }

    /// Kernel block devices that are not physical media.
    fn is_virtual(name: &str) -> bool {
        name.starts_with("loop")
            || name.starts_with("ram")
            || name.starts_with("zram")
            || name.starts_with("dm-")
            || name.starts_with("md")
            || name.starts_with("sr")
    }

    fn bus_for(name: &str) -> BusType {
        // The symlink under /sys/block encodes the transport in its path:
        // ../devices/pci0000:00/.../usb1/... or .../nvme/nvme0/nvme0n1
        let link = fs::read_link(format!("/sys/block/{name}"))
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        if name.starts_with("nvme") || link.contains("/nvme/") {
            BusType::Nvme
        } else if link.contains("/usb") {
            BusType::Usb
        } else if link.contains("/virtio") || name.starts_with("vd") {
            BusType::Virtual
        } else if link.contains("/ata") {
            BusType::Sata
        } else if link.contains("/sas") {
            BusType::Sas
        } else if link.contains("/scsi") || name.starts_with("sd") {
            BusType::Scsi
        } else {
            BusType::Unknown
        }
    }

    /// Resolve a `/proc/mounts` source to the `/sys/block` names it ultimately
    /// sits on, following partitions and device-mapper stacks.
    fn backing_disks(source: &str) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        let Some(name) = fs::canonicalize(source)
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
        else {
            return out;
        };

        // A device-mapper target (LUKS, LVM) names its members under slaves/.
        if name.starts_with("dm-") || name.starts_with("md") {
            if let Ok(slaves) = fs::read_dir(format!("/sys/block/{name}/slaves")) {
                for s in slaves.flatten() {
                    out.extend(backing_disks(&format!(
                        "/dev/{}",
                        s.file_name().to_string_lossy()
                    )));
                }
            }
            return out;
        }

        // A whole disk has its own /sys/block entry; a partition lives under its
        // parent's, so walking /sys/block and asking which one contains it is
        // the resolution step.
        if Path::new(&format!("/sys/block/{name}")).is_dir() {
            out.insert(name);
            return out;
        }
        if let Ok(blocks) = fs::read_dir("/sys/block") {
            for b in blocks.flatten() {
                let disk = b.file_name().to_string_lossy().to_string();
                if Path::new(&format!("/sys/block/{disk}/{name}")).is_dir() {
                    out.insert(disk);
                    return out;
                }
            }
        }
        out
    }

    fn system_disks() -> Result<BTreeSet<String>> {
        let mounts = fs::read_to_string("/proc/mounts")?;
        let mut out = BTreeSet::new();
        let mut saw_root = false;
        for line in mounts.lines() {
            let mut f = line.split_whitespace();
            let (Some(source), Some(target)) = (f.next(), f.next()) else {
                continue;
            };
            if !source.starts_with("/dev/") || !OS_MOUNTS.contains(&target) {
                continue;
            }
            if target == "/" {
                saw_root = true;
            }
            out.extend(backing_disks(source));
        }
        if !saw_root {
            anyhow::bail!("/proc/mounts lists no block device for /");
        }
        Ok(out)
    }

    pub fn enumerate() -> Result<Vec<Device>> {
        let (system, unresolved) = match system_disks() {
            Ok(s) => (s, false),
            Err(e) => {
                tracing::warn!(
                    error = %format!("{e:#}"),
                    "could not map mounts to block devices; treating every disk as system-hosting"
                );
                (BTreeSet::new(), true)
            }
        };

        let mut out = Vec::new();
        for entry in fs::read_dir("/sys/block")? {
            let name = entry?.file_name().to_string_lossy().to_string();
            if is_virtual(&name) {
                continue;
            }
            // /sys/block/<name>/size is in 512-byte sectors regardless of the
            // device's own logical sector size.
            let Some(sectors) =
                read_trimmed(format!("/sys/block/{name}/size")).and_then(|s| s.parse::<u64>().ok())
            else {
                tracing::warn!(device = %name, "skipping: unreadable size");
                continue;
            };
            if sectors == 0 {
                continue; // empty card reader slot
            }

            let is_system = unresolved || system.contains(&name);
            out.push(Device {
                path: format!("/dev/{name}"),
                model: read_trimmed(format!("/sys/block/{name}/device/model"))
                    .unwrap_or_else(|| "unknown".into()),
                serial: read_trimmed(format!("/sys/block/{name}/device/serial"))
                    .or_else(|| read_trimmed(format!("/sys/block/{name}/device/wwid")))
                    .or_else(|| read_trimmed(format!("/sys/block/{name}/wwid")))
                    .unwrap_or_default(),
                size_bytes: sectors * 512,
                bus: bus_for(&name),
                removable: read_trimmed(format!("/sys/block/{name}/removable")).as_deref()
                    == Some("1"),
                is_system,
                system_reason: is_system.then(|| {
                    if unresolved {
                        "mounts could not be resolved to block devices".into()
                    } else {
                        "backs a filesystem the running OS has mounted".into()
                    }
                }),
            });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }
}

#[cfg(windows)]
use windows as sys;

#[cfg(target_os = "linux")]
use linux as sys;

#[cfg(not(any(windows, target_os = "linux")))]
mod sys {
    use super::Device;

    pub fn enumerate() -> anyhow::Result<Vec<Device>> {
        anyhow::bail!("device enumeration is not implemented on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(serial: &str, size: u64) -> Device {
        Device {
            path: "/dev/sdz".into(),
            model: "TEST MODEL".into(),
            serial: serial.into(),
            size_bytes: size,
            bus: BusType::Sata,
            removable: false,
            is_system: false,
            system_reason: None,
        }
    }

    #[test]
    fn identity_changes_when_the_drive_does() {
        let a = dev("SN123", 500_000_000_000);
        let mut b = a.clone();
        b.serial = "SN999".into();
        assert_ne!(a.identity(), b.identity());

        let mut c = a.clone();
        c.size_bytes += 1;
        assert_ne!(a.identity(), c.identity());
    }

    #[test]
    fn human_bytes_scales() {
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1_099_511_627_776), "1.0 TiB");
    }

    #[test]
    fn usb_is_not_assumed_to_pass_through_hardware_purge() {
        assert!(!BusType::Usb.may_support_hardware_purge());
        assert!(BusType::Nvme.may_support_hardware_purge());
    }
}
