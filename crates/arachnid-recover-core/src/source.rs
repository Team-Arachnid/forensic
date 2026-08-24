//! What recovery reads from — and the reason it is a separate trait from
//! `arachnid_sanitize_core::target::WipeTarget` rather than a reuse of it.
//!
//! [`Source`] has no `write_at`. Not "has one that returns an error", not "has
//! one guarded by a flag": the method does not exist, so no code path in this
//! crate can be written that writes to the evidence being recovered from, and
//! none can be added without changing this file. Sanitize's target trait is the
//! mirror image and the two must never converge.
//!
//! Every handle opened here is opened read-only at the OS level as well, so a
//! bug that got past the type system would still be refused by the kernel.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};

/// A byte-addressable, read-only view of media under examination.
///
/// `read_at` is allowed to return fewer bytes than asked for only at the end of
/// the source; callers that need an exact fill use [`Source::read_exact_at`].
pub trait Source: Send {
    fn size(&self) -> u64;
    /// Fill as much of `buf` as the source has from `offset`, returning how many
    /// bytes were read. A read wholly past the end returns `Ok(0)`.
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize>;

    /// Read exactly `len` bytes, or fail. Short reads near the tail of a
    /// truncated image are a real condition on damaged media, so this reports
    /// them rather than silently handing back a partly-zeroed buffer.
    fn read_exact_at(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let n = self.read_at(offset, &mut buf)?;
        if n != len {
            anyhow::bail!("short read at offset {offset}: wanted {len} bytes, got {n}");
        }
        Ok(buf)
    }

    /// Human label for the source, recorded in results so an analyst can tell
    /// which image or device a finding came from.
    fn label(&self) -> String;
}

/// A raw disk or partition image on disk: a `dd` capture, a Core acquisition,
/// or an artifact pulled out of an evidence container.
pub struct ImageSource {
    file: File,
    size: u64,
    label: String,
}

impl ImageSource {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path).with_context(|| format!("open image {}", path.display()))?;
        let size = file
            .metadata()
            .with_context(|| format!("stat {}", path.display()))?
            .len();
        Ok(ImageSource {
            file,
            size,
            label: path.display().to_string(),
        })
    }
}

impl Source for ImageSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= self.size {
            return Ok(0);
        }
        self.file.seek(SeekFrom::Start(offset))?;
        let want = buf.len().min((self.size - offset) as usize);
        let mut done = 0;
        while done < want {
            match self.file.read(&mut buf[done..want])? {
                0 => break,
                n => done += n,
            }
        }
        Ok(done)
    }

    fn label(&self) -> String {
        self.label.clone()
    }
}

/// An attached device, opened read-only.
///
/// Enumeration is `arachnid_sanitize_core::device::enumerate`, which is already
/// read-only and already computes the system-volume cross-reference; there is no
/// second implementation of it here. What this adds is a handle that cannot
/// write: `OpenOptions` is given `.read(true)` and never `.write(true)`, on both
/// platforms, so the OS refuses a write even if one were somehow issued.
pub struct DeviceSource {
    file: File,
    size: u64,
    path: String,
}

impl DeviceSource {
    pub fn open(path: &str) -> Result<Self> {
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .open(path)
            .with_context(|| {
                format!(
                    "open {path} read-only \
                     (needs Administrator on Windows, root on Linux)"
                )
            })?;
        // Seeking to the end is the one size query that works for a block device
        // on Linux and a \\.\PhysicalDriveN handle on Windows alike, without an
        // ioctl on either.
        let size = file
            .seek(SeekFrom::End(0))
            .with_context(|| format!("query size of {path}"))?;
        file.seek(SeekFrom::Start(0))?;
        Ok(DeviceSource {
            file,
            size,
            path: path.to_string(),
        })
    }
}

impl Source for DeviceSource {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if self.size > 0 && offset >= self.size {
            return Ok(0);
        }
        self.file.seek(SeekFrom::Start(offset))?;
        let mut done = 0;
        while done < buf.len() {
            match self.file.read(&mut buf[done..])? {
                0 => break,
                n => done += n,
            }
        }
        Ok(done)
    }

    fn label(&self) -> String {
        self.path.clone()
    }
}

/// An in-memory source, for tests and for the small synthetic images in
/// `test-fixtures/`. A real implementation of the trait, not a mock: the parsers
/// and the carver see exactly the same interface they see against a device.
pub struct MemorySource {
    bytes: Vec<u8>,
    label: String,
}

impl MemorySource {
    pub fn new(bytes: Vec<u8>, label: impl Into<String>) -> Self {
        MemorySource {
            bytes,
            label: label.into(),
        }
    }
}

impl Source for MemorySource {
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let Ok(start) = usize::try_from(offset) else {
            return Ok(0);
        };
        if start >= self.bytes.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.bytes.len() - start);
        buf[..n].copy_from_slice(&self.bytes[start..start + n]);
        Ok(n)
    }

    fn label(&self) -> String {
        self.label.clone()
    }
}

// ---------------------------------------------------------------------------
// Little-endian readers
// ---------------------------------------------------------------------------
//
// Every on-disk structure this crate parses — NTFS, ext4, APFS, and all the
// carved container formats bar a couple of big-endian fields — is little-endian.
// These return an Option rather than panicking on a short slice, because the
// slice usually came off damaged media and a truncated structure is data, not a
// bug.

pub fn u16le(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

pub fn u32le(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

pub fn u64le(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

pub fn u32be(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_source_reads_and_clamps() {
        let mut s = MemorySource::new(vec![1, 2, 3, 4], "t");
        assert_eq!(s.size(), 4);
        let mut buf = [0u8; 3];
        assert_eq!(s.read_at(2, &mut buf).unwrap(), 2);
        assert_eq!(&buf[..2], &[3, 4]);
        assert_eq!(s.read_at(9, &mut buf).unwrap(), 0);
        assert!(s.read_exact_at(2, 3).is_err());
    }

    #[test]
    fn image_source_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("img");
        std::fs::write(&p, b"abcdefgh").unwrap();
        let mut s = ImageSource::open(&p).unwrap();
        assert_eq!(s.size(), 8);
        assert_eq!(s.read_exact_at(3, 4).unwrap(), b"defg");
        assert_eq!(s.read_at(8, &mut [0u8; 4]).unwrap(), 0);
    }

    #[test]
    fn readers_refuse_to_run_off_the_end() {
        let b = [0x01u8, 0x02, 0x03];
        assert_eq!(u16le(&b, 0), Some(0x0201));
        assert_eq!(u32le(&b, 0), None);
        assert_eq!(u64le(&b, 0), None);
    }
}
