//! What a wipe writes to: a raw block device, or — for every test in this
//! crate and in CI — a plain file standing in for one.
//!
//! [`WipeTarget`] is the seam that keeps the pattern and safety-rail logic
//! testable without real hardware. [`FileBackedTarget`] is not a mock: it is a
//! real, byte-addressable target that the engine writes and reads through the
//! same trait a physical drive uses, so a test exercising it exercises the real
//! chunking, pass sequencing, and error-handling code paths.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;

use anyhow::{Context, Result};

/// A byte-addressable target a wipe can write to and a verification pass can
/// read back from. Never implicitly buffered: implementors are responsible for
/// making writes durable (see [`WipeTarget::flush`]), because a wipe that only
/// reaches the OS page cache is not a wipe.
pub trait WipeTarget: Send {
    fn size(&mut self) -> Result<u64>;
    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()>;
    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()>;
    fn flush(&mut self) -> io::Result<()>;
}

/// A regular file used as a stand-in block device. Real production use is
/// `--dry-run` output review and the crypto-erase key store; every wipe-pattern
/// and safety-rail test in this crate points a real [`crate::engine::wipe`] run
/// at one of these instead of a physical disk.
pub struct FileBackedTarget {
    file: File,
    size: u64,
}

impl FileBackedTarget {
    /// Create (or truncate) a file of exactly `size` bytes at `path`.
    pub fn create(path: &Path, size: u64) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("create virtual device file {}", path.display()))?;
        file.set_len(size)
            .with_context(|| format!("size virtual device file to {size} bytes"))?;
        Ok(FileBackedTarget { file, size })
    }

    /// Open an existing file as a virtual device, sized to its current length.
    pub fn open(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open virtual device file {}", path.display()))?;
        let size = file
            .metadata()
            .with_context(|| format!("stat {}", path.display()))?
            .len();
        Ok(FileBackedTarget { file, size })
    }
}

impl WipeTarget for FileBackedTarget {
    fn size(&mut self) -> Result<u64> {
        Ok(self.size)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.sync_data()
    }
}

/// A real physical drive, opened by OS device path (`\\.\PhysicalDriveN` on
/// Windows, `/dev/sdX` / `/dev/nvme0n1` on Linux).
///
/// KNOWN LIMITATION: opened without platform-specific unbuffered/direct I/O
/// (`FILE_FLAG_NO_BUFFERING` / `O_DIRECT`), which requires sector-aligned
/// buffers and offsets that this first cut does not yet guarantee everywhere a
/// chunk boundary can fall. Writes go through `flush` (`FlushFileBuffers` /
/// `fsync`) after every pass, so data reaches the media before verification
/// reads it back, but a read immediately after a write within the same pass
/// could in principle be served from a cache the drive's own firmware does not
/// see. Tracked in the README "Known limitations" section; closing this gap
/// means aligning every chunk and the tail short-read to the device's physical
/// sector size before it can be turned on unconditionally.
pub struct RawDeviceTarget {
    file: File,
    size: u64,
}

impl RawDeviceTarget {
    pub fn open(path: &str) -> Result<Self> {
        sys::open(path)
    }
}

impl WipeTarget for RawDeviceTarget {
    fn size(&mut self) -> Result<u64> {
        Ok(self.size)
    }

    fn write_at(&mut self, offset: u64, buf: &[u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(buf)
    }

    fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        self.file.seek(SeekFrom::Start(offset))?;
        self.file.read_exact(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.sync_all()
    }
}

#[cfg(windows)]
mod sys {
    use super::*;
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_WRITE_THROUGH;

    pub fn open(path: &str) -> Result<RawDeviceTarget> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_WRITE_THROUGH.0)
            .open(path)
            .with_context(|| format!("open device {path}"))?;
        let size = crate::device::windows::drive_size(&file)
            .with_context(|| format!("query size of {path}"))?;
        Ok(RawDeviceTarget { file, size })
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use super::*;
    use std::os::unix::fs::OpenOptionsExt;

    const O_SYNC: i32 = 0o4010000;

    pub fn open(path: &str) -> Result<RawDeviceTarget> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_SYNC)
            .open(path)
            .with_context(|| format!("open device {path}"))?;
        let size = file
            .seek(SeekFrom::End(0))
            .with_context(|| format!("query size of {path} via seek"))?;
        file.seek(SeekFrom::Start(0))?;
        Ok(RawDeviceTarget { file, size })
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod sys {
    use super::*;

    pub fn open(_path: &str) -> Result<RawDeviceTarget> {
        anyhow::bail!("raw device access is not implemented on this platform")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn file_backed_target_round_trips() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("virtual.img");
        let mut t = FileBackedTarget::create(&path, 4096).unwrap();
        assert_eq!(t.size().unwrap(), 4096);

        t.write_at(0, &[0xAA; 512]).unwrap();
        t.write_at(512, &[0xBB; 512]).unwrap();
        t.flush().unwrap();

        let mut buf = [0u8; 512];
        t.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, [0xAA; 512]);
        t.read_at(512, &mut buf).unwrap();
        assert_eq!(buf, [0xBB; 512]);
    }
}
