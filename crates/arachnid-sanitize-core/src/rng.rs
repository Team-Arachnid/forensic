//! A seeded, replayable byte stream for "random" wipe passes.
//!
//! A verification pass has to know what a random pass *should* look like at a
//! given offset. Capturing the whole pattern is not an option on a multi-terabyte
//! disk, so the seed is captured instead: [`stream_at`] reproduces the exact same
//! bytes at the exact same offset on demand, from a 32-byte seed no larger than
//! any other value already carried in the certificate. This turns verification of
//! a "random" pass into the same exact-match check used for a fixed-byte pass,
//! rather than an entropy heuristic that could not tell a wipe from a lucky guess.
//!
//! Not a CSPRNG in the security sense — nothing here is a secret, only a wipe
//! pattern — but it is seeded from the OS entropy source ([`new_seed`]) so two
//! jobs never coincidentally overwrite with the same bytes.

use anyhow::{Context, Result};

/// 32 bytes of OS entropy, hex-encoded in the certificate as the pass's seed.
pub fn new_seed() -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).context("gather entropy for wipe pattern seed")?;
    Ok(seed)
}

/// Fill `buf` with the deterministic byte stream for `seed` starting at byte
/// offset `offset` within that stream. Two calls with the same `seed` and
/// `offset` always produce the same bytes, regardless of chunk boundaries.
pub fn fill_at(seed: &[u8; 32], offset: u64, buf: &mut [u8]) {
    // splitmix64, keyed by the seed and the 8-byte-aligned word index. A cheap,
    // well-distributed generator is enough for a wipe pattern; cryptographic
    // strength would cost throughput this loop cannot spare on a large disk.
    let key = u64::from_le_bytes(seed[0..8].try_into().unwrap())
        ^ u64::from_le_bytes(seed[8..16].try_into().unwrap()).rotate_left(17)
        ^ u64::from_le_bytes(seed[16..24].try_into().unwrap()).rotate_left(33)
        ^ u64::from_le_bytes(seed[24..32].try_into().unwrap()).rotate_left(49);

    let start_word = offset / 8;
    let mut word_index = start_word;
    let mut written = 0usize;
    // Bytes before the first full word, when `offset` is not 8-aligned.
    let lead = (offset % 8) as usize;

    while written < buf.len() {
        let word = splitmix64(key.wrapping_add(word_index));
        let bytes = word.to_le_bytes();
        let src_start = if word_index == start_word { lead } else { 0 };
        for &b in &bytes[src_start..] {
            if written == buf.len() {
                break;
            }
            buf[written] = b;
            written += 1;
        }
        word_index += 1;
    }
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E3779B97F4A7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_and_offset_reproduces_bytes() {
        let seed = [7u8; 32];
        let mut a = [0u8; 100];
        let mut b = [0u8; 100];
        fill_at(&seed, 4096, &mut a);
        fill_at(&seed, 4096, &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn chunking_does_not_change_the_stream() {
        let seed = [3u8; 32];
        let mut whole = [0u8; 64];
        fill_at(&seed, 1000, &mut whole);

        let mut first = [0u8; 20];
        let mut second = [0u8; 44];
        fill_at(&seed, 1000, &mut first);
        fill_at(&seed, 1020, &mut second);

        let mut stitched = Vec::with_capacity(64);
        stitched.extend_from_slice(&first);
        stitched.extend_from_slice(&second);
        assert_eq!(&whole[..], &stitched[..]);
    }

    #[test]
    fn different_seeds_diverge() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        fill_at(&[1u8; 32], 0, &mut a);
        fill_at(&[2u8; 32], 0, &mut b);
        assert_ne!(a, b);
    }
}
