//! Wipe methods and the exact overwrite pattern sequences they run.
//!
//! DoD 5220.22-M itself never fixed byte values — it specified "a character, its
//! complement, and a random pattern," and left the values to the implementer.
//! The sequence below follows the convention most wipe tools (Eraser, DBAN) ship
//! under that name, which is the one an auditor reading a certificate will
//! recognize. See the README compliance section for the citation.

use serde::{Deserialize, Serialize};

use crate::rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WipeMethod {
    /// NIST SP 800-88 Clear: one pass, fixed pattern.
    NistClear,
    /// NIST SP 800-88 Purge: hardware-backed erase, falling back to a multi-pass
    /// overwrite when the device supports no hardware purge command.
    NistPurge,
    Dod3Pass,
    Dod7Pass,
    /// Destroy the key of a self-encrypting drive, or of encryption this tool
    /// itself layered. No physical overwrite; see [`WipeMethod::is_overwrite`].
    CryptoErase,
}

impl WipeMethod {
    pub fn label(&self) -> &'static str {
        match self {
            WipeMethod::NistClear => "NIST SP 800-88 Clear",
            WipeMethod::NistPurge => "NIST SP 800-88 Purge",
            WipeMethod::Dod3Pass => "DoD 5220.22-M (3-pass)",
            WipeMethod::Dod7Pass => "DoD 5220.22-M (7-pass)",
            WipeMethod::CryptoErase => "Crypto-erase",
        }
    }

    /// What compliance regime this method's *software overwrite* path
    /// satisfies. [`WipeMethod::NistPurge`] additionally tries a hardware path
    /// first; see [`crate::engine::wipe`].
    pub fn explanation(&self) -> &'static str {
        match self {
            WipeMethod::NistClear => {
                "Single pass, fixed pattern. Meets NIST 800-88 Clear for media reused within \
                 the same organization; does not protect against lab-grade recovery."
            }
            WipeMethod::NistPurge => {
                "Tries a hardware-backed purge first (ATA Secure Erase, ATA Sanitize, or NVMe \
                 Format with crypto-erase). Falls back to a 3-pass software overwrite if the \
                 device supports none of those — the report states which path ran, because \
                 that materially changes the compliance claim."
            }
            WipeMethod::Dod3Pass => {
                "Character, complement, random — the short form of DoD 5220.22-M. Software \
                 overwrite only; slower than a hardware purge and gives no advantage over it."
            }
            WipeMethod::Dod7Pass => {
                "Seven alternating passes, the full DoD 5220.22-M ECE sequence. The most \
                 time-consuming method here; chosen for policies that require it by name."
            }
            WipeMethod::CryptoErase => {
                "Instant: destroys the encryption key rather than the data. Only as strong as \
                 the drive's (or this tool's) encryption — label certificates accordingly."
            }
        }
    }

    /// True when this method writes to the media itself (as opposed to
    /// [`WipeMethod::CryptoErase`], which destroys a key and touches no data).
    pub fn is_overwrite(&self) -> bool {
        !matches!(self, WipeMethod::CryptoErase)
    }

    /// True when this method's primary path is a hardware command rather than a
    /// software overwrite loop.
    pub fn tries_hardware_first(&self) -> bool {
        matches!(self, WipeMethod::NistPurge | WipeMethod::CryptoErase)
    }

    /// The pass sequence this method's *software* path runs. Empty for
    /// [`WipeMethod::CryptoErase`], which performs no overwrite.
    pub fn passes(&self) -> Vec<Pass> {
        match self {
            WipeMethod::NistClear => vec![Pass::Fixed(0x00)],
            // Software fallback for a Purge that found no hardware command.
            WipeMethod::NistPurge => vec![Pass::Fixed(0x00), Pass::Fixed(0xFF), Pass::Random],
            WipeMethod::Dod3Pass => vec![Pass::Fixed(0x00), Pass::Fixed(0xFF), Pass::Random],
            WipeMethod::Dod7Pass => vec![
                Pass::Random,
                Pass::Fixed(0x00),
                Pass::Fixed(0xFF),
                Pass::Random,
                Pass::Fixed(0x00),
                Pass::Fixed(0xFF),
                Pass::Random,
            ],
            WipeMethod::CryptoErase => vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Pass {
    Fixed(u8),
    Random,
}

impl Pass {
    /// Fill `buf` with this pass's content at absolute byte `offset` within the
    /// pass. For [`Pass::Random`], `seed` selects which reproducible stream —
    /// see [`crate::rng`] — so the exact same bytes can be recomputed at
    /// verification time.
    pub fn fill(&self, buf: &mut [u8], offset: u64, seed: &[u8; 32]) {
        match self {
            Pass::Fixed(b) => buf.fill(*b),
            Pass::Random => rng::fill_at(seed, offset, buf),
        }
    }
}

/// One concrete pass, with the seed it needs if it is [`Pass::Random`]. Built
/// once per job so every pass in the sequence — and later, verification — uses
/// the same seeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassPlan {
    pub pass: Pass,
    /// Hex-encoded; present only for [`Pass::Random`] passes.
    pub seed_hex: Option<String>,
}

impl PassPlan {
    pub fn plan(method: WipeMethod) -> anyhow::Result<Vec<PassPlan>> {
        method
            .passes()
            .into_iter()
            .map(|pass| {
                let seed_hex = match pass {
                    Pass::Random => Some(arachnid_evidence::hex(&rng::new_seed()?)),
                    Pass::Fixed(_) => None,
                };
                Ok(PassPlan { pass, seed_hex })
            })
            .collect()
    }

    pub fn fill(&self, buf: &mut [u8], offset: u64) {
        let seed = self
            .seed_hex
            .as_deref()
            .and_then(|h| arachnid_evidence::unhex(h).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .unwrap_or([0u8; 32]);
        self.pass.fill(buf, offset, &seed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dod_3pass_is_zero_ff_random() {
        let passes = WipeMethod::Dod3Pass.passes();
        assert_eq!(
            passes,
            vec![Pass::Fixed(0x00), Pass::Fixed(0xFF), Pass::Random]
        );
    }

    #[test]
    fn dod_7pass_is_the_full_ece_sequence() {
        let passes = WipeMethod::Dod7Pass.passes();
        assert_eq!(
            passes,
            vec![
                Pass::Random,
                Pass::Fixed(0x00),
                Pass::Fixed(0xFF),
                Pass::Random,
                Pass::Fixed(0x00),
                Pass::Fixed(0xFF),
                Pass::Random,
            ]
        );
    }

    #[test]
    fn nist_clear_is_a_single_zero_pass() {
        assert_eq!(WipeMethod::NistClear.passes(), vec![Pass::Fixed(0x00)]);
    }

    #[test]
    fn crypto_erase_writes_nothing() {
        assert!(WipeMethod::CryptoErase.passes().is_empty());
        assert!(!WipeMethod::CryptoErase.is_overwrite());
    }

    #[test]
    fn fixed_pass_fills_the_exact_byte() {
        let plan = PassPlan {
            pass: Pass::Fixed(0xAB),
            seed_hex: None,
        };
        let mut buf = [0u8; 37];
        plan.fill(&mut buf, 12345);
        assert!(buf.iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn random_pass_plans_are_independently_seeded() {
        let a = PassPlan::plan(WipeMethod::Dod3Pass).unwrap();
        let random_seeds: Vec<&str> = a.iter().filter_map(|p| p.seed_hex.as_deref()).collect();
        assert_eq!(random_seeds.len(), 1);
        assert_eq!(random_seeds[0].len(), 64); // 32 bytes, hex
    }
}
