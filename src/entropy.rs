//! Deterministic entropy-pattern generators.
//!
//! IMPORTANT / honest framing:
//! These generators enumerate entropy values for two legitimate purposes only:
//!   1. Pipeline verification (proving derive->check->record works end to end).
//!   2. Reproducing a SPECIFIC documented wallet bug, where the entropy value is
//!      already known or strongly constrained (e.g. "this wallet wrote entropy=0").
//!
//! They are NOT a fund-finder. Enumerating entropy values without a specific,
//! documented reason does not recover funds: derived addresses are uniformly
//! distributed over an address space of ~2^160, so the chance of colliding with a
//! funded wallet is negligible. See README ("Why structured search does not hunt").

use crate::crypto;

/// One candidate entropy value plus a label describing how it was obtained.
#[derive(Clone)]
pub struct Candidate {
    /// The generator/source name (provenance), e.g. "explicit", "counter".
    pub generator: String,
    /// The raw BIP39 entropy bytes.
    pub entropy: Vec<u8>,
}

impl Candidate {
    pub fn new(generator: &str, entropy: Vec<u8>) -> Self {
        Candidate {
            generator: generator.to_string(),
            entropy,
        }
    }
}

/// Enumerate candidates for a named generator, bounded by `count`.
/// Only patterns with a concrete, reproducible meaning are included.
pub fn enumerate(name: &str, count: u64) -> Vec<Candidate> {
    match name {
        // entropy = all zero bytes. Reproduces wallets whose RNG wrote nothing.
        "zero" => {
            let mut v = Vec::new();
            if count > 0 {
                v.push(Candidate::new("zero", vec![0u8; 16]));
            }
            v
        }
        // entropy = i little-endian, i = 0..count. Reproduces sequential-counter wallets.
        "counter" => {
            let mut v = Vec::new();
            for i in 0..count {
                v.push(Candidate::new("counter", crypto::u64_le(i).to_vec()));
            }
            v
        }
        // entropy = i big-endian, i = 0..count.
        "counter_be" => {
            let mut v = Vec::new();
            for i in 0..count {
                v.push(Candidate::new("counter_be", crypto::u64_be(i).to_vec()));
            }
            v
        }
        // entropy last byte varies 0..255, rest zero. Reproduces truncated-low-entropy wallets.
        "low_byte" => {
            let mut v = Vec::new();
            for x in 0..=255u8 {
                let mut e = [0u8; 16];
                e[15] = x;
                v.push(Candidate::new("low_byte", e.to_vec()));
            }
            let _ = count;
            v
        }
        // entropy = repeated byte x across all 16 bytes.
        "repeated" => {
            let mut v = Vec::new();
            for x in 0..=255u8 {
                v.push(Candidate::new("repeated", vec![x; 16]));
            }
            let _ = count;
            v
        }
        // entropy from common ASCII phrases, padded to 16 bytes.
        "ascii" => {
            let words = [
                "password",
                "seed",
                "wallet",
                "123456",
                "hello",
                "test",
                "demo",
                "bitcoin",
                "monkey",
                "correct horse battery staple",
                "hunter",
                "hunter2",
                "qwerty",
                "111111",
                "alexa",
                "let me",
            ];
            let mut v = Vec::new();
            for w in &words {
                v.push(Candidate::new("ascii", crypto::ascii16(w).to_vec()));
            }
            let _ = count;
            v
        }
        // entropy = year as u64 little-endian. Reproduces birth-year style wallets.
        "year" => {
            let mut v = Vec::new();
            for y in 1900..=2010u32 {
                let e = crypto::u64_le(y as u64);
                v.push(Candidate::new("year", e.to_vec()));
            }
            let _ = count;
            v
        }
        _ => Vec::new(),
    }
}

/// Total number of candidates a generator would produce (unbounded => u64::max).
pub fn total(name: &str) -> u64 {
    match name {
        "zero" => 1,
        "counter" | "counter_be" => u64::max_value(),
        "low_byte" => 256,
        "repeated" => 256,
        "ascii" => 16,
        "year" => 111,
        _ => 0,
    }
}
