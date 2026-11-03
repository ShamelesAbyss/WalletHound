//! Cryptographic primitives and entropy encoders.
//!
//! Keccak-256 is the Ethereum hash. The `*_le` / `*_be` / `ascii*` helpers encode
//! deterministic entropy patterns into fixed 16-byte (128-bit) BIP39 entropy buffers.

use tiny_keccak::Hasher;

/// Keccak-256 (the Ethereum hash). Returns 32 bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = tiny_keccak::Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

/// An integer written little-endian into a 16-byte buffer.
pub fn u64_le(v: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&v.to_le_bytes());
    b
}

/// An integer written big-endian into a 16-byte buffer.
pub fn u64_be(v: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&v.to_be_bytes());
    b
}

/// An ASCII string padded/truncated to 16 bytes.
pub fn ascii16(s: &str) -> [u8; 16] {
    let mut b = [0u8; 16];
    let n = s.len().min(16);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b
}

/// True if `len` is a valid BIP39 entropy length in bytes.
pub fn valid_entropy_len(len: usize) -> bool {
    matches!(len, 11 | 12 | 16 | 20 | 24 | 28 | 32)
}
