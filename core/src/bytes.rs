//! Bounds-checked little-endian readers (the Paranoid Gatekeeper standard).
//!
//! btrfs is little-endian on disk throughout. Every reader yields `0` when the
//! requested range lies outside the buffer, so a malformed or truncated image
//! can never panic a parser. Callers that need to distinguish "field absent"
//! from "field is zero" bounds-check the buffer length up front and surface
//! [`crate::BtrfsError::Truncated`].

/// Read a little-endian `u16` at `off`, or `0` if out of range.
#[must_use]
pub fn le_u16(data: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    if let Some(s) = data.get(off..off + 2) {
        b.copy_from_slice(s);
    }
    u16::from_le_bytes(b)
}

/// Read a little-endian `u32` at `off`, or `0` if out of range.
#[must_use]
pub fn le_u32(data: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    if let Some(s) = data.get(off..off + 4) {
        b.copy_from_slice(s);
    }
    u32::from_le_bytes(b)
}

/// Read a little-endian `u64` at `off`, or `0` if out of range.
#[must_use]
pub fn le_u64(data: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    if let Some(s) = data.get(off..off + 8) {
        b.copy_from_slice(s);
    }
    u64::from_le_bytes(b)
}

/// Read a single byte at `off`, or `0` if out of range.
#[must_use]
pub fn u8_at(data: &[u8], off: usize) -> u8 {
    data.get(off).copied().unwrap_or(0)
}
