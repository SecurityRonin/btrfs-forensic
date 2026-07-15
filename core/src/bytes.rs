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

#[cfg(test)]
mod unit {
    use super::{le_u16, le_u32, le_u64, u8_at};

    #[test]
    fn readers_decode_little_endian_in_range() {
        let d = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(le_u16(&d, 0), 0x0201);
        assert_eq!(le_u32(&d, 0), 0x0403_0201);
        assert_eq!(le_u64(&d, 0), 0x0807_0605_0403_0201);
        assert_eq!(u8_at(&d, 3), 0x04);
    }

    #[test]
    fn readers_yield_zero_out_of_range() {
        assert_eq!(le_u16(&[0x12], 0), 0); // slice too short
        assert_eq!(le_u32(&[0, 0, 0], 0), 0);
        assert_eq!(le_u64(&[0, 0, 0, 0, 0, 0, 0], 0), 0);
        assert_eq!(u8_at(&[], 0), 0);
        assert_eq!(u8_at(&[0xAA], 5), 0);
    }
}
