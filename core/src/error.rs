//! Error types for the btrfs reader.

use thiserror::Error;

/// Errors surfaced while parsing btrfs on-disk structures.
///
/// Every variant names the offending value so an "unknown/invalid" report hands
/// the investigator the evidence (raw bytes / offset), never a bare "invalid".
#[derive(Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum BtrfsError {
    /// The buffer was too small to hold the structure being parsed.
    #[error("buffer too small for {structure}: need {need} bytes, have {have}")]
    Truncated {
        /// Name of the structure that could not be read.
        structure: &'static str,
        /// Minimum byte length required.
        need: usize,
        /// Byte length actually available.
        have: usize,
    },

    /// The superblock magic did not match `_BHRfS_M` at offset 0x40.
    ///
    /// Carries the eight bytes actually found so the caller can identify what the
    /// image really is (fail-loud with the offending value).
    #[error("bad btrfs magic: found bytes {bytes:02x?} at superblock offset 0x40, expected 5f42485266535f4d (\"_BHRfS_M\")")]
    BadMagic {
        /// The eight raw bytes read at superblock offset 0x40.
        bytes: [u8; 8],
    },
}
