//! btrfs superblock CRC32c verification.
//!
//! Every btrfs metadata block (the superblock, and every B-tree node in later
//! phases) carries a checksum in its first [`BTRFS_CSUM_SIZE`] = 32 bytes,
//! computed over the block **from just past the checksum field to the end of the
//! block** (`[csum_len_end .. block_len]`, where `csum_len_end = 0x20`). For the
//! default `crc32c` type the digest is 4 bytes stored little-endian in that
//! field; the remaining 28 bytes are zero padding.
//!
//! btrfs uses the Castagnoli/iSCSI CRC32c polynomial — the same
//! `CRC_32_ISCSI` algorithm the fleet's other readers use. The kernel seeds it
//! with `~0` and stores the finalized (complemented) digest little-endian, which
//! is exactly what `crc::Crc::<u32>::new(&crc::CRC_32_ISCSI).checksum()`
//! produces, so the computed value's LE bytes compare directly to the stored
//! bytes.
//!
//! Verification is **non-fatal**: a bad checksum never fails a parse; it is
//! surfaced as `crc_valid: Some(false)` so the `-forensic` layer can turn it
//! into a Finding (a forensic reader must still parse a tampered block and
//! report the mismatch). For a non-crc32c checksum type (`xxhash64` / `sha256` /
//! `blake2`) the status is deferred as `None` — those verifiers arrive with the
//! phases that need them.

/// `BTRFS_CSUM_SIZE` — the fixed checksum field width at the start of every
/// btrfs metadata block (32 bytes; the crc32c digest occupies the first 4).
pub const BTRFS_CSUM_SIZE: usize = 32;

/// The btrfs on-disk checksum-type codes (`btrfs_super_block.csum_type`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CsumType {
    /// `BTRFS_CSUM_TYPE_CRC32` (0) — crc32c, the mkfs default.
    Crc32c,
    /// `BTRFS_CSUM_TYPE_XXHASH` (1).
    Xxhash64,
    /// `BTRFS_CSUM_TYPE_SHA256` (2).
    Sha256,
    /// `BTRFS_CSUM_TYPE_BLAKE2` (3).
    Blake2,
    /// A checksum-type code this reader does not recognize — carries the raw
    /// on-disk value so an "unknown" report shows the offending datum.
    Unknown(u16),
}

impl CsumType {
    /// Decode the on-disk `csum_type` code.
    #[must_use]
    pub fn from_code(code: u16) -> Self {
        match code {
            0 => CsumType::Crc32c,
            1 => CsumType::Xxhash64,
            2 => CsumType::Sha256,
            3 => CsumType::Blake2,
            other => CsumType::Unknown(other),
        }
    }
}

/// The btrfs CRC32c parameters: Castagnoli polynomial, reflected in/out, init
/// and xorout `0xFFFFFFFF` — the `CRC_32_ISCSI` algorithm, whose finalized
/// digest equals the value btrfs stores on disk (little-endian). Constructing
/// the `Crc` is cheap (it references a static algorithm), so it is built per
/// call.
fn crc32c() -> crc::Crc<u32> {
    crc::Crc::<u32>::new(&crc::CRC_32_ISCSI)
}

/// Verify the btrfs superblock CRC32c over `block`.
///
/// The checksum covers `block[0x20 .. covered_len]` (from just past the 32-byte
/// checksum field to `covered_len`, which for the superblock is the sectorsize).
/// The computed crc32c's little-endian bytes are compared to the first four
/// bytes of the stored checksum field (`block[0..4]`).
///
/// Panic-free and bounds-checked: a block too short to hold the checksum field
/// or the covered range returns `false` (verification fails) rather than
/// panicking — a truncated/hostile block is a failed check, never a crash.
#[must_use]
pub fn verify_superblock_crc32c(block: &[u8], covered_len: usize) -> bool {
    // The stored digest occupies the first 4 bytes of the 32-byte csum field.
    let Some(stored_bytes) = block.get(0..4) else {
        return false;
    };
    let stored = [
        stored_bytes[0],
        stored_bytes[1],
        stored_bytes[2],
        stored_bytes[3],
    ];
    // The covered range is `[BTRFS_CSUM_SIZE .. covered_len]`. A block that does
    // not even reach past the checksum field cannot carry a valid checksum.
    if covered_len <= BTRFS_CSUM_SIZE {
        return false;
    }
    let Some(covered) = block.get(BTRFS_CSUM_SIZE..covered_len) else {
        return false;
    };
    let computed = crc32c().checksum(covered);
    computed.to_le_bytes() == stored
}

/// Compute the non-fatal CRC status for a superblock `block` of `covered_len`
/// (sectorsize) bytes: `Some(true|false)` when the checksum type is `crc32c`
/// (verified via [`verify_superblock_crc32c`]), or `None` for a non-crc32c type
/// whose verifier is deferred to a later phase.
#[must_use]
pub fn superblock_crc_status(
    csum_type: CsumType,
    block: &[u8],
    covered_len: usize,
) -> Option<bool> {
    match csum_type {
        CsumType::Crc32c => Some(verify_superblock_crc32c(block, covered_len)),
        _ => None,
    }
}

#[cfg(test)]
mod unit {
    use super::{superblock_crc_status, verify_superblock_crc32c, CsumType, BTRFS_CSUM_SIZE};

    #[test]
    fn csum_type_decodes_every_code() {
        assert_eq!(CsumType::from_code(0), CsumType::Crc32c);
        assert_eq!(CsumType::from_code(1), CsumType::Xxhash64);
        assert_eq!(CsumType::from_code(2), CsumType::Sha256);
        assert_eq!(CsumType::from_code(3), CsumType::Blake2);
        assert_eq!(CsumType::from_code(99), CsumType::Unknown(99));
    }

    #[test]
    fn verify_rejects_short_and_degenerate_blocks() {
        // Fewer than 4 bytes: cannot read the stored digest → false.
        assert!(!verify_superblock_crc32c(&[0u8; 3], 4096));
        // covered_len at or below the csum field: no covered range → false.
        assert!(!verify_superblock_crc32c(&[0u8; 64], BTRFS_CSUM_SIZE));
        // covered_len past the buffer end: covered slice out of range → false.
        assert!(!verify_superblock_crc32c(&[0u8; 40], 4096));
    }

    #[test]
    fn crc_status_is_none_for_non_crc32c_types() {
        let block = [0u8; 64];
        assert_eq!(superblock_crc_status(CsumType::Xxhash64, &block, 64), None);
        assert_eq!(superblock_crc_status(CsumType::Sha256, &block, 64), None);
        assert_eq!(superblock_crc_status(CsumType::Blake2, &block, 64), None);
        assert_eq!(
            superblock_crc_status(CsumType::Unknown(7), &block, 64),
            None
        );
    }
}
