//! btrfs `sys_chunk_array` bootstrap chunk map (the P1 seed) — RED stub.
//!
//! Struct surface only; `SysChunk::parse_array` returns nothing and
//! `logical_to_physical` maps nothing until P0 is implemented (GREEN).

use crate::bytes::le_u64;

/// Offset of the `sys_chunk_array` within the superblock block.
pub const SYS_CHUNK_ARRAY_OFFSET: usize = 0x32b;

/// `btrfs_disk_key` on-disk size.
pub const DISK_KEY_SIZE: usize = 17;

/// `btrfs_stripe` on-disk size.
pub const STRIPE_SIZE: usize = 32;

/// `BTRFS_CHUNK_ITEM_KEY` — the disk-key type byte of a chunk item (228).
pub const CHUNK_ITEM_KEY: u8 = 228;

/// `BTRFS_BLOCK_GROUP_DATA` (1 << 0).
pub const BLOCK_GROUP_DATA: u64 = 1 << 0;
/// `BTRFS_BLOCK_GROUP_SYSTEM` (1 << 1).
pub const BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
/// `BTRFS_BLOCK_GROUP_METADATA` (1 << 2).
pub const BLOCK_GROUP_METADATA: u64 = 1 << 2;
/// `BTRFS_BLOCK_GROUP_DUP` (1 << 5).
pub const BLOCK_GROUP_DUP: u64 = 1 << 5;

/// A `btrfs_disk_key` — the `(objectid, type, offset)` tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskKey {
    /// `objectid`.
    pub objectid: u64,
    /// `type` byte.
    pub key_type: u8,
    /// `offset`.
    pub offset: u64,
}

/// One stripe of a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stripe {
    /// `devid`.
    pub devid: u64,
    /// physical `offset`.
    pub offset: u64,
    /// `dev_uuid`.
    pub dev_uuid: [u8; 16],
}

/// A decoded chunk map entry from the `sys_chunk_array`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysChunk {
    /// chunk item disk key.
    pub key: DiskKey,
    /// `length`.
    pub length: u64,
    /// `owner`.
    pub owner: u64,
    /// `stripe_len`.
    pub stripe_len: u64,
    /// `type` block-group flags.
    pub chunk_type: u64,
    /// `num_stripes`.
    pub num_stripes: u16,
    /// `sub_stripes`.
    pub sub_stripes: u16,
    /// decoded stripes.
    pub stripes: Vec<Stripe>,
}

impl SysChunk {
    /// RED stub — maps nothing.
    #[must_use]
    pub fn logical_to_physical(&self, _logical: u64) -> Option<u64> {
        None
    }

    /// RED stub — decodes nothing.
    #[must_use]
    pub fn parse_array(block: &[u8], _array_off: usize, _array_size: u32) -> Vec<SysChunk> {
        // Touch a reader so the module type-checks against `bytes`; returns empty.
        let _ = le_u64(block, 0);
        Vec::new()
    }
}
