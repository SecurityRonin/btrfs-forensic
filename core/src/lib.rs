//! `btrfs-core` — a pure-Rust, from-scratch btrfs filesystem reader.
//!
//! Phase 0 parses the **superblock** (at physical offset 65536) — geometry,
//! tree-root logical addresses, the checksum descriptor, and the
//! `sys_chunk_array` bootstrap chunk map that seeds logical→physical translation
//! — over any byte source. btrfs is little-endian on disk throughout.
//!
//! Import path is `btrfs_core` (the bare `btrfs` crate on crates.io is an
//! unrelated live-FS ioctl wrapper we do not shadow): `use btrfs_core::Superblock;`.
//!
//! # Safety and robustness
//!
//! This crate parses untrusted, attacker-controllable disk images. It is
//! `#![forbid(unsafe_code)]` and every integer is read through bounds-checked
//! little-endian helpers that yield `0`/`None` out of range rather than panic
//! (the Paranoid Gatekeeper standard).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod bytes;
mod chunk;
pub mod crc;
mod error;
mod superblock;

pub use chunk::{
    DiskKey, Stripe, SysChunk, BLOCK_GROUP_DATA, BLOCK_GROUP_DUP, BLOCK_GROUP_METADATA,
    BLOCK_GROUP_SYSTEM, CHUNK_ITEM_KEY, DISK_KEY_SIZE, STRIPE_SIZE, SYS_CHUNK_ARRAY_OFFSET,
};
pub use crc::{superblock_crc_status, verify_superblock_crc32c, CsumType, BTRFS_CSUM_SIZE};
pub use error::BtrfsError;
pub use superblock::{
    Superblock, BTRFS_FSID_SIZE, BTRFS_LABEL_SIZE, BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET,
    BTRFS_SUPER_INFO_SIZE,
};
