//! `btrfs-core` — a pure-Rust, from-scratch btrfs filesystem reader.
//!
//! Phase 0 parses the **superblock** (at physical offset 65536) — geometry,
//! tree-root logical addresses, the checksum descriptor, and the
//! `sys_chunk_array` bootstrap chunk map that seeds logical→physical translation
//! — over any byte source. btrfs is little-endian on disk throughout.
//!
//! Phase 1 adds **B-tree node parsing and the chunk tree**: a [`Node`] decodes
//! any `nodesize`-byte block (`btrfs_header` + leaf items or interior
//! key-pointers, with non-fatal crc32c status), [`ChunkMap`] walks the chunk
//! tree into a full logical→physical map, and [`read_node`] reads any node by
//! its logical address.
//!
//! Phase 2 adds **root-tree navigation and FS-tree semantics**: [`fs_tree_root`]
//! locates the FS_TREE's `ROOT_ITEM` in the root tree, and [`read_inode`],
//! [`list_dir`], and [`read_by_path`] decode `btrfs_inode_item` metadata (size,
//! mode, the four timestamps), directory entries (`DIR_ITEM`/`DIR_INDEX`), and
//! resolve a slash-separated path from the FS_TREE root directory.
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
mod fstree;
mod node;
mod superblock;

pub use chunk::{
    DiskKey, Stripe, SysChunk, BLOCK_GROUP_DATA, BLOCK_GROUP_DUP, BLOCK_GROUP_METADATA,
    BLOCK_GROUP_SYSTEM, CHUNK_ITEM_KEY, DISK_KEY_SIZE, STRIPE_SIZE, SYS_CHUNK_ARRAY_OFFSET,
};
pub use crc::{superblock_crc_status, verify_superblock_crc32c, CsumType, BTRFS_CSUM_SIZE};
pub use error::BtrfsError;
pub use fstree::{
    fs_tree_root, list_dir, read_by_path, read_inode, DirEntry, DirItemType, FsTreeRoot, Inode,
    Timestamp, DIR_INDEX_KEY, DIR_ITEM_KEY, FS_TREE_OBJECTID, FS_TREE_ROOT_DIR_OBJECTID,
    INODE_ITEM_KEY, INODE_ITEM_SIZE, INODE_REF_KEY, ROOT_ITEM_KEY, TIMESTAMP_SIZE,
};
pub use node::{
    read_node, Chunk, ChunkMap, Header, KeyPtr, Node, BTRFS_HEADER_SIZE, BTRFS_ITEM_SIZE,
    BTRFS_KEY_PTR_SIZE, CHUNK_HEADER_SIZE, CHUNK_TREE_OBJECTID,
};
pub use superblock::{
    Superblock, BTRFS_FSID_SIZE, BTRFS_LABEL_SIZE, BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET,
    BTRFS_SUPER_INFO_SIZE,
};
