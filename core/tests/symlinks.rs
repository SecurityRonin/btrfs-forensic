//! Symlink targets read from real btrfs-progs output.
//!
//! Fixture: `btrfs_symlink_leaf.bin`, the raw 16384-byte `FS_TREE` leaf of a
//! self-minted image built with `mkfs.btrfs --rootdir` (btrfs-progs v6.6.3,
//! sectorsize 4096). Provenance and the generator command are in
//! `tests/data/README.md`.
//!
//! Oracle: the targets passed to `ln -s` in the source directory, confirmed
//! with `os.readlink` there, and `btrfs inspect-internal dump-tree -t 5`
//! (committed as `btrfs_symlink.fs-tree.txt`):
//!
//! ```text
//! item 15 key (54002677 INODE_ITEM 0)  size 12 nbytes 13
//! item 17 key (54002677 EXTENT_DATA 0) inline extent data size 13 ram_bytes 13 compression 0 (none)
//! item 18 key (54002678 INODE_ITEM 0)  size 2003 nbytes 2004
//! item 20 key (54002678 EXTENT_DATA 0) inline extent data size 2004 ram_bytes 2004 compression 0 (none)
//! ```
//!
//! btrfs-progs stores a trailing NUL in the inline payload (13 bytes for a
//! 12-byte target); the inode size, not the payload, is the target length.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use btrfs_core::{read_symlink_from_leaf, BtrfsError, Node};

/// `short` -> `dir/file.txt`.
const SHORT_INO: u64 = 54_002_677;
/// `long` -> `d/` x 1000 then `end` (2003 bytes, half a sector).
const LONG_INO: u64 = 54_002_678;
/// The image's sectorsize (`btrfs inspect-internal dump-super`).
const SECTORSIZE: u32 = 4096;

fn symlink_leaf() -> Vec<u8> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // core/ -> repo root
    d.push("tests/data/btrfs_symlink_leaf.bin");
    std::fs::read(&d).unwrap_or_else(|e| panic!("read fixture {}: {e}", d.display()))
}

#[test]
fn real_symlink_targets_match_the_source_readlink() {
    let node = Node::parse(&symlink_leaf()).expect("leaf parses");
    assert_eq!(
        read_symlink_from_leaf(&node, SECTORSIZE, SHORT_INO).unwrap(),
        b"dir/file.txt"
    );
    let long = read_symlink_from_leaf(&node, SECTORSIZE, LONG_INO).unwrap();
    assert_eq!(long, format!("{}end", "d/".repeat(1000)).as_bytes());
}

#[test]
fn a_compressed_symlink_extent_is_refused_loud() {
    // btrfs_symlink always writes the target uncompressed. Mark the real
    // `short` extent zlib-compressed (compression byte = 1) in this leaf.
    // Leaf layout: a 0x65-byte header, then 25-byte items of key(17) +
    // data offset(4, relative to the header end) + data size(4).
    const HDR_END: usize = 0x65;
    let mut leaf = symlink_leaf();
    let nritems = u32::from_le_bytes(leaf[0x60..0x64].try_into().unwrap()) as usize;
    let data = (0..nritems)
        .map(|i| HDR_END + i * 25)
        .find(|&io| {
            u64::from_le_bytes(leaf[io..io + 8].try_into().unwrap()) == SHORT_INO
                && leaf[io + 8] == btrfs_core::EXTENT_DATA_KEY
        })
        .map(|io| HDR_END + u32::from_le_bytes(leaf[io + 17..io + 21].try_into().unwrap()) as usize)
        .expect("short has an EXTENT_DATA item");
    assert_eq!(leaf[data + 16], 0, "the real extent is uncompressed");
    leaf[data + 16] = 1; // compression byte
    let node = Node::parse(&leaf).expect("leaf parses");
    let err = read_symlink_from_leaf(&node, SECTORSIZE, SHORT_INO).unwrap_err();
    assert!(
        matches!(err, BtrfsError::InvalidSymlink { found: 1, .. }),
        "{err}"
    );
    assert!(err.to_string().contains("uncompressed"), "{err}");
}
