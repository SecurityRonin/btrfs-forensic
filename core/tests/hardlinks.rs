//! `INODE_REF` back-references — every name a btrfs inode is known by.
//!
//! Fixture: `btrfs_hardlink_leaf.bin`, the raw 16384-byte `FS_TREE` leaf of a
//! self-minted image built with `mkfs.btrfs --rootdir` (btrfs-progs v6.6.3),
//! which preserves hard links from the source directory.
//!
//! Oracle — `btrfs inspect-internal dump-tree -t 5`, committed verbatim beside
//! the fixture as `btrfs_hardlink.fs-tree.txt`:
//!
//! ```text
//! item 15 key (65011972 INODE_REF 256)      itemoff 15338 itemsize 42
//!         index 3 namelen 12 name: hardlink.txt
//!         index 5 namelen 10 name: target.txt
//! item 16 key (65011972 INODE_REF 65011971) itemoff 15313 itemsize 25
//!         index 2 namelen 15 name: second_name.txt
//! item 19 key (65011973 INODE_REF 256)      itemoff 15093 itemsize 19
//!         (plain.txt — a single-named file, the control)
//! ```
//!
//! Source link counts at mint time: `target.txt`, `hardlink.txt` and
//! `dir/second_name.txt` all `nlink=3 ino=65011716`; `plain.txt` `nlink=1`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use btrfs_core::{list_inode_refs, Node};

/// The hard-linked inode: three names, two parents.
const LINKED_INO: u64 = 65_011_972;
/// A single-named file in the same leaf.
const PLAIN_INO: u64 = 65_011_973;
/// The `FS_TREE` root directory objectid.
const ROOT_DIR: u64 = 256;
/// The `dir/` subdirectory that holds the third name.
const SUBDIR: u64 = 65_011_971;

fn hardlink_leaf() -> Vec<u8> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // core/ -> repo root
    d.push("tests/data/btrfs_hardlink_leaf.bin");
    std::fs::read(&d).unwrap_or_else(|e| panic!("read fixture {}: {e}", d.display()))
}

#[test]
fn a_hard_linked_inode_reports_every_name_with_its_parent_tier1() {
    let node = Node::parse(&hardlink_leaf()).expect("leaf parses");
    let refs = list_inode_refs(&node, LINKED_INO);

    let mut got: Vec<(u64, String)> = refs.iter().map(|r| (r.parent, r.name.clone())).collect();
    got.sort();

    assert_eq!(
        got,
        vec![
            (ROOT_DIR, "hardlink.txt".to_string()),
            (ROOT_DIR, "target.txt".to_string()),
            (SUBDIR, "second_name.txt".to_string()),
        ],
        "dump-tree reports three names across two parents"
    );
}

#[test]
fn two_names_packed_in_one_inode_ref_item_are_both_returned() {
    // The subtlety this fixture exists to catch: item 15 is a SINGLE item of
    // itemsize 42 holding TWO `btrfs_inode_ref` records (10 + 12, then 10 + 10).
    // A walk that stops after the first record silently drops `target.txt` --
    // reporting two links where the volume has three.
    let node = Node::parse(&hardlink_leaf()).expect("leaf parses");
    let mut in_root: Vec<String> = list_inode_refs(&node, LINKED_INO)
        .into_iter()
        .filter(|r| r.parent == ROOT_DIR)
        .map(|r| r.name)
        .collect();
    in_root.sort();
    assert_eq!(
        in_root,
        vec!["hardlink.txt".to_string(), "target.txt".to_string()],
        "both records inside the 42-byte item must be decoded"
    );
}

#[test]
fn a_singly_linked_file_reports_exactly_one_name() {
    // CONTROL. If this returned more than one name the walk would be running
    // past the item into a neighbour's bytes.
    let node = Node::parse(&hardlink_leaf()).expect("leaf parses");
    let refs = list_inode_refs(&node, PLAIN_INO);
    assert_eq!(refs.len(), 1, "expected one name, got {refs:?}");
    assert_eq!(refs[0].name, "plain.txt");
    assert_eq!(refs[0].parent, ROOT_DIR);
}

#[test]
fn an_inode_absent_from_the_leaf_yields_no_names() {
    // CONTROL. An objectid this leaf does not describe must return empty
    // rather than another inode's names -- a leaf interleaves many inodes.
    let node = Node::parse(&hardlink_leaf()).expect("leaf parses");
    assert!(list_inode_refs(&node, 999_999_999).is_empty());
}
