//! Btrfs extended attributes — `XATTR_ITEM` in the FS tree.
//!
//! Nothing in this crate read `XATTR_ITEM` before this test, so every Btrfs
//! image presented files with no extended attributes — indistinguishable from
//! files that have none, which on Linux silently drops `SELinux` labels,
//! capabilities and POSIX `ACLs`.
//!
//! ## The oracle is btrfs-progs
//!
//! `tests/data/btrfs_xattr_leaf.bin` is the raw 16384-byte `FS_TREE` leaf lifted
//! out of an image `mkfs.btrfs` created and the Linux btrfs driver populated
//! through a real mount. `btrfs inspect-internal dump-tree -t 5` listed every
//! item back:
//!
//! ``text
//! item 8  key (257 `XATTR_ITEM` 95888091)   itemsize 50    data_len 10   name_len 10  name: user.small
//! item 10 key (257 `XATTR_ITEM` 2425280219) itemsize 2038  data_len 2000 name_len 8   name: user.big
//! item 12 key (257 `XATTR_ITEM` 3817753667) itemsize 83    data_len 37   name_len 16  name: security.selinux
//! item 16 key (258 `XATTR_ITEM` 386189463)  itemsize 54    data_len 14   name_len 10  name: user.ondir
//! ``
//!
//! ## Two things Btrfs does differently, both load-bearing
//!
//! **The stored name is the FULL name.** `security.selinux`, not `selinux` plus
//! a namespace tag. ext4 and XFS both split the prefix off and require it to be
//! reconstructed; Btrfs does not, and inventing a prefix here would corrupt
//! every name.
//!
//! **An `XATTR_ITEM` is a `btrfs_dir_item`** — the same 30-byte structure a
//! directory entry uses, with the name followed by `data_len` value bytes. The
//! header length is confirmed by arithmetic that has to close:
//! `itemsize == 30 + name_len + data_len` for every item above (50 = 30+10+10,
//! 2038 = 30+8+2000, 83 = 30+16+37).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use btrfs_core::{list_xattrs, Node};

/// `file.txt` and `adir`, per `dump-tree`.
const FILE_OBJECTID: u64 = 257;
const DIR_OBJECTID: u64 = 258;

fn leaf() -> Vec<u8> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.push("tests/data/btrfs_xattr_leaf.bin");
    std::fs::read(&d).unwrap_or_else(|e| panic!("read fixture {}: {e}", d.display()))
}

/// Every attribute the kernel wrote must be listed, under its full name.
#[test]
fn xattr_items_are_listed_with_full_names() {
    let raw = leaf();
    let node = Node::parse(&raw).expect("fs tree leaf parses");
    let attrs = list_xattrs(&node, FILE_OBJECTID);

    // Non-zero baseline: an empty list would satisfy every lookup below.
    assert_eq!(
        attrs.len(),
        5,
        "dump-tree shows 5 XATTR_ITEMs on objectid 257: {attrs:?}"
    );

    let names: Vec<&str> = attrs.iter().map(|x| x.name.as_str()).collect();
    for want in [
        "user.small",
        "user.comment",
        "user.big",
        "trusted.t",
        // Btrfs stores this verbatim. A reader that split and rebuilt the
        // prefix would be doing work the format does not ask for.
        "security.selinux",
    ] {
        assert!(names.contains(&want), "missing {want}; got {names:?}");
    }
}

/// Values must come back byte-exact, including one too large to eyeball.
#[test]
fn values_are_byte_exact() {
    let raw = leaf();
    let node = Node::parse(&raw).unwrap();
    let attrs = list_xattrs(&node, FILE_OBJECTID);
    let get = |n: &str| -> Vec<u8> {
        attrs
            .iter()
            .find(|x| x.name == n)
            .unwrap_or_else(|| panic!("no attribute {n}"))
            .value
            .clone()
    };

    assert_eq!(get("user.small"), b"tiny-value");
    assert_eq!(get("user.comment"), b"a second attribute");
    assert_eq!(get("trusted.t"), b"trusted-value");
    // All 2000 bytes: the value starts at 30 + name_len, so an off-by-one in
    // the header length yields the right LENGTH shifted by one byte.
    assert_eq!(get("user.big"), vec![b'B'; 2000]);
}

/// Directories carry attributes, and one inode's must not leak into another's.
#[test]
fn attributes_are_scoped_to_their_own_inode() {
    let raw = leaf();
    let node = Node::parse(&raw).unwrap();
    let attrs = list_xattrs(&node, DIR_OBJECTID);

    let names: Vec<&str> = attrs.iter().map(|x| x.name.as_str()).collect();
    assert!(
        names.contains(&"user.ondir"),
        "adir must carry user.ondir; got {names:?}"
    );
    // The leaf holds both inodes' items interleaved, so a decoder that filtered
    // only on key_type would hand file.txt's attributes to the directory.
    assert!(
        !names.contains(&"user.small"),
        "objectid 258 must not inherit 257's attributes: {names:?}"
    );
}

/// An inode with no attributes lists nothing, and that is not an error.
#[test]
fn an_inode_without_attributes_lists_nothing() {
    let raw = leaf();
    let node = Node::parse(&raw).unwrap();
    assert!(
        list_xattrs(&node, 999_999).is_empty(),
        "an objectid with no XATTR_ITEMs yields an empty list"
    );
}
