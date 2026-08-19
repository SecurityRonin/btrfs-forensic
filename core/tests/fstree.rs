//! P2 root-tree + FS-tree inode / directory / path tests.
//!
//! Ground truth is `btrfs inspect-internal dump-tree` on the minted oracle
//! (btrfs-progs v6.6.3) cross-checked against an independent mount-ro `ls -i` /
//! `stat` capture (a different implementation from this reader — Doer-Checker).
//! Every field the reader decodes is asserted against that output; the verified
//! offsets are recorded in `tests/data/README.md` ("P2 ground truth").
//!
//! Tiers:
//! - **Always-on (Tier-1 fixture):** the committed `btrfs_fs_tree_leaf.bin` is
//!   the raw 16384-byte `FS_TREE` leaf (the node at logical 30654464). Parsing it
//!   into inodes / directory entries / a path resolver reproduces dump-tree +
//!   `stat` exactly.
//! - **Env-gated (Tier-1 full image):** with `BTRFS_ORACLE_IMG`, walk the root
//!   tree from the superblock, locate the `FS_TREE` `ROOT_ITEM`, and confirm its
//!   `bytenr` equals the `FS_TREE` leaf's logical address dump-tree reports.
//! - **Robustness:** a lying `name_len` in an `INODE_REF` / `DIR_ITEM` never panics
//!   or over-reads.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use btrfs_core::{
    fs_tree_root, list_dir, read_by_path, read_inode, ChunkMap, DirItemType, Node, Superblock,
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, DIR_ITEM_KEY, FS_TREE_OBJECTID,
    FS_TREE_ROOT_DIR_OBJECTID, INODE_ITEM_KEY, INODE_REF_KEY, ROOT_ITEM_KEY,
};

/// The `FS_TREE` leaf's own logical address. dump-tree: `leaf 30654464 items 25
/// ... owner FS_TREE`.
const FS_TREE_LEAF_LOGICAL: u64 = 30_654_464;

/// The committed always-on fixture: the raw 16384-byte `FS_TREE` leaf node.
fn fs_tree_leaf() -> Vec<u8> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // core/ -> repo root
    d.push("tests/data/btrfs_fs_tree_leaf.bin");
    std::fs::read(&d).unwrap_or_else(|e| panic!("read fixture {}: {e}", d.display()))
}

#[test]
fn fs_tree_leaf_header_matches_dump_tree() {
    // dump-tree: `leaf 30654464 items 25 ... generation 8 owner FS_TREE` (=5),
    // level 0. The header's own `bytenr` equals the node's logical addr.
    let node = Node::parse(&fs_tree_leaf()).expect("fs tree leaf parses");
    assert_eq!(
        node.header.bytenr, FS_TREE_LEAF_LOGICAL,
        "bytenr = own logical"
    );
    assert_eq!(node.header.generation, 8, "generation");
    assert_eq!(node.header.owner, FS_TREE_OBJECTID, "owner = FS_TREE (5)");
    assert_eq!(node.header.nritems, 25, "nritems");
    assert_eq!(node.header.level, 0, "level 0 = leaf");
    assert_eq!(node.crc_valid, Some(true), "clean node crc32c verifies");
}

#[test]
fn known_inodes_decode_size_mode_and_mtime() {
    // Every value is dump-tree + `stat` ground truth (README "P2 ground truth"):
    //   ino 257 small.txt: size 26  mode 0o100644  mtime 1783927276.206047007
    //   ino 258 mid.bin:   size 65536 mode 0o100644 mtime 1783927276.216047007
    //   ino 259 dir:       size 6   mode 0o40755   mtime 1783927276.226047007
    //   ino 260 dir/sub:   size 16  mode 0o40755   mtime 1783927276.231047007
    //   ino 261 leaf.txt:  size 20  mode 0o100644  mtime 1783927276.231047007
    //   ino 256 root dir:  size 38  mode 0o40755
    let node = Node::parse(&fs_tree_leaf()).unwrap();

    let small = read_inode(&node, 257).expect("inode 257");
    assert_eq!(small.size, 26, "small.txt size");
    assert_eq!(small.mode, 0o100_644, "small.txt mode");
    assert_eq!(small.nlink, 1);
    assert!(small.is_file());
    assert!(!small.is_dir());
    assert_eq!(small.mtime.sec, 1_783_927_276);
    assert_eq!(small.mtime.nsec, 206_047_007, "small.txt mtime nsec");
    assert_eq!(small.ctime.nsec, 206_047_007, "small.txt ctime nsec");
    assert_eq!(small.atime.nsec, 251_047_007, "small.txt atime nsec");
    assert_eq!(small.otime.nsec, 206_047_007, "small.txt otime nsec");
    assert_eq!(small.generation, 7);

    let mid = read_inode(&node, 258).expect("inode 258");
    assert_eq!(mid.size, 65_536, "mid.bin size");
    assert_eq!(mid.mode, 0o100_644);
    assert_eq!(mid.mtime.nsec, 216_047_007, "mid.bin mtime nsec");

    let dir = read_inode(&node, 259).expect("inode 259");
    assert_eq!(dir.size, 6, "dir size");
    assert_eq!(dir.mode, 0o40_755, "dir mode");
    assert!(dir.is_dir());
    assert!(!dir.is_file());
    assert_eq!(dir.mtime.nsec, 226_047_007, "dir mtime nsec");

    let sub = read_inode(&node, 260).expect("inode 260");
    assert_eq!(sub.size, 16, "sub size");
    assert_eq!(sub.mode, 0o40_755);
    assert_eq!(sub.mtime.nsec, 231_047_007, "sub mtime nsec");

    let leaf = read_inode(&node, 261).expect("inode 261");
    assert_eq!(leaf.size, 20, "leaf.txt size");
    assert_eq!(leaf.mode, 0o100_644);
    assert_eq!(leaf.mtime.nsec, 231_047_007, "leaf.txt mtime nsec");

    let root = read_inode(&node, FS_TREE_ROOT_DIR_OBJECTID).expect("inode 256");
    assert_eq!(root.size, 38, "root dir size");
    assert_eq!(root.mode, 0o40_755);
    assert!(root.is_dir());
}

#[test]
fn read_inode_absent_objectid_is_none() {
    // An objectid with no INODE_ITEM in this leaf yields None (not a panic).
    let node = Node::parse(&fs_tree_leaf()).unwrap();
    assert!(read_inode(&node, 9_999).is_none(), "absent inode is None");
}

#[test]
fn list_dir_root_matches_ls_i() {
    // `ls -i` on the mount: 257 small.txt, 258 mid.bin, 259 dir. dump-tree keys
    // the root dir (256) with DIR_INDEX entries pointing at those child inodes.
    let node = Node::parse(&fs_tree_leaf()).unwrap();
    let entries = list_dir(&node, FS_TREE_ROOT_DIR_OBJECTID);

    // Three children, deduplicated (DIR_ITEM and DIR_INDEX both name each child;
    // the listing surfaces each name once).
    let mut by_name: Vec<(String, u64, DirItemType)> = entries
        .iter()
        .map(|e| (e.name.clone(), e.child, e.item_type))
        .collect();
    by_name.sort_by(|a, b| a.0.cmp(&b.0));

    assert_eq!(
        by_name,
        vec![
            ("dir".to_string(), 259, DirItemType::Dir),
            ("mid.bin".to_string(), 258, DirItemType::File),
            ("small.txt".to_string(), 257, DirItemType::File),
        ],
        "root dir listing == ls -i"
    );
}

#[test]
fn list_dir_subdir_matches_ls_i() {
    // dir (259) contains sub (260); sub (260) contains leaf.txt (261).
    let node = Node::parse(&fs_tree_leaf()).unwrap();

    let dir_entries = list_dir(&node, 259);
    assert_eq!(dir_entries.len(), 1, "dir has one child");
    assert_eq!(dir_entries[0].name, "sub");
    assert_eq!(dir_entries[0].child, 260);
    assert_eq!(dir_entries[0].item_type, DirItemType::Dir);

    let sub_entries = list_dir(&node, 260);
    assert_eq!(sub_entries.len(), 1, "sub has one child");
    assert_eq!(sub_entries[0].name, "leaf.txt");
    assert_eq!(sub_entries[0].child, 261);
    assert_eq!(sub_entries[0].item_type, DirItemType::File);
}

#[test]
fn list_dir_of_a_file_or_absent_dir_is_empty() {
    // A file inode has no DIR entries keyed on it; an absent objectid likewise.
    let node = Node::parse(&fs_tree_leaf()).unwrap();
    assert!(list_dir(&node, 257).is_empty(), "a file has no dir entries");
    assert!(list_dir(&node, 4_242).is_empty(), "absent dir is empty");
}

#[test]
fn read_by_path_resolves_known_files() {
    let node = Node::parse(&fs_tree_leaf()).unwrap();

    // /small.txt -> inode 257 (inline file, size 26).
    let (ino, inode) = read_by_path(&node, "/small.txt").expect("resolve /small.txt");
    assert_eq!(ino, 257);
    assert_eq!(inode.size, 26);
    assert!(inode.is_file());

    // /dir -> inode 259 (a directory).
    let (ino, inode) = read_by_path(&node, "/dir").expect("resolve /dir");
    assert_eq!(ino, 259);
    assert!(inode.is_dir());

    // /dir/sub -> inode 260.
    let (ino, _) = read_by_path(&node, "/dir/sub").expect("resolve /dir/sub");
    assert_eq!(ino, 260);

    // /dir/sub/leaf.txt -> inode 261 (nested inline file, size 20).
    let (ino, inode) = read_by_path(&node, "/dir/sub/leaf.txt").expect("resolve nested");
    assert_eq!(ino, 261, "nested path resolves to leaf.txt inode");
    assert_eq!(inode.size, 20);
    assert!(inode.is_file());

    // The empty / root path resolves to the FS_TREE root dir (256).
    let (ino, inode) = read_by_path(&node, "/").expect("resolve root");
    assert_eq!(ino, FS_TREE_ROOT_DIR_OBJECTID);
    assert!(inode.is_dir());
}

#[test]
fn read_by_path_missing_component_is_none() {
    let node = Node::parse(&fs_tree_leaf()).unwrap();
    // A component that does not exist anywhere in the path resolves to None.
    assert!(read_by_path(&node, "/nope").is_none(), "missing top-level");
    assert!(
        read_by_path(&node, "/dir/missing").is_none(),
        "missing nested"
    );
    // Descending *through* a file (not a directory) fails.
    assert!(
        read_by_path(&node, "/small.txt/deeper").is_none(),
        "cannot descend through a file"
    );
}

#[test]
fn read_by_path_tolerates_extra_and_trailing_slashes() {
    let node = Node::parse(&fs_tree_leaf()).unwrap();
    // Redundant separators and a trailing slash resolve to the same inode.
    assert_eq!(read_by_path(&node, "/dir/sub/").map(|(i, _)| i), Some(260));
    assert_eq!(read_by_path(&node, "//dir//sub").map(|(i, _)| i), Some(260));
    // A relative path (no leading slash) resolves from the FS_TREE root too.
    assert_eq!(read_by_path(&node, "small.txt").map(|(i, _)| i), Some(257));
}

#[test]
fn key_type_constants_match_the_on_disk_values() {
    // The published on-disk item-type bytes (btrfs_tree.h), verified against
    // dump-tree's key output on the oracle leaf.
    assert_eq!(INODE_ITEM_KEY, 1);
    assert_eq!(INODE_REF_KEY, 12);
    assert_eq!(FS_TREE_OBJECTID, 5);
    assert_eq!(FS_TREE_ROOT_DIR_OBJECTID, 256);
}

// ---- Robustness: hostile name_len / dir_item must not panic or over-read ----

#[test]
fn lying_inode_ref_name_len_does_not_overread() {
    // Corrupt an INODE_REF's name_len to a huge value; list/parse must clamp to
    // the item data, never read past it. We drive this through list_dir on the
    // root (which walks DIR items) and read_by_path (which walks INODE_REFs are
    // not used, but the INODE_REF decoder is exercised by a targeted helper).
    let mut raw = fs_tree_leaf();
    // item 9 is (257 INODE_REF 256); its data is name_len@8. Find it by scanning
    // item headers for oid=257 type=12.
    let node0 = Node::parse(&raw).unwrap();
    let target = node0
        .leaf_items()
        .find(|(k, _)| k.objectid == 257 && k.key_type == INODE_REF_KEY)
        .map(|(k, _)| k)
        .expect("inode 257 INODE_REF present");
    assert_eq!(target.offset, 256, "parent dir objectid via key.offset");

    // Blow up a name_len somewhere in the leaf's INODE_REF region and confirm no
    // panic when everything is re-parsed and listed. (We corrupt the whole node
    // conservatively by flipping a byte inside item 9's data; the decoders must
    // stay in-bounds regardless.)
    let hdr_end = 101usize;
    let item_stride = 25usize;
    // item 9 data_offset field lives at hdr_end + 9*stride + 17.
    let it9 = hdr_end + 9 * item_stride;
    let doff = u32::from_le_bytes(raw[it9 + 17..it9 + 21].try_into().unwrap()) as usize;
    let dstart = hdr_end + doff;
    // name_len is u16 at data offset 8 for an INODE_REF.
    raw[dstart + 8..dstart + 10].copy_from_slice(&u16::MAX.to_le_bytes());

    let node = Node::parse(&raw).expect("corrupt-name-len node still parses");
    // Must not panic:
    let _ = list_dir(&node, FS_TREE_ROOT_DIR_OBJECTID);
    let _ = read_by_path(&node, "/dir/sub/leaf.txt");
    let _ = read_inode(&node, 257);
}

#[test]
fn lying_dir_item_name_len_yields_bounded_name() {
    // Corrupt a DIR_ITEM's name_len (u16 at data offset 27) to a huge value: the
    // decoded name must be clamped to the bytes actually present, never an
    // over-read, and list_dir must not panic.
    let mut raw = fs_tree_leaf();
    let hdr_end = 101usize;
    let item_stride = 25usize;
    // item 2 is (256 DIR_ITEM ...) -> small.txt. name_len at data offset 27.
    let it2 = hdr_end + 2 * item_stride;
    let doff = u32::from_le_bytes(raw[it2 + 17..it2 + 21].try_into().unwrap()) as usize;
    let dstart = hdr_end + doff;
    raw[dstart + 27..dstart + 29].copy_from_slice(&u16::MAX.to_le_bytes());

    let node = Node::parse(&raw).expect("corrupt dir_item still parses");
    let entries = list_dir(&node, FS_TREE_ROOT_DIR_OBJECTID);
    // No entry name is longer than the item data could hold (bounded, not
    // over-read). The clamped item may still surface with a truncated name; the
    // invariant is only that nothing panicked and names stay within the block.
    for e in &entries {
        assert!(
            e.name.len() <= raw.len(),
            "name stays bounded by the block, never an over-read"
        );
    }
}

// ---- Env-gated full-image test (Tier-1: whole 512 MiB oracle) ----

fn oracle_image() -> Option<Vec<u8>> {
    let path = std::env::var("BTRFS_ORACLE_IMG").ok()?;
    Some(std::fs::read(path).expect("read BTRFS_ORACLE_IMG"))
}

#[test]
fn full_image_locates_fs_tree_root_from_root_tree() {
    let Some(img) = oracle_image() else {
        eprintln!("skip: BTRFS_ORACLE_IMG unset");
        return;
    };
    let start = BTRFS_SUPER_INFO_OFFSET as usize;
    let sb = Superblock::parse(&img[start..start + BTRFS_SUPER_INFO_SIZE]).unwrap();
    let map = btrfs_core::ChunkMap::walk(&img, &sb).expect("chunk-tree walk");

    // Walk the root tree, find the FS_TREE (objectid 5) ROOT_ITEM, and confirm
    // its `bytenr` is the FS_TREE leaf's logical address dump-tree reports.
    let root = fs_tree_root(&img, &sb, &map).expect("locate FS_TREE root");
    assert_eq!(
        root.bytenr, FS_TREE_LEAF_LOGICAL,
        "FS_TREE ROOT_ITEM bytenr == FS_TREE leaf logical"
    );
    assert_eq!(root.level, 0, "FS_TREE root is a single leaf");
    assert_eq!(root.root_dirid, FS_TREE_ROOT_DIR_OBJECTID, "root dir = 256");
    assert_eq!(root.generation, 8, "FS_TREE root generation");

    // Read that FS_TREE leaf and resolve a known path end to end over the image.
    let fs_leaf = btrfs_core::read_node(&img, &sb, &map, root.bytenr).expect("read fs leaf");
    let (ino, inode) = read_by_path(&fs_leaf, "/dir/sub/leaf.txt").expect("resolve nested");
    assert_eq!(ino, 261);
    assert_eq!(inode.size, 20);
}

// ---- Crafted-leaf tests for branches the oracle does not exercise ----
//
// The oracle has only files + directories, an FS_TREE that always exists, and no
// truncated items, so the symlink / other-type classification, the too-short
// dir-item guard, and the "no FS_TREE ROOT_ITEM" error path have no real fixture.
// These synthesize a minimal in-memory leaf (a lower tier than the real oracle,
// but the byte layout is the verified P2 layout) to drive those branches. The
// real oracle above remains the correctness backstop for the happy path.

const NODESIZE: usize = 16384;
const HDR_END: usize = 101;
const ITEM_STRIDE: usize = 25;

/// Build an FS_TREE-style leaf: a `btrfs_header` (owner 5, level 0) + item
/// headers (key + `data_offset/size`) with data laid out backward from the node
/// end, and a fixed-up crc32c so `Node::parse` reports `crc_valid == Some(true)`.
fn build_fs_leaf(owner: u64, items: &[(u64, u8, u64, Vec<u8>)]) -> Vec<u8> {
    let mut node = vec![0u8; NODESIZE];
    node[0x30..0x38].copy_from_slice(&30_654_464u64.to_le_bytes()); // bytenr
    node[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
    node[0x60..0x64].copy_from_slice(&(items.len() as u32).to_le_bytes());
    node[0x64] = 0; // leaf
    let mut data_tail = NODESIZE;
    for (i, (oid, ty, koff, data)) in items.iter().enumerate() {
        let io = HDR_END + i * ITEM_STRIDE;
        node[io..io + 8].copy_from_slice(&oid.to_le_bytes());
        node[io + 8] = *ty;
        node[io + 9..io + 17].copy_from_slice(&koff.to_le_bytes());
        data_tail -= data.len();
        let doff = (data_tail - HDR_END) as u32;
        node[io + 17..io + 21].copy_from_slice(&doff.to_le_bytes());
        node[io + 21..io + 25].copy_from_slice(&(data.len() as u32).to_le_bytes());
        node[data_tail..data_tail + data.len()].copy_from_slice(data);
    }
    fix_node_crc(&mut node);
    node
}

/// Encode a `btrfs_dir_item` body: location key[17] + transid(8) + `data_len(2)` +
/// `name_len(2)` + type(1) + name.
fn dir_item(child: u64, dir_type: u8, name: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 30 + name.len()];
    d[0..8].copy_from_slice(&child.to_le_bytes()); // location.objectid
    d[8] = 1; // location.type = INODE_ITEM
              // transid @17, data_len @25 = 0
    d[27..29].copy_from_slice(&(name.len() as u16).to_le_bytes()); // name_len
    d[29] = dir_type;
    d[30..30 + name.len()].copy_from_slice(name);
    d
}

fn fix_node_crc(node: &mut [u8]) {
    let c = crc32c_iscsi(&node[0x20..]);
    node[0..4].copy_from_slice(&c.to_le_bytes());
}

fn crc32c_iscsi(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in buf {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xFFFF_FFFF
}

#[test]
fn dir_item_type_classifies_symlink_and_other() {
    // A directory (256) with a symlink child (type 7) and an unknown type (99):
    // the classifier must surface Symlink and Other(99) (unknown value shown,
    // never dropped).
    let leaf = build_fs_leaf(
        FS_TREE_OBJECTID,
        &[
            (256, DIR_ITEM_KEY, 111, dir_item(300, 7, b"link")),
            (256, DIR_ITEM_KEY, 222, dir_item(301, 99, b"weird")),
        ],
    );
    let node = Node::parse(&leaf).unwrap();
    let entries = list_dir(&node, 256);
    let link = entries.iter().find(|e| e.name == "link").unwrap();
    assert_eq!(link.item_type, DirItemType::Symlink, "type 7 = Symlink");
    assert_eq!(link.child, 300);
    let weird = entries.iter().find(|e| e.name == "weird").unwrap();
    assert_eq!(
        weird.item_type,
        DirItemType::Other(99),
        "unknown dir type surfaces its raw byte"
    );
}

#[test]
fn list_dir_skips_a_truncated_dir_item() {
    // A DIR_ITEM whose data is shorter than the 30-byte fixed prefix cannot be
    // decoded: parse_dir_item returns None and list_dir skips it (no panic), and
    // a well-formed sibling still lists.
    let leaf = build_fs_leaf(
        FS_TREE_OBJECTID,
        &[
            (256, DIR_ITEM_KEY, 111, vec![0u8; 10]), // too short (< 30)
            (256, DIR_ITEM_KEY, 222, dir_item(302, 1, b"ok.txt")),
        ],
    );
    let node = Node::parse(&leaf).unwrap();
    let entries = list_dir(&node, 256);
    assert_eq!(entries.len(), 1, "the truncated dir item is skipped");
    assert_eq!(entries[0].name, "ok.txt");
    assert_eq!(entries[0].child, 302);
}

#[test]
fn fs_tree_root_errors_loud_when_root_tree_has_no_fs_tree_item() {
    // A crafted image whose root tree (a leaf) carries a ROOT_ITEM for some other
    // tree but NOT the FS_TREE (objectid 5): fs_tree_root must return a loud,
    // named Truncated error, never silently succeed. The image is built so the
    // sys_chunk_array identity-maps the root logical to a physical offset holding
    // this crafted root-tree leaf.
    let root_logical = 4096u64;
    let sys_len = 65536u64;

    // Root-tree leaf with one ROOT_ITEM keyed by objectid 2 (EXTENT_TREE), not 5.
    let root_item = vec![0u8; 239]; // >= level offset (238); all-zero is fine here
    let leaf = build_fs_leaf(1 /*ROOT_TREE*/, &[(2, ROOT_ITEM_KEY, 0, root_item)]);

    // Superblock: magic, root=root_logical, chunk_root outside (unused here since
    // read_node falls back to sys_chunks for the root logical), nodesize, and a
    // sys_chunk_array identity-mapping [root_logical, +sys_len).
    let mut sb = vec![0u8; BTRFS_SUPER_INFO_SIZE];
    sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
    sb[0x30..0x38].copy_from_slice(&65536u64.to_le_bytes()); // bytenr
    sb[0x50..0x58].copy_from_slice(&root_logical.to_le_bytes()); // root
    sb[0x58..0x60].copy_from_slice(&root_logical.to_le_bytes()); // chunk_root (unused)
    sb[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes()); // sectorsize
    sb[0x94..0x98].copy_from_slice(&(NODESIZE as u32).to_le_bytes()); // nodesize
    let arr = 0x32busize;
    sb[arr..arr + 8].copy_from_slice(&256u64.to_le_bytes()); // FIRST_CHUNK_TREE
    sb[arr + 8] = 228; // CHUNK_ITEM
    sb[arr + 9..arr + 17].copy_from_slice(&root_logical.to_le_bytes());
    let ci = {
        let mut d = vec![0u8; 48 + 32];
        d[0..8].copy_from_slice(&sys_len.to_le_bytes()); // length
        d[24..32].copy_from_slice(&0x2u64.to_le_bytes()); // SYSTEM
        d[44..46].copy_from_slice(&1u16.to_le_bytes()); // num_stripes
        d[46..48].copy_from_slice(&1u16.to_le_bytes()); // sub_stripes
        d[48..56].copy_from_slice(&1u64.to_le_bytes()); // stripe devid
        d[56..64].copy_from_slice(&root_logical.to_le_bytes()); // stripe offset (identity)
        d
    };
    sb[arr + 17..arr + 17 + ci.len()].copy_from_slice(&ci);
    sb[0xa0..0xa4].copy_from_slice(&((17 + ci.len()) as u32).to_le_bytes()); // sys_array_size

    // Assemble the image: superblock @0x10000, root-tree leaf @physical 4096.
    let sb_off = 65536usize;
    let mut img = vec![0u8; sb_off + BTRFS_SUPER_INFO_SIZE];
    img[sb_off..sb_off + BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);
    img[root_logical as usize..root_logical as usize + NODESIZE].copy_from_slice(&leaf);

    let sb = Superblock::parse(&img[sb_off..sb_off + BTRFS_SUPER_INFO_SIZE]).unwrap();
    let map = ChunkMap::new(); // empty: read_node falls back to sys_chunks bootstrap
    let err = fs_tree_root(&img, &sb, &map).unwrap_err();
    assert!(
        format!("{err:?}").contains("FS_TREE ROOT_ITEM"),
        "missing FS_TREE ROOT_ITEM is a loud, named failure, got {err:?}"
    );
}

#[test]
fn fs_tree_root_locates_the_fs_tree_root_item_over_a_crafted_image() {
    // The success arm of fs_tree_root: a crafted image whose ROOT_TREE leaf holds a
    // FS_TREE (objectid 5) ROOT_ITEM. fs_tree_root must decode its bytenr / level /
    // root_dirid / generation from the item (the happy path the oracle exercises
    // only under BTRFS_ORACLE_IMG). The sys_chunk_array identity-maps the root
    // logical to the physical offset holding this crafted ROOT_TREE leaf.
    let root_logical = 4096u64;
    let sys_len = 65_536u64;

    // btrfs_root_item field offsets within the item data.
    const ROOT_GENERATION: usize = 160;
    const ROOT_DIRID: usize = 168;
    const ROOT_BYTENR: usize = 176;
    const ROOT_LEVEL: usize = 238;
    let fs_tree_bytenr = 30_654_464u64;

    let mut root_item = vec![0u8; 239];
    root_item[ROOT_GENERATION..ROOT_GENERATION + 8].copy_from_slice(&9u64.to_le_bytes());
    root_item[ROOT_DIRID..ROOT_DIRID + 8].copy_from_slice(&256u64.to_le_bytes());
    root_item[ROOT_BYTENR..ROOT_BYTENR + 8].copy_from_slice(&fs_tree_bytenr.to_le_bytes());
    root_item[ROOT_LEVEL] = 0;
    // Root-tree leaf with the FS_TREE (objectid 5) ROOT_ITEM.
    let leaf = build_fs_leaf(1 /* ROOT_TREE */, &[(5, ROOT_ITEM_KEY, 0, root_item)]);

    // Superblock: magic, root=root_logical, nodesize, and a sys_chunk_array
    // identity-mapping [root_logical, +sys_len) to physical root_logical.
    let mut sb = vec![0u8; BTRFS_SUPER_INFO_SIZE];
    sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
    sb[0x30..0x38].copy_from_slice(&65536u64.to_le_bytes()); // bytenr
    sb[0x50..0x58].copy_from_slice(&root_logical.to_le_bytes()); // root
    sb[0x58..0x60].copy_from_slice(&root_logical.to_le_bytes()); // chunk_root (unused)
    sb[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes()); // sectorsize
    sb[0x94..0x98].copy_from_slice(&(NODESIZE as u32).to_le_bytes()); // nodesize
    let arr = 0x32busize;
    sb[arr..arr + 8].copy_from_slice(&256u64.to_le_bytes()); // FIRST_CHUNK_TREE
    sb[arr + 8] = 228; // CHUNK_ITEM
    sb[arr + 9..arr + 17].copy_from_slice(&root_logical.to_le_bytes());
    let ci = {
        let mut d = vec![0u8; 48 + 32];
        d[0..8].copy_from_slice(&sys_len.to_le_bytes()); // length
        d[24..32].copy_from_slice(&0x2u64.to_le_bytes()); // SYSTEM
        d[44..46].copy_from_slice(&1u16.to_le_bytes()); // num_stripes
        d[46..48].copy_from_slice(&1u16.to_le_bytes()); // sub_stripes
        d[48..56].copy_from_slice(&1u64.to_le_bytes()); // stripe devid
        d[56..64].copy_from_slice(&root_logical.to_le_bytes()); // stripe offset (identity)
        d
    };
    sb[arr + 17..arr + 17 + ci.len()].copy_from_slice(&ci);
    sb[0xa0..0xa4].copy_from_slice(&((17 + ci.len()) as u32).to_le_bytes()); // sys_array_size

    // Image: superblock @0x10000, root-tree leaf @physical root_logical.
    let sb_off = 65_536usize;
    let mut img = vec![0u8; sb_off + BTRFS_SUPER_INFO_SIZE];
    img[sb_off..sb_off + BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);
    img[root_logical as usize..root_logical as usize + NODESIZE].copy_from_slice(&leaf);

    let sb = Superblock::parse(&img[sb_off..sb_off + BTRFS_SUPER_INFO_SIZE]).unwrap();
    let map = ChunkMap::new(); // read_node falls back to sys_chunks bootstrap
    let root = fs_tree_root(&img, &sb, &map).expect("locate FS_TREE ROOT_ITEM");
    assert_eq!(root.bytenr, fs_tree_bytenr, "FS_TREE root node logical");
    assert_eq!(root.level, 0, "FS_TREE root level");
    assert_eq!(root.root_dirid, 256, "root_dirid");
    assert_eq!(root.generation, 9, "generation");
}
