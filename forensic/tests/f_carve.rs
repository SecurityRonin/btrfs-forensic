//! F-CARVE COW deleted-file recovery tests (Tier-2 deletion oracle).
//!
//! btrfs is copy-on-write: the superblock `btrfs_root_backup[4]` array retains
//! pointers to previous-generation tree roots. A file present in an OLDER
//! generation's FS_TREE but ABSENT in the current FS_TREE was deleted; its
//! content is recoverable while the old extents survive.
//!
//! Deletion oracle (minted on the Parallels `Ubuntu 24.04 (with Rosetta)` VM,
//! btrfs-progs v6.6.3 — see `tests/data/README.md` "Deletion oracle"):
//!   1. `mkfs.btrfs`, write `secret.txt` (80 bytes) + `keep.txt`, `sync`.
//!   2. `rm secret.txt`, `sync` — CoW writes a new FS_TREE; the pre-delete
//!      generation-7 FS_TREE root (bytenr 30507008) stays referenced in a backup
//!      slot and still holds inode 257 (secret.txt) with its inline extent.
//!
//! Committed always-on fixtures (small metadata nodes, not the 256 MiB image):
//!   - `btrfs_del_superblock.bin`         — the deletion oracle's superblock.
//!   - `btrfs_del_old_fs_tree_leaf.bin`   — the pre-delete FS_TREE leaf (gen 7,
//!     12 items, has secret.txt/257).
//!   - `btrfs_del_current_fs_tree_leaf.bin` — the current FS_TREE leaf (gen 8,
//!     7 items, secret.txt gone).
//!
//! THE gate: the carved deleted-file content's sha256 equals the pre-delete
//! `sha256sum` recorded at mint (`DELETED_SECRET_SHA256`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::format_collect
)]

use std::path::PathBuf;

use btrfs_core::{ChunkMap, Node};
use btrfs_forensic::{recover_deleted_from_leaves, RecoveredFile};

/// Pre-delete sha256 of `secret.txt` (80 bytes), captured at mint on the VM
/// (`sha256sum /mnt/btrfs-del/secret.txt` before the `rm`).
const DELETED_SECRET_SHA256: &str =
    "4fce0707f6dbddc3e37931fd76044862979ddca3d80b97e338197f8995e8d312";

fn data(name: &str) -> Vec<u8> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // forensic/ -> repo root
    d.push("tests/data");
    d.push(name);
    std::fs::read(&d).unwrap_or_else(|e| panic!("read {}: {e}", d.display()))
}

fn sha256_hex(data: &[u8]) -> String {
    // A tiny pure-Rust sha256 avoids a dev-dependency; verified against the
    // recorded ground-truth constant, which is the independent oracle.
    sha256::hex(data)
}

// ── the diff-and-carve recovery over the committed deletion-oracle leaves ──────

#[test]
fn recovers_deleted_inline_file_from_old_generation_leaf() {
    let old = Node::parse(&data("btrfs_del_old_fs_tree_leaf.bin")).unwrap();
    let current = Node::parse(&data("btrfs_del_current_fs_tree_leaf.bin")).unwrap();

    // No image bytes are needed for an inline extent — its content lives in the
    // old FS_TREE leaf itself.
    let recovered: Vec<RecoveredFile> =
        recover_deleted_from_leaves(&old, &current, &[], &ChunkMap::new(), 4096);

    let hit = recovered
        .iter()
        .find(|r| r.inode == 257)
        .expect("deleted inode 257 (secret.txt) recovered by diffing old vs current");

    assert_eq!(hit.path, "secret.txt", "recovered name");
    assert_eq!(hit.size, 80, "inode size");
    assert_eq!(hit.generation, 7, "the pre-delete FS_TREE generation");
    assert_eq!(hit.content.len(), 80, "carved content length == size");

    // THE gate: carved content reproduces the pre-delete sha256.
    assert_eq!(
        hit.content_sha256, DELETED_SECRET_SHA256,
        "carved deleted-file content sha256 must equal the pre-delete hash"
    );
    assert_eq!(
        sha256_hex(&hit.content),
        DELETED_SECRET_SHA256,
        "independently re-hashing the carved bytes agrees"
    );
}

#[test]
fn kept_file_is_not_reported_as_deleted() {
    // keep.txt (inode 258) exists in BOTH leaves, so it must not be recovered as
    // a deleted file (the diff only surfaces old-minus-current inodes).
    let old = Node::parse(&data("btrfs_del_old_fs_tree_leaf.bin")).unwrap();
    let current = Node::parse(&data("btrfs_del_current_fs_tree_leaf.bin")).unwrap();
    let recovered = recover_deleted_from_leaves(&old, &current, &[], &ChunkMap::new(), 4096);
    assert!(
        recovered.iter().all(|r| r.inode != 258),
        "keep.txt (still present) must not be reported as deleted"
    );
    // Exactly one deleted file (secret.txt).
    assert_eq!(recovered.len(), 1, "only secret.txt was deleted");
}

#[test]
fn identical_leaves_recover_nothing() {
    // Diffing a leaf against itself yields no deleted files.
    let old = Node::parse(&data("btrfs_del_old_fs_tree_leaf.bin")).unwrap();
    let recovered = recover_deleted_from_leaves(&old, &old, &[], &ChunkMap::new(), 4096);
    assert!(
        recovered.is_empty(),
        "no deletions between identical leaves"
    );
}

// ── whole-image entry point (env-gated on the 256 MiB deletion image) ─────────

#[test]
fn full_image_recovers_deleted_file() {
    let Ok(path) = std::env::var("BTRFS_DEL_ORACLE") else {
        eprintln!("skip: BTRFS_DEL_ORACLE unset (256 MiB deletion image absent)");
        return;
    };
    let img = std::fs::read(&path).expect("read BTRFS_DEL_ORACLE");
    let recovered = btrfs_forensic::recover_deleted(&img);
    let hit = recovered
        .iter()
        .find(|r| r.inode == 257)
        .expect("deleted inode 257 recovered from the whole image via backup roots");
    assert_eq!(hit.content_sha256, DELETED_SECRET_SHA256);
}

// ── branch coverage over crafted leaves ───────────────────────────────────────

const NODESIZE: usize = 16_384;
const HDR_END: usize = 101;
const ITEM_STRIDE: usize = 25;

/// crc32c (Castagnoli/iSCSI), used to seal a crafted node.
fn crc32c(buf: &[u8]) -> u32 {
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

/// Build an FS_TREE-style leaf (owner configurable) with items laid out backward
/// from the node end and a fixed-up crc32c. `items` are `(objectid, type, offset,
/// data)`.
fn build_leaf(owner: u64, generation: u64, items: &[(u64, u8, u64, Vec<u8>)]) -> Vec<u8> {
    let mut node = vec![0u8; NODESIZE];
    node[0x30..0x38].copy_from_slice(&30_654_464u64.to_le_bytes()); // bytenr
    node[0x50..0x58].copy_from_slice(&generation.to_le_bytes());
    node[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
    node[0x60..0x64].copy_from_slice(&(items.len() as u32).to_le_bytes());
    node[0x64] = 0; // leaf
    let mut tail = NODESIZE;
    for (i, (oid, ty, koff, data)) in items.iter().enumerate() {
        let io = HDR_END + i * ITEM_STRIDE;
        node[io..io + 8].copy_from_slice(&oid.to_le_bytes());
        node[io + 8] = *ty;
        node[io + 9..io + 17].copy_from_slice(&koff.to_le_bytes());
        tail -= data.len();
        let doff = (tail - HDR_END) as u32;
        node[io + 17..io + 21].copy_from_slice(&doff.to_le_bytes());
        node[io + 21..io + 25].copy_from_slice(&(data.len() as u32).to_le_bytes());
        node[tail..tail + data.len()].copy_from_slice(data);
    }
    let c = crc32c(&node[0x20..]);
    node[0..4].copy_from_slice(&c.to_le_bytes());
    node
}

/// A 160-byte INODE_ITEM with `size` at offset 16.
fn inode_item(size: u64) -> Vec<u8> {
    let mut d = vec![0u8; 160];
    d[16..24].copy_from_slice(&size.to_le_bytes());
    d
}

/// An inline EXTENT_DATA (type 0) carrying `payload` (ram_bytes = payload.len()).
fn inline_extent(payload: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 21 + payload.len()];
    d[8..16].copy_from_slice(&(payload.len() as u64).to_le_bytes()); // ram_bytes
    d[20] = 0; // inline
    d[21..].copy_from_slice(payload);
    d
}

/// A DIR_ITEM body: location key[17] + transid(8) + data_len(2) + name_len(2) +
/// type(1) + name.
fn dir_item(child: u64, name: &[u8]) -> Vec<u8> {
    let mut d = vec![0u8; 30 + name.len()];
    d[0..8].copy_from_slice(&child.to_le_bytes());
    d[8] = 1; // INODE_ITEM
    d[27..29].copy_from_slice(&(name.len() as u16).to_le_bytes());
    d[29] = 1; // REG_FILE
    d[30..].copy_from_slice(name);
    d
}

const INODE_ITEM_KEY: u8 = 1;
const EXTENT_DATA_KEY: u8 = 108;
const DIR_ITEM_KEY: u8 = 84;
const FS_TREE_OBJECTID: u64 = 5;
const CHUNK_TREE_OBJECTID: u64 = 3;

#[test]
fn non_fs_tree_leaf_pair_recovers_nothing() {
    // A non-FS_TREE owner (chunk tree, owner 3) short-circuits the diff.
    let old = Node::parse(&build_leaf(CHUNK_TREE_OBJECTID, 7, &[])).unwrap();
    let current = Node::parse(&build_leaf(CHUNK_TREE_OBJECTID, 8, &[])).unwrap();
    assert!(recover_deleted_from_leaves(&old, &current, &[], &ChunkMap::new(), 4096).is_empty());
}

#[test]
fn deleted_inode_without_extent_data_is_not_carved() {
    // Inode 300 present in old (with a name + INODE_ITEM but NO EXTENT_DATA — a
    // deleted directory or metadata-only inode) and absent in current: it must
    // NOT be reported (nothing to carve), exercising the no-EXTENT_DATA branch.
    let old = build_leaf(
        FS_TREE_OBJECTID,
        7,
        &[
            (256, DIR_ITEM_KEY, 111, dir_item(300, b"emptydir")),
            (300, INODE_ITEM_KEY, 0, inode_item(0)),
        ],
    );
    let current = build_leaf(FS_TREE_OBJECTID, 8, &[]);
    let old = Node::parse(&old).unwrap();
    let current = Node::parse(&current).unwrap();
    let recovered = recover_deleted_from_leaves(&old, &current, &[], &ChunkMap::new(), 4096);
    assert!(
        recovered.iter().all(|r| r.inode != 300),
        "an inode with no EXTENT_DATA has nothing to carve"
    );
}

#[test]
fn deleted_inode_without_dir_name_falls_back_to_synthetic_name() {
    // Inode 301 deleted (INODE_ITEM + inline EXTENT_DATA) but with NO DIR_ITEM
    // naming it in the old leaf: the recovered path falls back to `inode_301`,
    // exercising the name-fallback branch.
    let payload = b"orphaned content no name";
    let old = build_leaf(
        FS_TREE_OBJECTID,
        7,
        &[
            (301, INODE_ITEM_KEY, 0, inode_item(payload.len() as u64)),
            (301, EXTENT_DATA_KEY, 0, inline_extent(payload)),
        ],
    );
    let current = build_leaf(FS_TREE_OBJECTID, 8, &[]);
    let old = Node::parse(&old).unwrap();
    let current = Node::parse(&current).unwrap();
    let recovered = recover_deleted_from_leaves(&old, &current, &[], &ChunkMap::new(), 4096);
    let hit = recovered.iter().find(|r| r.inode == 301).unwrap();
    assert_eq!(hit.path, "inode_301", "no dir entry → synthetic name");
    assert_eq!(hit.content, payload);
}

#[test]
fn dir_names_skips_a_truncated_dir_item() {
    // A DIR_ITEM shorter than the 30-byte fixed prefix is skipped by the name
    // decoder (no over-read); the deleted inode still recovers with a synthetic
    // name. Exercises the too-short dir-item branch in dir_names.
    let payload = b"content";
    let old = build_leaf(
        FS_TREE_OBJECTID,
        7,
        &[
            (256, DIR_ITEM_KEY, 111, vec![0u8; 10]), // too short (< 30)
            (302, INODE_ITEM_KEY, 0, inode_item(payload.len() as u64)),
            (302, EXTENT_DATA_KEY, 0, inline_extent(payload)),
        ],
    );
    let current = build_leaf(FS_TREE_OBJECTID, 8, &[]);
    let old = Node::parse(&old).unwrap();
    let current = Node::parse(&current).unwrap();
    let recovered = recover_deleted_from_leaves(&old, &current, &[], &ChunkMap::new(), 4096);
    let hit = recovered.iter().find(|r| r.inode == 302).unwrap();
    assert_eq!(hit.content, payload);
}

#[test]
fn recover_deleted_valid_superblock_but_unreadable_root_tree_returns_empty() {
    // A valid btrfs superblock (the committed deletion-oracle SB parses) placed in
    // an image with NO tree nodes: the chunk-tree walk / root-tree read fail, so
    // recover_deleted returns empty rather than panicking (the fs_tree_root-Err
    // branch of the whole-image path).
    let sb = data("btrfs_del_superblock.bin");
    let mut img = vec![0u8; 65_536 + 4096 + 64 * 1024 * 1024];
    img[65_536..65_536 + 4096].copy_from_slice(&sb);
    assert!(
        btrfs_forensic::recover_deleted(&img).is_empty(),
        "a superblock with no reachable root tree recovers nothing"
    );
}

// ── robustness: malformed input never panics ──────────────────────────────────

#[test]
fn recover_deleted_malformed_input_does_not_panic() {
    // Empty, too-short, and a wrong-magic buffer long enough to hold the
    // superblock block (exercises the whole-image parse-Err branches).
    assert!(btrfs_forensic::recover_deleted(&[]).is_empty());
    assert!(btrfs_forensic::recover_deleted(&[0u8; 32]).is_empty());
    assert!(btrfs_forensic::recover_deleted(b"not btrfs").is_empty());
    let long_wrong_magic = vec![0u8; 65_536 + 4096 + 16_384];
    assert!(btrfs_forensic::recover_deleted(&long_wrong_magic).is_empty());
}

// ── whole-image recover_deleted over a crafted walkable image (always-on) ─────
//
// full_image_recovers_deleted_file above needs the 256 MiB deletion oracle,
// absent on CI. This drives the same whole-image entry point over a small crafted
// walkable image: a superblock whose `root` names a ROOT_TREE leaf holding the
// FS_TREE ROOT_ITEM (→ the CURRENT FS_TREE leaf), and whose btrfs_root_backup[0]
// `fs_root` names an OLD FS_TREE leaf holding a deleted inode. recover_deleted
// reads the current tree, diffs each backup FS_TREE, and carves the deletion.

const SUPER_SIZE: usize = 4096;
const SUPER_OFFSET: usize = 65_536;
const CHUNK_LEN: u64 = 4 * 1024 * 1024;
const ROOT_LOGICAL: u64 = 0x20_000; // ROOT_TREE leaf
const CUR_FS_LOGICAL: u64 = 0x30_000; // current FS_TREE leaf
const OLD_FS_LOGICAL: u64 = 0x40_000; // old (backup) FS_TREE leaf
const BACKUP_ROOTS_OFFSET: usize = 0xb2b;
const BACKUP_FS_ROOT_OFF: usize = 48; // btrfs_root_backup.fs_root

/// A CHUNK_TREE leaf (chunk_root @ physical 0) identity-mapping `[0, CHUNK_LEN)`.
fn build_chunk_leaf() -> Vec<u8> {
    let mut node = vec![0u8; NODESIZE];
    node[0x30..0x38].copy_from_slice(&0u64.to_le_bytes()); // bytenr
    node[0x58..0x60].copy_from_slice(&CHUNK_TREE_OBJECTID.to_le_bytes()); // owner
    node[0x60..0x64].copy_from_slice(&1u32.to_le_bytes()); // nritems
    node[0x64] = 0; // leaf
    let mut chunk = vec![0u8; 48 + 32];
    chunk[0..8].copy_from_slice(&CHUNK_LEN.to_le_bytes()); // length
    chunk[24..32].copy_from_slice(&0x1u64.to_le_bytes()); // type DATA
    chunk[44..46].copy_from_slice(&1u16.to_le_bytes()); // num_stripes
    chunk[46..48].copy_from_slice(&1u16.to_le_bytes()); // sub_stripes
    chunk[48..56].copy_from_slice(&1u64.to_le_bytes()); // stripe devid
    chunk[56..64].copy_from_slice(&0u64.to_le_bytes()); // stripe offset (identity)
    let data_tail = NODESIZE - chunk.len();
    let io = HDR_END;
    node[io..io + 8].copy_from_slice(&256u64.to_le_bytes()); // FIRST_CHUNK_TREE
    node[io + 8] = 228; // CHUNK_ITEM
    node[io + 9..io + 17].copy_from_slice(&0u64.to_le_bytes()); // logical 0
    node[io + 17..io + 21].copy_from_slice(&((data_tail - HDR_END) as u32).to_le_bytes());
    node[io + 21..io + 25].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
    node[data_tail..data_tail + chunk.len()].copy_from_slice(&chunk);
    let c = crc32c(&node[0x20..]);
    node[0..4].copy_from_slice(&c.to_le_bytes());
    node
}

/// A superblock: magic, generation 8, `root` = ROOT_LOGICAL, `chunk_root` = 0,
/// nodesize, an identity sys_chunk_array, and btrfs_root_backup[0].fs_root =
/// OLD_FS_LOGICAL (the retained pre-delete FS_TREE root).
fn build_super_with_backup(old_fs_root: u64) -> Vec<u8> {
    let mut sb = vec![0u8; SUPER_SIZE];
    sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
    sb[0x30..0x38].copy_from_slice(&65536u64.to_le_bytes()); // bytenr
    sb[0x48..0x50].copy_from_slice(&8u64.to_le_bytes()); // generation
    sb[0x50..0x58].copy_from_slice(&ROOT_LOGICAL.to_le_bytes()); // root
    sb[0x58..0x60].copy_from_slice(&0u64.to_le_bytes()); // chunk_root logical 0
    sb[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes()); // sectorsize
    sb[0x94..0x98].copy_from_slice(&(NODESIZE as u32).to_le_bytes()); // nodesize
    let arr = 0x32busize;
    sb[arr..arr + 8].copy_from_slice(&256u64.to_le_bytes());
    sb[arr + 8] = 228;
    sb[arr + 9..arr + 17].copy_from_slice(&0u64.to_le_bytes());
    let mut ci = vec![0u8; 48 + 32];
    ci[0..8].copy_from_slice(&CHUNK_LEN.to_le_bytes());
    ci[24..32].copy_from_slice(&0x2u64.to_le_bytes()); // SYSTEM
    ci[44..46].copy_from_slice(&1u16.to_le_bytes());
    ci[46..48].copy_from_slice(&1u16.to_le_bytes());
    ci[48..56].copy_from_slice(&1u64.to_le_bytes());
    ci[56..64].copy_from_slice(&0u64.to_le_bytes());
    sb[arr + 17..arr + 17 + ci.len()].copy_from_slice(&ci);
    sb[0xa0..0xa4].copy_from_slice(&((17 + ci.len()) as u32).to_le_bytes());
    // btrfs_root_backup[0].fs_root -> OLD_FS_LOGICAL.
    let b0 = BACKUP_ROOTS_OFFSET + BACKUP_FS_ROOT_OFF;
    sb[b0..b0 + 8].copy_from_slice(&old_fs_root.to_le_bytes());
    sb
}

/// A ROOT_TREE leaf holding a FS_TREE (objectid 5) ROOT_ITEM whose bytenr@176 =
/// `fs_leaf_logical`.
fn build_root_tree_leaf(fs_leaf_logical: u64) -> Vec<u8> {
    let mut root_item = vec![0u8; 239];
    root_item[176..184].copy_from_slice(&fs_leaf_logical.to_le_bytes());
    root_item[168..176].copy_from_slice(&256u64.to_le_bytes()); // root_dirid
    build_leaf(
        1, /* ROOT_TREE */
        8,
        &[(5, 132 /* ROOT_ITEM */, 0, root_item)],
    )
}

#[test]
fn recover_deleted_whole_image_via_backup_root() {
    // Current FS_TREE (gen 8): root dir 256 + keep.txt (258). secret.txt is GONE.
    let current = build_leaf(
        FS_TREE_OBJECTID,
        8,
        &[
            (256, DIR_ITEM_KEY, 10, dir_item(258, b"keep.txt")),
            (258, INODE_ITEM_KEY, 0, inode_item(4)),
            (258, EXTENT_DATA_KEY, 0, inline_extent(b"keep")),
        ],
    );
    // Old FS_TREE (gen 7, retained in backup[0]): still has secret.txt (257).
    let secret = b"the pre-delete secret content";
    let old = build_leaf(
        FS_TREE_OBJECTID,
        7,
        &[
            (256, DIR_ITEM_KEY, 10, dir_item(257, b"secret.txt")),
            (256, DIR_ITEM_KEY, 20, dir_item(258, b"keep.txt")),
            (257, INODE_ITEM_KEY, 0, inode_item(secret.len() as u64)),
            (257, EXTENT_DATA_KEY, 0, inline_extent(secret)),
            (258, INODE_ITEM_KEY, 0, inode_item(4)),
            (258, EXTENT_DATA_KEY, 0, inline_extent(b"keep")),
        ],
    );

    let mut img = vec![0u8; CHUNK_LEN as usize];
    img[0..NODESIZE].copy_from_slice(&build_chunk_leaf());
    img[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE]
        .copy_from_slice(&build_super_with_backup(OLD_FS_LOGICAL));
    img[ROOT_LOGICAL as usize..ROOT_LOGICAL as usize + NODESIZE]
        .copy_from_slice(&build_root_tree_leaf(CUR_FS_LOGICAL));
    img[CUR_FS_LOGICAL as usize..CUR_FS_LOGICAL as usize + NODESIZE].copy_from_slice(&current);
    img[OLD_FS_LOGICAL as usize..OLD_FS_LOGICAL as usize + NODESIZE].copy_from_slice(&old);

    let recovered = btrfs_forensic::recover_deleted(&img);
    let hit = recovered
        .iter()
        .find(|r| r.inode == 257)
        .expect("secret.txt (257) recovered from the backup FS_TREE via the whole-image path");
    assert_eq!(hit.path, "secret.txt");
    assert_eq!(hit.generation, 7, "recovered from the old generation");
    assert_eq!(hit.content, secret);
    // keep.txt (present in both) is not reported as deleted.
    assert!(recovered.iter().all(|r| r.inode != 258));
}

/// A minimal, self-contained SHA-256 for the independent re-hash assertion (the
/// recorded `DELETED_SECRET_SHA256` from the mint is the real oracle; this only
/// confirms our own re-hash agrees, so a vendored impl is acceptable here).
mod sha256 {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];

    pub fn hex(data: &[u8]) -> String {
        let mut h: [u32; 8] = [
            0x6a09_e667,
            0xbb67_ae85,
            0x3c6e_f372,
            0xa54f_f53a,
            0x510e_527f,
            0x9b05_688c,
            0x1f83_d9ab,
            0x5be0_cd19,
        ];
        let bit_len = (data.len() as u64).wrapping_mul(8);
        let mut msg = data.to_vec();
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());

        for chunk in msg.chunks_exact(64) {
            let mut w = [0u32; 64];
            for (i, wi) in w.iter_mut().take(16).enumerate() {
                *wi = u32::from_be_bytes([
                    chunk[i * 4],
                    chunk[i * 4 + 1],
                    chunk[i * 4 + 2],
                    chunk[i * 4 + 3],
                ]);
            }
            for i in 16..64 {
                let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
                let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
                w[i] = w[i - 16]
                    .wrapping_add(s0)
                    .wrapping_add(w[i - 7])
                    .wrapping_add(s1);
            }
            let mut v = h;
            for i in 0..64 {
                let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
                let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
                let t1 = v[7]
                    .wrapping_add(s1)
                    .wrapping_add(ch)
                    .wrapping_add(K[i])
                    .wrapping_add(w[i]);
                let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
                let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
                let t2 = s0.wrapping_add(maj);
                v[7] = v[6];
                v[6] = v[5];
                v[5] = v[4];
                v[4] = v[3].wrapping_add(t1);
                v[3] = v[2];
                v[2] = v[1];
                v[1] = v[0];
                v[0] = t1.wrapping_add(t2);
            }
            for (hi, vi) in h.iter_mut().zip(v.iter()) {
                *hi = hi.wrapping_add(*vi);
            }
        }
        h.iter().map(|x| format!("{x:08x}")).collect()
    }
}
