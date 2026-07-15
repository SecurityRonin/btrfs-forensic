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

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use btrfs_core::Node;
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
    let recovered: Vec<RecoveredFile> = recover_deleted_from_leaves(&old, &current, &[]);

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
    let recovered = recover_deleted_from_leaves(&old, &current, &[]);
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
    let recovered = recover_deleted_from_leaves(&old, &old, &[]);
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

// ── robustness: malformed input never panics ──────────────────────────────────

#[test]
fn recover_deleted_malformed_input_does_not_panic() {
    assert!(btrfs_forensic::recover_deleted(&[]).is_empty());
    assert!(btrfs_forensic::recover_deleted(&[0u8; 32]).is_empty());
    assert!(btrfs_forensic::recover_deleted(b"not btrfs").is_empty());
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
