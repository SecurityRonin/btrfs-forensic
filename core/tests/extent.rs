//! P3 EXTENT_DATA → file-content tests.
//!
//! Ground truth is two independent oracles (Doer-Checker):
//!
//! - **Content sha256 from a kernel mount-ro** (`btrfs.content.sha256`, a
//!   different implementation than this reader): `read_file` of each known
//!   oracle file must reproduce the mounted file's sha256 exactly. small.txt
//!   and leaf.txt are *inline* extents living in the committed always-on
//!   FS_TREE leaf; mid.bin is a *regular* extent whose data lives in the DATA
//!   chunk of the full image, so its test is env-gated on `BTRFS_ORACLE_IMG`.
//! - **Real compressor output** for the compression decoders: the zlib / zstd /
//!   btrfs-LZO blobs embedded below were produced by independent encoders
//!   (Python `zlib`, `zstandard`, and a hand-built LZO1X literal run) and
//!   round-tripped through the `flate2` / `ruzstd` / `lzo` crates — so the
//!   decoder is checked against an oracle a different party authored, not a
//!   self-encoded round trip (avoids the LZNT1 trap). The self-mint's own small
//!   files are uncompressed, so these blobs exercise the decompressors that the
//!   oracle files do not.
//!
//! Robustness: a lying `num_bytes` / `ram_bytes` never panics or OOMs — it is
//! rejected as an allocation bomb, or clamped, never allocated blindly.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use btrfs_core::{
    decompress_extent, read_by_path_content, read_file, read_file_from_leaf, BtrfsError,
    Compression, Node, Superblock, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE,
};

const SECTORSIZE: u32 = 4096;

/// The committed always-on fixture: the raw 16384-byte FS_TREE leaf node.
fn fs_tree_leaf() -> Vec<u8> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // core/ -> repo root
    d.push("tests/data/btrfs_fs_tree_leaf.bin");
    std::fs::read(&d).unwrap_or_else(|e| panic!("read fixture {}: {e}", d.display()))
}

fn sha256_hex(data: &[u8]) -> String {
    // A tiny, dependency-free sha256 (test-only) — reproduces `sha256sum`.
    // Uses the reference algorithm; not perf-critical.
    sha256::hex(data)
}

/// Expected content sha256 from the mount-ro oracle (`btrfs.content.sha256`).
const SMALL_TXT_SHA: &str = "9ca0c72a68735d1609cee7f1a60bcd80bf93b97db99c913887a4ace34111c10c";
const MID_BIN_SHA: &str = "7c2c6d9f7efd73a13da32a36d6a5a86d08f55a0a39b72600722922f20021eaef";
const LEAF_TXT_SHA: &str = "c7a34a532566fb437362e0cfd8b99d7ced90b6b13731489661968aab893c9cad";

// ---- Inline extents (always-on: live in the committed FS_TREE leaf) ----

#[test]
fn read_inline_file_small_txt_matches_mount_sha256() {
    // ino 257 small.txt: EXTENT_DATA type 0 (inline), ram_bytes 26, compression
    // none. The 26 inline bytes follow the 21-byte extent header in the leaf.
    let node = Node::parse(&fs_tree_leaf()).unwrap();
    let bytes = read_file_from_leaf(&node, &[], &Default::default(), SECTORSIZE, 257)
        .expect("read inline small.txt");
    assert_eq!(bytes.len(), 26, "small.txt logical size");
    assert_eq!(bytes, b"hello inline btrfs oracle\n");
    assert_eq!(
        sha256_hex(&bytes),
        SMALL_TXT_SHA,
        "small.txt == mount sha256"
    );
}

#[test]
fn read_inline_nested_leaf_txt_matches_mount_sha256() {
    // ino 261 dir/sub/leaf.txt: inline, ram_bytes 20.
    let node = Node::parse(&fs_tree_leaf()).unwrap();
    let bytes = read_file_from_leaf(&node, &[], &Default::default(), SECTORSIZE, 261)
        .expect("read inline leaf.txt");
    assert_eq!(bytes.len(), 20);
    assert_eq!(bytes, b"nested leaf content\n");
    assert_eq!(sha256_hex(&bytes), LEAF_TXT_SHA, "leaf.txt == mount sha256");
}

#[test]
fn read_file_of_absent_inode_is_a_loud_error() {
    // An objectid with no INODE_ITEM/EXTENT_DATA in the leaf: a loud, named
    // error, never an empty Vec masquerading as an empty file.
    let node = Node::parse(&fs_tree_leaf()).unwrap();
    let err = read_file_from_leaf(&node, &[], &Default::default(), SECTORSIZE, 9_999).unwrap_err();
    assert!(
        matches!(err, BtrfsError::Truncated { .. }),
        "absent inode is a loud error, got {err:?}"
    );
}

// ---- Regular extent (env-gated full image: data lives in the DATA chunk) ----

fn oracle_image() -> Option<Vec<u8>> {
    let path = std::env::var("BTRFS_ORACLE_IMG").ok()?;
    Some(std::fs::read(path).expect("read BTRFS_ORACLE_IMG"))
}

fn oracle_superblock(img: &[u8]) -> Superblock {
    let start = BTRFS_SUPER_INFO_OFFSET as usize;
    Superblock::parse(&img[start..start + BTRFS_SUPER_INFO_SIZE]).unwrap()
}

#[test]
fn read_regular_file_mid_bin_matches_mount_sha256() {
    // ino 258 mid.bin: EXTENT_DATA type 1 (regular), disk_bytenr 13631488,
    // num_bytes 65536, compression none. Its data is in the DATA chunk, so this
    // needs the whole image; content must reproduce the mount sha256 end-to-end.
    let Some(img) = oracle_image() else {
        eprintln!("skip: BTRFS_ORACLE_IMG unset");
        return;
    };
    let sb = oracle_superblock(&img);
    let map = btrfs_core::ChunkMap::walk(&img, &sb).expect("chunk walk");

    let bytes = read_file(&img, &sb, &map, 258).expect("read regular mid.bin");
    assert_eq!(bytes.len(), 65_536, "mid.bin logical size");
    assert_eq!(sha256_hex(&bytes), MID_BIN_SHA, "mid.bin == mount sha256");
}

#[test]
fn read_by_path_content_resolves_and_reads_end_to_end() {
    let Some(img) = oracle_image() else {
        eprintln!("skip: BTRFS_ORACLE_IMG unset");
        return;
    };
    let sb = oracle_superblock(&img);
    let map = btrfs_core::ChunkMap::walk(&img, &sb).expect("chunk walk");

    // Inline nested file, resolved by path, read end to end.
    let leaf_txt =
        read_by_path_content(&img, &sb, &map, "/dir/sub/leaf.txt").expect("read /dir/sub/leaf.txt");
    assert_eq!(sha256_hex(&leaf_txt), LEAF_TXT_SHA);

    // Regular file, by path.
    let mid = read_by_path_content(&img, &sb, &map, "/mid.bin").expect("read /mid.bin");
    assert_eq!(mid.len(), 65_536);
    assert_eq!(sha256_hex(&mid), MID_BIN_SHA);

    // A missing path is a loud error, not an empty file.
    let err = read_by_path_content(&img, &sb, &map, "/nope").unwrap_err();
    assert!(
        matches!(err, BtrfsError::Truncated { .. }),
        "missing path is loud, got {err:?}"
    );
}

// ---- Compression decoders (always-on: real-compressor blobs) ----
//
// Each blob was produced by an INDEPENDENT encoder and the expected plaintext
// sha256 is the sector text `SECTOR_PLAIN_SHA`. The decoder must reproduce it.

/// 4096-byte plaintext sha256 the zlib/zstd blobs decompress to.
const SECTOR_PLAIN_SHA: &str = "ec5472468ce7895a8ed98c8637b2ccc0686e269aae0dcdd0eab05ed2421f4125";

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

// zlib stream (Python zlib.compress, level 6) of the 4096-byte sector text.
const ZLIB_HEX: &str = "789cedca571180301445412b57016a628092d07921109a7ab0c1ccf9de759dd79afb7a5495ec5c14ecd290e7b8c90e9fb47f3c95cfadc6da428e4c2693c96432994c2693c964f21ff30b5becbe7d";
// zstd frame (Python zstandard, level 3) of the same 4096-byte sector text.
const ZSTD_HEX: &str = "28b52ffd60000fb50100d40254686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672e200100853ef45519";
// btrfs-LZO frame: 4-byte total(LE) + 4-byte seg_len(LE) + one LZO1X literal
// segment, decoding to a 68-byte literal run (verified via the `lzo` crate).
const LZO_FRAME_HEX: &str = "50000000480000005562747266732d6c7a6f2d6f7261636c653a2068616e642d6275696c74206c69746572616c2072756e2c206465636f64656420627920746865206c7a6f2063726174652e0a110000";
const LZO_PLAIN_SHA: &str = "2b10b19edcb731f3b054c48dc5cb867064bd63b4a75fa98ac6a38477a9305ce3";

#[test]
fn decompress_zlib_extent_matches_plaintext() {
    let out = decompress_extent(Compression::Zlib, &hx(ZLIB_HEX), 4096, SECTORSIZE)
        .expect("zlib decompresses");
    assert_eq!(out.len(), 4096);
    assert_eq!(
        sha256_hex(&out),
        SECTOR_PLAIN_SHA,
        "zlib -> sector plaintext"
    );
}

#[test]
fn decompress_zstd_extent_matches_plaintext() {
    let out = decompress_extent(Compression::Zstd, &hx(ZSTD_HEX), 4096, SECTORSIZE)
        .expect("zstd decompresses");
    assert_eq!(out.len(), 4096);
    assert_eq!(
        sha256_hex(&out),
        SECTOR_PLAIN_SHA,
        "zstd -> sector plaintext"
    );
}

#[test]
fn decompress_lzo_extent_matches_plaintext() {
    let out = decompress_extent(Compression::Lzo, &hx(LZO_FRAME_HEX), 68, SECTORSIZE)
        .expect("btrfs-lzo decompresses");
    assert_eq!(out.len(), 68);
    assert_eq!(
        out,
        b"btrfs-lzo-oracle: hand-built literal run, decoded by the lzo crate.\n"
    );
    assert_eq!(sha256_hex(&out), LZO_PLAIN_SHA, "lzo -> literal plaintext");
}

// ---- Hole / prealloc zero-fill + allocation-bomb robustness (always-on) ----

const NODESIZE: usize = 16384;
const HDR_END: usize = 101;
const ITEM_STRIDE: usize = 25;

/// Build an FS_TREE leaf with the given items and a fixed-up crc32c so
/// `Node::parse` reports `crc_valid == Some(true)`.
fn build_fs_leaf(items: &[(u64, u8, u64, Vec<u8>)]) -> Vec<u8> {
    let mut node = vec![0u8; NODESIZE];
    node[0x30..0x38].copy_from_slice(&30_654_464u64.to_le_bytes()); // bytenr
    node[0x58..0x60].copy_from_slice(&5u64.to_le_bytes()); // owner = FS_TREE
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
    let c = crc32c_iscsi(&node[0x20..]);
    node[0..4].copy_from_slice(&c.to_le_bytes());
    node
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

/// An INODE_ITEM body of the given size (byte 16 = size u64).
fn inode_item(size: u64, mode: u32) -> Vec<u8> {
    let mut d = vec![0u8; 160];
    d[16..24].copy_from_slice(&size.to_le_bytes());
    d[52..56].copy_from_slice(&mode.to_le_bytes());
    d
}

/// A regular EXTENT_DATA item: 21-byte header (type 1, compression `comp`) then
/// disk_bytenr, disk_num_bytes, offset, num_bytes.
fn extent_reg(
    comp: u8,
    disk_bytenr: u64,
    disk_num_bytes: u64,
    offset: u64,
    num_bytes: u64,
) -> Vec<u8> {
    let mut d = vec![0u8; 53];
    d[8..16].copy_from_slice(&num_bytes.to_le_bytes()); // ram_bytes (uncompressed span)
    d[16] = comp;
    d[20] = 1; // type = regular
    d[21..29].copy_from_slice(&disk_bytenr.to_le_bytes());
    d[29..37].copy_from_slice(&disk_num_bytes.to_le_bytes());
    d[37..45].copy_from_slice(&offset.to_le_bytes());
    d[45..53].copy_from_slice(&num_bytes.to_le_bytes());
    d
}

#[test]
fn hole_extent_zero_fills_to_num_bytes() {
    // A regular extent with disk_bytenr == 0 is a HOLE: it contributes
    // `num_bytes` zeros, no image read. The file's size truncates the result.
    let leaf = build_fs_leaf(&[
        (300, 1 /*INODE_ITEM*/, 0, inode_item(8192, 0o100_644)),
        (
            300,
            108, /*EXTENT_DATA*/
            0,
            extent_reg(0, 0, 0, 0, 8192),
        ),
    ]);
    let node = Node::parse(&leaf).unwrap();
    // Empty image: a hole needs no image bytes.
    let out = read_file_from_leaf(&node, &[], &Default::default(), SECTORSIZE, 300)
        .expect("hole zero-fills");
    assert_eq!(out.len(), 8192, "hole spans num_bytes");
    assert!(out.iter().all(|&b| b == 0), "hole is all zeros");
}

#[test]
fn size_truncates_a_tail_hole() {
    // Two extents: a 4096-byte regular hole then a 4096-byte hole, but the inode
    // size is only 5000 — the assembled content is truncated to `size`.
    let leaf = build_fs_leaf(&[
        (301, 1, 0, inode_item(5000, 0o100_644)),
        (301, 108, 0, extent_reg(0, 0, 0, 0, 4096)),
        (301, 108, 4096, extent_reg(0, 0, 0, 0, 4096)),
    ]);
    let node = Node::parse(&leaf).unwrap();
    let out = read_file_from_leaf(&node, &[], &Default::default(), SECTORSIZE, 301)
        .expect("truncated to size");
    assert_eq!(out.len(), 5000, "assembled content truncated to inode size");
}

#[test]
fn lying_num_bytes_is_rejected_not_ooming() {
    // A hole extent claiming a preposterous num_bytes (larger than any plausible
    // image) must be rejected as an allocation bomb, never blindly allocated.
    let huge = u64::MAX / 2;
    let leaf = build_fs_leaf(&[
        (302, 1, 0, inode_item(huge, 0o100_644)),
        (302, 108, 0, extent_reg(0, 0, 0, 0, huge)),
    ]);
    let node = Node::parse(&leaf).unwrap();
    let err =
        read_file_from_leaf(&node, &[0u8; 4096], &Default::default(), SECTORSIZE, 302).unwrap_err();
    assert!(
        matches!(err, BtrfsError::AllocationBomb { .. }),
        "absurd num_bytes rejected, got {err:?}"
    );
}

#[test]
fn lying_ram_bytes_on_compressed_extent_is_rejected() {
    // A compressed decode whose claimed ram_bytes dwarfs the source must be
    // capped/rejected, never used to pre-allocate an OOM-sized buffer.
    let huge = u64::MAX / 2;
    let err = decompress_extent(Compression::Zlib, &hx(ZLIB_HEX), huge, SECTORSIZE).unwrap_err();
    assert!(
        matches!(err, BtrfsError::AllocationBomb { .. }),
        "absurd ram_bytes rejected, got {err:?}"
    );
}

// A minimal, self-contained sha256 for the tests (reproduces `sha256sum`),
// kept test-local so btrfs-core takes no hashing dependency.
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
        let mut msg = data.to_vec();
        let bit_len = (data.len() as u64) * 8;
        msg.push(0x80);
        while msg.len() % 64 != 56 {
            msg.push(0);
        }
        msg.extend_from_slice(&bit_len.to_be_bytes());
        for chunk in msg.chunks(64) {
            let mut w = [0u32; 64];
            for (i, wi) in w.iter_mut().enumerate().take(16) {
                let o = i * 4;
                *wi = u32::from_be_bytes([chunk[o], chunk[o + 1], chunk[o + 2], chunk[o + 3]]);
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
        let mut out = String::with_capacity(64);
        for word in h {
            out.push_str(&format!("{word:08x}"));
        }
        out
    }
}
