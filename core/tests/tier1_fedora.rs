//! Tier-1 real-world validation against a genuine third-party btrfs filesystem:
//! the **Fedora Cloud Base 41** root partition.
//!
//! btrfs has **no ground-truth forensic corpus** — no `libfsbtrfs` in libyal, no
//! dfvfs btrfs test image, no NIST CFReDS btrfs answer key, and TSK's btrfs
//! support was reverted as experimental. The strongest genuine Tier-1 available
//! is therefore a **real distribution image + an independent decoder oracle**,
//! not an answer-key corpus. The filesystem here was authored by the Fedora
//! Project (a third party, not us); the ground-truth values asserted below come
//! from `btrfs inspect-internal dump-super -f` / `dump-tree` (btrfs-progs v6.6.3,
//! a wholly separate implementation from this reader). See `docs/validation.md`
//! and `tests/data/README.md` for provenance.
//!
//! **Env-gated.** The ~4 GiB btrfs partition is gitignored and downloaded /
//! extracted on demand; this test skips cleanly when `BTRFS_FEDORA_ORACLE` is
//! unset, so CI without the corpus stays green (like the `BTRFS_ORACLE_IMG`
//! full-image tests in `superblock.rs` / `node.rs`).
//!
//! If `btrfs-core` FAILS on this real image, that is a genuine real-world-quirk
//! finding (Fedora's geometry — a 256 MiB METADATA chunk, multiple DATA chunks,
//! COMPRESS_ZSTD in `incompat_flags` — that our single self-mint never
//! exercised). If it PASSES, it is strong Tier-1 validation that the reader
//! decodes a filesystem neither the image nor its answer key came from us.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use btrfs_core::{
    ChunkMap, CsumType, Superblock, BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE,
};

// ---- Ground truth (btrfs inspect-internal on the real Fedora partition) ----
//
// `dump-super -f` on Fedora-Cloud-Base-Generic-41-1.4 root partition
// (md5 2e91a6d3b627ecf759779a1d2f54066d, 4212112896 bytes):
//   magic _BHRfS_M [match]   csum_type 0 (crc32c)
//   fsid 815e66c2-6a8a-4984-a890-1a3c710bf933   label "fedora"   generation 13
//   root 71991296   chunk_root 22069248   log_root 0
//   total_bytes 4212109312   bytes_used 479145984
//   sectorsize 4096   nodesize 16384   stripesize 4096   num_devices 1
//   incompat_flags 0x371 (MIXED_BACKREF | COMPRESS_ZSTD | BIG_METADATA |
//                         EXTENDED_IREF | SKINNY_METADATA | NO_HOLES)
const FSID: &str = "815e66c2-6a8a-4984-a890-1a3c710bf933";
const LABEL: &str = "fedora";
const GENERATION: u64 = 13;
const ROOT_LOGICAL: u64 = 71_991_296;
const CHUNK_ROOT_LOGICAL: u64 = 22_069_248;
const TOTAL_BYTES: u64 = 4_212_109_312;
const SECTORSIZE: u32 = 4096;
const NODESIZE: u32 = 16384;
// Fedora sets COMPRESS_ZSTD (0x10) that our self-mint (0x361) never did.
const INCOMPAT_FLAGS: u64 = 0x371;

// From `dump-tree -t chunk` + the raw bytes:
//   root logical 71991296 sits in the METADATA|DUP chunk [30408704, +268435456);
//   first stripe physical 38797312, so root physical =
//   38797312 + (71991296 - 30408704) = 80379904.
//   chunk_root logical 22069248 sits in the SYSTEM|DUP chunk [22020096, +8388608)
//   at first stripe physical 22020096 -> identity physical 22069248.
const ROOT_PHYSICAL: u64 = 80_379_904;
const CHUNK_ROOT_PHYSICAL: u64 = 22_069_248;

/// The real Fedora btrfs partition, read from the gitignored on-demand path.
/// `None` (skip) when `BTRFS_FEDORA_ORACLE` is unset.
fn fedora_image() -> Option<Vec<u8>> {
    let path = std::env::var("BTRFS_FEDORA_ORACLE").ok()?;
    Some(std::fs::read(&path).unwrap_or_else(|e| panic!("read BTRFS_FEDORA_ORACLE {path}: {e}")))
}

#[test]
fn fedora_superblock_matches_btrfs_inspect_internal() {
    let Some(img) = fedora_image() else {
        eprintln!("skip: BTRFS_FEDORA_ORACLE unset (real Fedora btrfs partition not present)");
        return;
    };
    let start = BTRFS_SUPER_INFO_OFFSET as usize;
    let block = &img[start..start + BTRFS_SUPER_INFO_SIZE];
    let sb = Superblock::parse(block).expect("Fedora superblock parses at 0x10000");

    // Every field the reader decodes == the independent dump-super oracle.
    assert_eq!(sb.magic, BTRFS_MAGIC, "magic");
    assert_eq!(sb.fsid_string(), FSID, "fsid");
    assert_eq!(sb.label, LABEL, "label");
    assert_eq!(sb.csum_type, CsumType::Crc32c, "csum_type");
    assert_eq!(sb.generation, GENERATION, "generation");
    assert_eq!(sb.root, ROOT_LOGICAL, "root logical addr");
    assert_eq!(sb.chunk_root, CHUNK_ROOT_LOGICAL, "chunk_root logical addr");
    assert_eq!(sb.log_root, 0, "log_root");
    assert_eq!(sb.total_bytes, TOTAL_BYTES, "total_bytes");
    assert_eq!(sb.bytenr, BTRFS_SUPER_INFO_OFFSET, "primary sb bytenr");
    assert_eq!(sb.sectorsize, SECTORSIZE, "sectorsize");
    assert_eq!(sb.nodesize, NODESIZE, "nodesize");
    assert_eq!(sb.stripesize, SECTORSIZE, "stripesize");
    assert_eq!(sb.num_devices, 1, "num_devices (single-device)");
    // The real-world quirk our self-mint never produced: COMPRESS_ZSTD is set.
    assert_eq!(sb.incompat_flags, INCOMPAT_FLAGS, "incompat_flags (Fedora)");
    assert_eq!(
        sb.incompat_flags & 0x10,
        0x10,
        "COMPRESS_ZSTD bit set (Fedora default) — a flag our self-mint lacked"
    );
    assert_eq!(sb.root_level, 0, "root_level");
    assert_eq!(sb.chunk_root_level, 0, "chunk_root_level");

    // The primary superblock's crc32c verifies over its sectorsize block.
    assert_eq!(sb.crc_valid, Some(true), "primary sb crc32c verifies");
}

#[test]
fn fedora_chunk_walk_maps_root_tree_to_dump_tree_physical() {
    let Some(img) = fedora_image() else {
        eprintln!("skip: BTRFS_FEDORA_ORACLE unset");
        return;
    };
    let start = BTRFS_SUPER_INFO_OFFSET as usize;
    let sb = Superblock::parse(&img[start..start + BTRFS_SUPER_INFO_SIZE]).unwrap();

    // Bootstrap from the sys_chunk_array and walk the whole chunk tree. Fedora's
    // chunk tree has 7 items across several DATA chunks and a 256 MiB METADATA
    // chunk — a far richer layout than the self-mint's 3 chunks; the walk must
    // still build a correct map.
    let map = ChunkMap::walk(&img, &sb).expect("chunk-tree walk over the real Fedora image");

    // chunk_root logical -> its identity physical (SYSTEM|DUP first mirror).
    assert_eq!(
        map.logical_to_physical(CHUNK_ROOT_LOGICAL),
        Some((1, CHUNK_ROOT_PHYSICAL)),
        "chunk_root logical maps to dump-tree's physical"
    );

    // The root tree's logical address maps into the METADATA chunk exactly where
    // dump-tree + the raw bytes place it.
    assert_eq!(
        map.logical_to_physical(ROOT_LOGICAL),
        Some((1, ROOT_PHYSICAL)),
        "root-tree logical maps into the METADATA chunk (single-device DUP)"
    );

    // read_node translates + reads the root tree by logical address; its own
    // header self-references the same logical addr and the crc32c verifies.
    let root = btrfs_core::read_node(&img, &sb, &map, sb.root).expect("read Fedora root node");
    assert_eq!(root.header.bytenr, ROOT_LOGICAL, "root node's own logical");
    assert_eq!(root.header.owner, 1, "owner = ROOT_TREE");
    assert!(root.header.nritems > 0, "root tree has items");
    assert_eq!(root.header.level, 0, "Fedora root tree is a single leaf");
    assert_eq!(root.crc_valid, Some(true), "root node crc32c verifies");

    // The chunk root itself reads back with the CHUNK_TREE owner.
    let cr = btrfs_core::read_node(&img, &sb, &map, sb.chunk_root).expect("read Fedora chunk root");
    assert_eq!(cr.header.bytenr, CHUNK_ROOT_LOGICAL);
    assert_eq!(cr.header.owner, 3, "owner = CHUNK_TREE");
    assert_eq!(cr.crc_valid, Some(true), "chunk root crc32c verifies");
}
