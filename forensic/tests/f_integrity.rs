//! F-INTEGRITY structural-integrity auditor tests.
//!
//! Fixtures (committed, always-on — see `tests/data/README.md`):
//!   - `btrfs_superblock.bin` — the clean 4096-byte superblock of the base
//!     oracle. `audit_image` over a whole clean image built from it MUST emit no
//!     findings (clean-image-is-clean, the success criterion).
//!   - crafted corruption over copies of the committed node fixtures (byte-flip a
//!     node → `BTRFS-CRC-MISMATCH`; corrupt the superblock csum →
//!     `BTRFS-SUPERBLOCK-CRC-MISMATCH`; craft a backup-root divergence; craft an
//!     ORPHAN_ITEM; absurd geometry → `BTRFS-IMPOSSIBLE-GEOMETRY`).
//!
//! btrfs metadata is little-endian on disk; the superblock lives at physical
//! offset 65536 and the `btrfs_root_backup[4]` array at superblock offset 0xb2b.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::too_many_lines,
    clippy::doc_markdown
)]

use std::path::PathBuf;

use btrfs_core::{Superblock, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE};
use btrfs_forensic::{audit_findings, audit_image, AnomalyKind, Severity};

fn data(name: &str) -> Vec<u8> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // forensic/ -> repo root
    d.push("tests/data");
    d.push(name);
    std::fs::read(&d).unwrap_or_else(|e| panic!("read {}: {e}", d.display()))
}

/// crc32c (Castagnoli/iSCSI) — the btrfs on-disk checksum. Used to re-seal a
/// crafted block so a divergence/orphan finding is not masked by a CRC finding.
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

/// Re-seal a superblock block's crc32c over `[0x20 .. sectorsize]`.
fn reseal_sb(block: &mut [u8], sectorsize: usize) {
    let c = crc32c(&block[0x20..sectorsize]);
    block[0..4].copy_from_slice(&c.to_le_bytes());
}

/// Re-seal a node block's crc32c over `[0x20 .. len]`.
fn reseal_node(block: &mut [u8]) {
    let c = crc32c(&block[0x20..]);
    block[0..4].copy_from_slice(&c.to_le_bytes());
}

/// The base-oracle superblock (4096-byte block). Its geometry: chunk_root
/// 22036480 (identity), root 30720000 (METADATA), METADATA chunk first stripe
/// physical 38797312. Build a whole-image byte buffer big enough to hold the
/// nodes the audit sweeps so the clean image is genuinely clean.
fn base_superblock() -> Vec<u8> {
    data("btrfs_superblock.bin")
}

/// Assemble a minimal whole image from the committed fixtures so `audit_image`
/// can translate + read the tree nodes the base oracle references. The chunk
/// tree leaf and FS_TREE leaf are placed at their physical offsets; the SYSTEM
/// bootstrap in the superblock maps chunk_root at identity.
fn base_image() -> Vec<u8> {
    let sb = base_superblock();
    // Physical extent we need to cover: FS_TREE leaf at physical 39043072 + 16384.
    let mut img = vec![0u8; 39_043_072 + 16_384];
    // superblock at 65536
    img[65_536..65_536 + 4096].copy_from_slice(&sb);
    // chunk-tree leaf: logical 22036480 -> physical 22036480 (identity)
    let chunk = data("btrfs_chunk_root.bin");
    img[22_036_480..22_036_480 + 16_384].copy_from_slice(&chunk);
    // FS_TREE leaf: logical 30654464 -> physical 39043072
    let fs = data("btrfs_fs_tree_leaf.bin");
    img[39_043_072..39_043_072 + 16_384].copy_from_slice(&fs);
    // root tree leaf: logical 30720000 -> physical 39108608 — beyond our buffer;
    // grow to include it so fs_tree_root resolves. root physical:
    // 38797312 + (30720000-30408704) = 39108608.
    let root_phys = 39_108_608usize;
    if img.len() < root_phys + 16_384 {
        img.resize(root_phys + 16_384, 0);
    }
    // We do not have the committed root-tree leaf fixture; the FS_TREE sweep in
    // the audit walks reachable nodes from the superblock roots directly, so the
    // root-tree leaf being zero is acceptable (it decodes to an empty node).
    img
}

// ── clean-image-is-clean (THE success criterion) ─────────────────────────────

#[test]
fn clean_image_emits_no_anomalies() {
    let img = base_image();
    let anomalies = audit_image(&img);
    assert!(
        anomalies.is_empty(),
        "clean base image must be clean, got: {anomalies:?}"
    );
    assert!(audit_findings(&img, "volume: base").is_empty());
}

// ── BTRFS-SUPERBLOCK-CRC-MISMATCH: corrupt the superblock's own csum ──────────

#[test]
fn corrupt_superblock_csum_flags_superblock_crc_mismatch() {
    let mut img = base_image();
    // Flip a byte in the superblock body (past the csum field, before magic) so
    // the stored crc32c no longer verifies. Offset 0x30 (bytenr) is safe to flip.
    img[65_536 + 0x30] ^= 0xFF;
    let anomalies = audit_image(&img);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::SuperblockCrcMismatch { .. })),
        "expected BTRFS-SUPERBLOCK-CRC-MISMATCH, got: {anomalies:?}"
    );
    let a = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::SuperblockCrcMismatch { .. }))
        .unwrap();
    assert_eq!(a.code, "BTRFS-SUPERBLOCK-CRC-MISMATCH");
    assert_eq!(a.severity, Severity::High);
}

// ── BTRFS-CRC-MISMATCH: byte-flip a metadata node ────────────────────────────

#[test]
fn byte_flipped_node_flags_crc_mismatch() {
    let mut img = base_image();
    // Flip a byte inside the FS_TREE leaf (physical 39043072), away from the
    // header magic/csum, so the node still parses but its crc32c breaks.
    img[39_043_072 + 200] ^= 0xFF;
    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::NodeCrcMismatch { bytenr, .. } if *bytenr == 30_654_464
        )),
        "expected BTRFS-CRC-MISMATCH for the flipped FS_TREE leaf, got: {anomalies:?}"
    );
    let a = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::NodeCrcMismatch { .. }))
        .unwrap();
    assert_eq!(a.code, "BTRFS-CRC-MISMATCH");
    assert_eq!(a.severity, Severity::High);
}

// ── BTRFS-BACKUP-ROOT-DIVERGENCE: a backup newer than the current gen ─────────

#[test]
fn backup_root_newer_than_current_flags_divergence() {
    let mut img = base_image();
    // The backup_roots[4] array is at superblock offset 0xb2b; each btrfs_root_backup
    // is 168 bytes. backup[0].tree_root_gen is at +8 (tree_root@0, gen@8). The
    // superblock generation is at offset 0x48. Set backup[0]'s gen ABOVE the
    // current generation (a backup cannot legitimately be newer than the SB).
    let sb_gen_off = 65_536 + 0x48;
    let cur_gen = u64::from_le_bytes(img[sb_gen_off..sb_gen_off + 8].try_into().unwrap());
    let backup0_gen_off = 65_536 + 0xb2b + 8;
    img[backup0_gen_off..backup0_gen_off + 8].copy_from_slice(&(cur_gen + 5).to_le_bytes());
    // Re-seal the superblock so a CRC finding does not mask the divergence.
    let sect = 4096usize;
    reseal_sb(&mut img[65_536..65_536 + sect], sect);

    let anomalies = audit_image(&img);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::BackupRootDivergence { .. })),
        "expected BTRFS-BACKUP-ROOT-DIVERGENCE, got: {anomalies:?}"
    );
    let a = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::BackupRootDivergence { .. }))
        .unwrap();
    assert_eq!(a.code, "BTRFS-BACKUP-ROOT-DIVERGENCE");
    // A backup newer than the current committed generation is High.
    assert_eq!(a.severity, Severity::High);
}

// ── BTRFS-ORPHANED-INODE: craft an ORPHAN_ITEM in the FS_TREE ─────────────────

#[test]
fn crafted_orphan_item_flags_orphaned_inode() {
    // Build a whole image whose FS_TREE leaf carries an ORPHAN_ITEM
    // (objectid ORPHAN_OBJECTID = -5 = u64::MAX-4, key type 48). Start from the
    // committed FS_TREE leaf and splice an ORPHAN_ITEM into a spare item slot.
    let mut img = base_image();
    let fs_phys = 39_043_072usize;
    // The FS_TREE leaf has nritems @0x60; append one ORPHAN_ITEM header + a small
    // data. Simplest crafted approach: overwrite item 0's key to an ORPHAN key.
    // item 0 header is at fs_phys + 101 (HDR_END). key = objectid(8) type(1) off(8).
    let it0 = fs_phys + 101;
    let orphan_objectid: u64 = u64::MAX - 4; // ORPHAN_OBJECTID = -5
    img[it0..it0 + 8].copy_from_slice(&orphan_objectid.to_le_bytes());
    img[it0 + 8] = 48; // ORPHAN_ITEM_KEY
                       // key offset (the orphaned inode number) at it0+9.
    img[it0 + 9..it0 + 17].copy_from_slice(&257u64.to_le_bytes());
    reseal_node(&mut img[fs_phys..fs_phys + 16_384]);

    let anomalies = audit_image(&img);
    let orphan = anomalies
        .iter()
        .find(|a| matches!(&a.kind, AnomalyKind::OrphanedInode { inode } if *inode == 257));
    assert!(
        orphan.is_some(),
        "expected BTRFS-ORPHANED-INODE for the crafted ORPHAN_ITEM, got: {anomalies:?}"
    );
    assert_eq!(orphan.unwrap().code, "BTRFS-ORPHANED-INODE");
    assert_eq!(orphan.unwrap().severity, Severity::Medium);
}

// ── BTRFS-IMPOSSIBLE-GEOMETRY: a root logical address past the image ──────────

#[test]
fn impossible_geometry_root_past_image_flags_finding() {
    let mut img = base_image();
    // Set the superblock `root` logical (offset 0x50) absurdly large so it cannot
    // map/read within the image — an impossible geometry. Re-seal the SB so the
    // finding is the geometry one, not a CRC one.
    let root_off = 65_536 + 0x50;
    img[root_off..root_off + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let sect = 4096usize;
    reseal_sb(&mut img[65_536..65_536 + sect], sect);
    let anomalies = audit_image(&img);
    assert!(
        anomalies
            .iter()
            .any(|a| matches!(a.kind, AnomalyKind::ImpossibleGeometry { .. })),
        "expected BTRFS-IMPOSSIBLE-GEOMETRY, got: {anomalies:?}"
    );
    let a = anomalies
        .iter()
        .find(|a| matches!(a.kind, AnomalyKind::ImpossibleGeometry { .. }))
        .unwrap();
    assert_eq!(a.code, "BTRFS-IMPOSSIBLE-GEOMETRY");
    assert_eq!(a.severity, Severity::High);
}

// ── audit_findings converts every anomaly kind to a graded report::Finding ────

#[test]
fn audit_findings_convert_every_anomaly_kind() {
    // Two crafted images together yield all five codes.
    // (a) superblock-csum corruption + node corruption → SuperblockCrc + NodeCrc.
    let mut a = base_image();
    a[65_536 + 0x30] ^= 0xFF; // superblock body → superblock crc mismatch
    a[39_043_072 + 200] ^= 0xFF; // FS_TREE leaf → node crc mismatch

    // (b) backup divergence + orphan + impossible geometry, SB re-sealed.
    let mut b = base_image();
    let sb_gen_off = 65_536 + 0x48;
    let cur_gen = u64::from_le_bytes(b[sb_gen_off..sb_gen_off + 8].try_into().unwrap());
    let backup0_gen_off = 65_536 + 0xb2b + 8;
    b[backup0_gen_off..backup0_gen_off + 8].copy_from_slice(&(cur_gen + 5).to_le_bytes());
    // Orphan item in the FS_TREE leaf.
    let fs_phys = 39_043_072usize;
    let it0 = fs_phys + 101;
    b[it0..it0 + 8].copy_from_slice(&(u64::MAX - 4).to_le_bytes());
    b[it0 + 8] = 48;
    b[it0 + 9..it0 + 17].copy_from_slice(&257u64.to_le_bytes());
    reseal_node(&mut b[fs_phys..fs_phys + 16_384]);
    // Impossible geometry: the `root` (root-tree) logical is absurd (offset 0x50)
    // so it cannot resolve — while `chunk_root` stays valid, keeping the chunk map
    // intact so the crafted FS_TREE orphan is still reachable for the scan.
    let root_off = 65_536 + 0x50;
    b[root_off..root_off + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    let sect = 4096usize;
    reseal_sb(&mut b[65_536..65_536 + sect], sect);

    let mut codes = std::collections::BTreeSet::new();
    for img in [&a, &b] {
        let findings = audit_findings(img, "volume: base");
        for f in &findings {
            assert!(!f.note.is_empty());
            assert!(f.severity.is_some());
            assert_eq!(f.source.analyzer, "btrfs-forensic");
            assert_eq!(f.source.scope, "volume: base");
            codes.insert(f.code.as_ref().to_string());
        }
    }
    for want in [
        "BTRFS-SUPERBLOCK-CRC-MISMATCH",
        "BTRFS-CRC-MISMATCH",
        "BTRFS-BACKUP-ROOT-DIVERGENCE",
        "BTRFS-ORPHANED-INODE",
        "BTRFS-IMPOSSIBLE-GEOMETRY",
    ] {
        assert!(codes.contains(want), "missing {want}; got {codes:?}");
    }
}

// ── robustness: malformed input degrades, never panics ────────────────────────

#[test]
fn audit_malformed_input_does_not_panic() {
    assert!(audit_image(&[]).is_empty());
    assert!(audit_image(&[0u8; 16]).is_empty());
    assert!(audit_image(b"not a btrfs image at all").is_empty());
    assert!(audit_findings(&[0u8; 8], "x").is_empty());
    // A buffer with the magic but truncated before the whole superblock.
    let mut tiny = vec![0u8; 65_536 + 0x50];
    tiny[65_536 + 0x40..65_536 + 0x48].copy_from_slice(b"_BHRfS_M");
    let _ = audit_image(&tiny);
}

#[test]
fn zero_nodesize_degrades_without_panic() {
    let mut img = base_image();
    // sectorsize@0x90, nodesize@0x94 — zero the nodesize; the node sweep cannot
    // slice nodes and must degrade rather than panic.
    let nodesize_off = 65_536 + 0x94;
    img[nodesize_off..nodesize_off + 4].copy_from_slice(&0u32.to_le_bytes());
    let sect = 4096usize;
    reseal_sb(&mut img[65_536..65_536 + sect], sect);
    let _ = audit_image(&img);
}

#[test]
fn superblock_parse_over_whole_image_is_sound() {
    // Sanity: the base image's superblock parses at 0x10000 (the audit reads it
    // there, exactly like the reader's own tests).
    let img = base_image();
    let start = BTRFS_SUPER_INFO_OFFSET as usize;
    let sb = Superblock::parse(&img[start..start + BTRFS_SUPER_INFO_SIZE]).unwrap();
    assert_eq!(sb.generation, 9);
}

#[test]
fn superblock_present_but_wrong_magic_yields_no_findings() {
    // A buffer long enough to hold the superblock block, but whose bytes at 0x40
    // are not "_BHRfS_M": Superblock::parse fails and audit_image returns empty
    // (the parse-Err early return), never panicking.
    let img = vec![0u8; 65_536 + 4096 + 16_384];
    assert!(audit_image(&img).is_empty());
}

#[test]
fn zero_root_logical_is_not_a_geometry_error() {
    // Set the superblock `root` (offset 0x50) to 0 ("none"): check_root_reachable
    // must treat 0 as absent, not an impossible-geometry finding.
    let mut img = base_image();
    let root_off = 65_536 + 0x50;
    img[root_off..root_off + 8].copy_from_slice(&0u64.to_le_bytes());
    let sect = 4096usize;
    reseal_sb(&mut img[65_536..65_536 + sect], sect);
    let anomalies = audit_image(&img);
    // No ImpossibleGeometry for `root` (0 is "none").
    assert!(
        !anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::ImpossibleGeometry { field, .. } if *field == "root"
        )),
        "root == 0 must not flag impossible geometry, got: {anomalies:?}"
    );
}

#[test]
fn backup_fs_root_gen_newer_flags_divergence() {
    // Diverge only the fs_root_gen of a backup slot (keep tree_root_gen sane) to
    // exercise the fs_root-generation branch of check_backup_roots.
    let mut img = base_image();
    let sb_gen_off = 65_536 + 0x48;
    let cur_gen = u64::from_le_bytes(img[sb_gen_off..sb_gen_off + 8].try_into().unwrap());
    // backup[1].fs_root_gen is at +48+8 = +56 within slot 1 (offset 0xb2b + 168).
    let slot1 = 65_536 + 0xb2b + 168;
    let fs_gen_off = slot1 + 56;
    img[fs_gen_off..fs_gen_off + 8].copy_from_slice(&(cur_gen + 3).to_le_bytes());
    let sect = 4096usize;
    reseal_sb(&mut img[65_536..65_536 + sect], sect);
    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::BackupRootDivergence { reason, .. }
                if reason.contains("fs_root generation")
        )),
        "expected fs_root-generation divergence, got: {anomalies:?}"
    );
}

#[test]
fn backup_tree_root_past_image_flags_divergence() {
    // A backup tree_root logical address past the end of the image, with sane
    // generations, exercises the "tree_root past image" branch.
    let mut img = base_image();
    // backup[2].tree_root is at slot 2 offset +0 (0xb2b + 2*168).
    let slot2 = 65_536 + 0xb2b + 2 * 168;
    let huge = (img.len() as u64) + 1_000_000;
    img[slot2..slot2 + 8].copy_from_slice(&huge.to_le_bytes());
    let sect = 4096usize;
    reseal_sb(&mut img[65_536..65_536 + sect], sect);
    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::BackupRootDivergence { reason, .. }
                if reason.contains("past the end of the image")
        )),
        "expected tree_root-past-image divergence, got: {anomalies:?}"
    );
}

// ── interior-node descent: a corrupt CHILD leaf under an interior root ────────
//
// The self-mint's trees are single leaves, so the sweep's interior-descent path
// (following key-pointers to children) has no real fixture. This crafts a minimal
// self-contained image: a superblock whose sys_chunk_array identity-maps a SYSTEM
// chunk, an INTERIOR node (level 1) at `sb.root` whose key-pointer references a
// CHILD leaf, and that child leaf carries a broken crc32c. The sweep must descend
// the interior node to reach and flag the child (BTRFS-CRC-MISMATCH).

const NODESIZE: usize = 16_384;

/// A crc32c-sealed node header at logical `bytenr`, `level`, `nritems`, owner 5.
fn node_header(block: &mut [u8], bytenr: u64, level: u8, nritems: u32, fsid: &[u8; 16]) {
    block[0x20..0x30].copy_from_slice(fsid);
    block[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
    block[0x58..0x60].copy_from_slice(&5u64.to_le_bytes()); // owner FS_TREE
    block[0x60..0x64].copy_from_slice(&nritems.to_le_bytes());
    block[0x64] = level;
}

fn seal_node(block: &mut [u8]) {
    let c = crc32c(&block[0x20..]);
    block[0..4].copy_from_slice(&c.to_le_bytes());
}

#[test]
fn interior_node_descent_reaches_a_corrupt_child_leaf() {
    // Identity-mapped geometry: logical == physical for the whole image via one
    // SYSTEM chunk spanning [0, sys_len).
    let root_logical = 100 * NODESIZE as u64; // interior node's logical addr
    let child_logical = 101 * NODESIZE as u64; // child leaf's logical addr
    let sys_len = 200 * NODESIZE as u64;
    let fsid = [0xAB; 16];

    // Superblock @ 0x10000.
    let mut sb = vec![0u8; BTRFS_SUPER_INFO_SIZE];
    sb[0x20..0x30].copy_from_slice(&fsid);
    sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
    sb[0x30..0x38].copy_from_slice(&65_536u64.to_le_bytes()); // bytenr
    sb[0x48..0x50].copy_from_slice(&9u64.to_le_bytes()); // generation
    sb[0x50..0x58].copy_from_slice(&root_logical.to_le_bytes()); // root
    sb[0x58..0x60].copy_from_slice(&22_020_096u64.to_le_bytes()); // chunk_root (unused: sys bootstrap)
    sb[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes()); // sectorsize
    sb[0x94..0x98].copy_from_slice(&(NODESIZE as u32).to_le_bytes()); // nodesize
                                                                      // sys_chunk_array: one CHUNK_ITEM identity-mapping [0, sys_len).
    let arr = 0x32busize;
    sb[arr..arr + 8].copy_from_slice(&256u64.to_le_bytes()); // FIRST_CHUNK_TREE
    sb[arr + 8] = 228; // CHUNK_ITEM
    sb[arr + 9..arr + 17].copy_from_slice(&0u64.to_le_bytes()); // chunk logical start 0
    let ci = {
        let mut d = vec![0u8; 48 + 32];
        d[0..8].copy_from_slice(&sys_len.to_le_bytes()); // length
        d[24..32].copy_from_slice(&0x2u64.to_le_bytes()); // SYSTEM
        d[44..46].copy_from_slice(&1u16.to_le_bytes()); // num_stripes
        d[46..48].copy_from_slice(&1u16.to_le_bytes()); // sub_stripes
        d[48..56].copy_from_slice(&1u64.to_le_bytes()); // stripe devid
        d[56..64].copy_from_slice(&0u64.to_le_bytes()); // stripe offset 0 (identity)
        d
    };
    sb[arr + 17..arr + 17 + ci.len()].copy_from_slice(&ci);
    sb[0xa0..0xa4].copy_from_slice(&((17 + ci.len()) as u32).to_le_bytes()); // sys_array_size
                                                                             // Seal the superblock over [0x20 .. sectorsize].
    reseal_sb(&mut sb, 4096);

    // Interior node (level 1) at root_logical: one key-pointer to child_logical.
    // btrfs_key_ptr = disk_key[17] + blockptr(u64) + generation(u64) at header end.
    let mut interior = vec![0u8; NODESIZE];
    node_header(&mut interior, root_logical, 1, 1, &fsid);
    let hdr = 101usize;
    interior[hdr + 17..hdr + 25].copy_from_slice(&child_logical.to_le_bytes()); // blockptr
    seal_node(&mut interior);

    // Child leaf at child_logical with a DELIBERATELY broken crc32c (seal, then
    // flip a body byte so the stored digest no longer matches).
    let mut child = vec![0u8; NODESIZE];
    node_header(&mut child, child_logical, 0, 0, &fsid);
    seal_node(&mut child);
    child[500] ^= 0xFF; // break the body after sealing

    // Assemble the identity-mapped image.
    let end = (child_logical as usize) + NODESIZE;
    let mut img = vec![0u8; end.max(65_536 + BTRFS_SUPER_INFO_SIZE)];
    img[65_536..65_536 + BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);
    img[root_logical as usize..root_logical as usize + NODESIZE].copy_from_slice(&interior);
    img[child_logical as usize..child_logical as usize + NODESIZE].copy_from_slice(&child);

    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::NodeCrcMismatch { bytenr, .. } if *bytenr == child_logical
        )),
        "the sweep must descend the interior node to flag the corrupt child leaf, got: {anomalies:?}"
    );
}

// ── scan_orphans over a walkable image whose ROOT_TREE names the FS_TREE ──────
//
// The crafted-orphan test above reaches the orphan through the BACKUP roots
// (base_image's root-tree leaf is zeroed, so fs_tree_root returns Err). This
// drives the OTHER path: a walkable image whose ROOT_TREE leaf holds the FS_TREE
// ROOT_ITEM, so fs_tree_root SUCCEEDS and scan_orphans reaches the current FS_TREE
// leaf directly — the live-root-tree orphan scan the oracle test exercises.

const HDR_END_I: usize = 101;
const ITEM_STRIDE_I: usize = 25;
const CHUNK_LEN_I: u64 = 4 * 1024 * 1024;
const ROOT_LOGICAL_I: u64 = 0x20_000;
const FS_LEAF_LOGICAL_I: u64 = 0x30_000;

/// Build a leaf (`owner`, level 0) with `items = (objectid, type, key_off, data)`
/// laid out backward from the node end, crc32c-sealed.
fn build_leaf_i(owner: u64, items: &[(u64, u8, u64, Vec<u8>)]) -> Vec<u8> {
    let mut node = vec![0u8; NODESIZE];
    node[0x30..0x38].copy_from_slice(&30_654_464u64.to_le_bytes()); // bytenr
    node[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
    node[0x60..0x64].copy_from_slice(&(items.len() as u32).to_le_bytes());
    node[0x64] = 0; // leaf
    let mut tail = NODESIZE;
    for (i, (oid, ty, koff, data)) in items.iter().enumerate() {
        let io = HDR_END_I + i * ITEM_STRIDE_I;
        node[io..io + 8].copy_from_slice(&oid.to_le_bytes());
        node[io + 8] = *ty;
        node[io + 9..io + 17].copy_from_slice(&koff.to_le_bytes());
        tail -= data.len();
        let doff = (tail - HDR_END_I) as u32;
        node[io + 17..io + 21].copy_from_slice(&doff.to_le_bytes());
        node[io + 21..io + 25].copy_from_slice(&(data.len() as u32).to_le_bytes());
        node[tail..tail + data.len()].copy_from_slice(data);
    }
    seal_node(&mut node);
    node
}

/// A CHUNK_TREE leaf (chunk_root @0) identity-mapping `[0, CHUNK_LEN_I)`.
fn build_chunk_leaf_i() -> Vec<u8> {
    let mut node = vec![0u8; NODESIZE];
    node[0x58..0x60].copy_from_slice(&3u64.to_le_bytes()); // owner CHUNK_TREE
    node[0x60..0x64].copy_from_slice(&1u32.to_le_bytes());
    node[0x64] = 0;
    let mut chunk = vec![0u8; 48 + 32];
    chunk[0..8].copy_from_slice(&CHUNK_LEN_I.to_le_bytes());
    chunk[24..32].copy_from_slice(&0x1u64.to_le_bytes());
    chunk[44..46].copy_from_slice(&1u16.to_le_bytes());
    chunk[46..48].copy_from_slice(&1u16.to_le_bytes());
    chunk[48..56].copy_from_slice(&1u64.to_le_bytes());
    chunk[56..64].copy_from_slice(&0u64.to_le_bytes());
    let data_tail = NODESIZE - chunk.len();
    let io = HDR_END_I;
    node[io..io + 8].copy_from_slice(&256u64.to_le_bytes());
    node[io + 8] = 228;
    node[io + 9..io + 17].copy_from_slice(&0u64.to_le_bytes());
    node[io + 17..io + 21].copy_from_slice(&((data_tail - HDR_END_I) as u32).to_le_bytes());
    node[io + 21..io + 25].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
    node[data_tail..data_tail + chunk.len()].copy_from_slice(&chunk);
    seal_node(&mut node);
    node
}

#[test]
fn scan_orphans_reaches_current_fs_tree_via_root_tree() {
    // Current FS_TREE leaf (owner 5) carrying an ORPHAN_ITEM (objectid -5, key
    // type 48, offset = orphaned inode 257).
    let orphan_oid = u64::MAX - 4;
    let fs_leaf = build_leaf_i(
        5, /* FS_TREE */
        &[(orphan_oid, 48 /* ORPHAN_ITEM */, 257, vec![0u8; 0])],
    );
    // ROOT_TREE leaf: FS_TREE (objectid 5) ROOT_ITEM whose bytenr@176 = FS leaf.
    let mut root_item = vec![0u8; 239];
    root_item[176..184].copy_from_slice(&FS_LEAF_LOGICAL_I.to_le_bytes());
    root_item[168..176].copy_from_slice(&256u64.to_le_bytes());
    let root_leaf = build_leaf_i(
        1, /* ROOT_TREE */
        &[(5, 132 /* ROOT_ITEM */, 0, root_item)],
    );

    // Superblock: root = ROOT_LOGICAL_I, chunk_root 0, identity sys_chunk_array.
    let mut sb = vec![0u8; BTRFS_SUPER_INFO_SIZE];
    sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
    sb[0x30..0x38].copy_from_slice(&65_536u64.to_le_bytes());
    sb[0x48..0x50].copy_from_slice(&9u64.to_le_bytes()); // generation
    sb[0x50..0x58].copy_from_slice(&ROOT_LOGICAL_I.to_le_bytes()); // root
    sb[0x58..0x60].copy_from_slice(&0u64.to_le_bytes()); // chunk_root logical 0
    sb[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes());
    sb[0x94..0x98].copy_from_slice(&(NODESIZE as u32).to_le_bytes());
    let arr = 0x32busize;
    sb[arr..arr + 8].copy_from_slice(&256u64.to_le_bytes());
    sb[arr + 8] = 228;
    sb[arr + 9..arr + 17].copy_from_slice(&0u64.to_le_bytes());
    let ci = {
        let mut d = vec![0u8; 48 + 32];
        d[0..8].copy_from_slice(&CHUNK_LEN_I.to_le_bytes());
        d[24..32].copy_from_slice(&0x2u64.to_le_bytes()); // SYSTEM
        d[44..46].copy_from_slice(&1u16.to_le_bytes());
        d[46..48].copy_from_slice(&1u16.to_le_bytes());
        d[48..56].copy_from_slice(&1u64.to_le_bytes());
        d[56..64].copy_from_slice(&0u64.to_le_bytes());
        d
    };
    sb[arr + 17..arr + 17 + ci.len()].copy_from_slice(&ci);
    sb[0xa0..0xa4].copy_from_slice(&((17 + ci.len()) as u32).to_le_bytes());
    reseal_sb(&mut sb, 4096);

    let mut img = vec![0u8; CHUNK_LEN_I as usize];
    img[0..NODESIZE].copy_from_slice(&build_chunk_leaf_i());
    img[65_536..65_536 + BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb);
    img[ROOT_LOGICAL_I as usize..ROOT_LOGICAL_I as usize + NODESIZE].copy_from_slice(&root_leaf);
    img[FS_LEAF_LOGICAL_I as usize..FS_LEAF_LOGICAL_I as usize + NODESIZE]
        .copy_from_slice(&fs_leaf);

    let anomalies = audit_image(&img);
    assert!(
        anomalies.iter().any(|a| matches!(
            &a.kind,
            AnomalyKind::OrphanedInode { inode } if *inode == 257
        )),
        "fs_tree_root must resolve the current FS_TREE so scan_orphans finds inode 257, got: {anomalies:?}"
    );
}

// ── env-gated whole-image audit over the deletion oracle (real root tree) ─────

#[test]
fn full_image_audit_scans_real_fs_tree_for_orphans() {
    let Ok(path) = std::env::var("BTRFS_DEL_ORACLE") else {
        eprintln!("skip: BTRFS_DEL_ORACLE unset");
        return;
    };
    let img = std::fs::read(&path).expect("read BTRFS_DEL_ORACLE");
    // The deletion oracle is a genuine, clean btrfs image (no crafted corruption):
    // audit_image walks its real root tree + backup roots. It has no ORPHAN_ITEMs
    // and no crafted corruption, so a clean audit is expected — the value here is
    // exercising the live-root-tree scan path over a real image.
    let anomalies = audit_image(&img);
    assert!(
        anomalies.is_empty(),
        "the clean deletion oracle must audit clean, got: {anomalies:?}"
    );
}
