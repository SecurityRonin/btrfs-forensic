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

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::too_many_lines)]

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
    // Impossible geometry: chunk_root logical absurd (offset 0x58).
    let chunk_root_off = 65_536 + 0x58;
    b[chunk_root_off..chunk_root_off + 8].copy_from_slice(&u64::MAX.to_le_bytes());
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
