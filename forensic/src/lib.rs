//! `btrfs-forensic` — anomaly auditor + CoW deleted-file recovery for btrfs.
//!
//! btrfs is an everything-is-copy-on-write B-tree filesystem, and that CoW model
//! is the forensic lever this crate pulls:
//!
//! - **F-INTEGRITY** ([`audit_image`] / [`audit_findings`]) emits graded
//!   [`forensicnomicon::report::Finding`]s for structural anomalies: a metadata
//!   node whose crc32c does not verify (`BTRFS-CRC-MISMATCH`), the superblock's
//!   own csum failing (`BTRFS-SUPERBLOCK-CRC-MISMATCH`), the four
//!   `btrfs_root_backup` entries disagreeing with the committed generation
//!   (`BTRFS-BACKUP-ROOT-DIVERGENCE` — consistent with rollback/tampering), an
//!   `ORPHAN_ITEM` in the `FS_TREE` (`BTRFS-ORPHANED-INODE`), and geometry beyond
//!   the image (`BTRFS-IMPOSSIBLE-GEOMETRY`).
//! - **F-CARVE** ([`recover_deleted`] / [`recover_deleted_from_leaves`]) walks an
//!   OLDER generation's `FS_TREE` (reached through a `btrfs_root_backup[4]` entry)
//!   and diffs it against the CURRENT `FS_TREE`: an inode present in the old
//!   generation but absent now was deleted, and its content is carvable while the
//!   old extents survive (`BTRFS-DELETED-FILE-CARVED`).
//!
//! Built on `btrfs-core` for valid-path reading; where the audit must see the raw
//! `btrfs_root_backup` array the reader does not surface, it parses those bytes
//! directly (the reader/analyzer-split principle).
//!
//! Each finding is an **observation** ("consistent with …"); the examiner draws
//! the conclusions. Mirrors the fleet producer pattern (typed `AnomalyKind` +
//! `impl Observation` + `audit_*` → `Vec<Anomaly>` + `audit_findings` →
//! `Vec<Finding>`), as in `xfs-forensic` / `ntfs-forensic`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub use forensicnomicon::report::Severity;
use forensicnomicon::report::{Evidence, Finding, Location, Observation, Source};

use btrfs_core::{
    read_file_from_leaf, read_node, ChunkMap, Node, Superblock, BTRFS_SUPER_INFO_OFFSET,
    BTRFS_SUPER_INFO_SIZE, EXTENT_DATA_KEY, FS_TREE_OBJECTID, INODE_ITEM_KEY,
};

// ── btrfs on-disk constants the analyzer parses below `-core` ──────────────────

/// `BTRFS_ORPHAN_OBJECTID` (−5 as a `u64`) — the objectid every `ORPHAN_ITEM`
/// keys on. A non-empty set of these is a list of inodes unlinked while open /
/// pending cleanup.
const ORPHAN_OBJECTID: u64 = u64::MAX - 4;

/// `BTRFS_ORPHAN_ITEM_KEY` — the item-type byte of an `ORPHAN_ITEM` (48).
const ORPHAN_ITEM_KEY: u8 = 48;

/// Byte offset of the `btrfs_root_backup[4]` array within the superblock block
/// (`btrfs_super_block.super_roots`), verified against `dump-super -f` on the
/// oracle (`tests/data/README.md`).
const BACKUP_ROOTS_OFFSET: usize = 0xb2b;

/// `sizeof(btrfs_root_backup)` on disk (168 bytes): six `(root, gen)` u64 pairs
/// (tree/chunk/extent/fs/dev/csum) + `total_bytes`/`bytes_used`/`num_devices` +
/// padding + the level bytes.
const ROOT_BACKUP_SIZE: usize = 168;

/// The number of `btrfs_root_backup` entries the superblock retains.
const NUM_BACKUP_ROOTS: usize = 4;

// Field offsets within one `btrfs_root_backup` (verified vs dump-super).
mod backup_off {
    pub const TREE_ROOT: usize = 0;
    pub const TREE_ROOT_GEN: usize = 8;
    pub const FS_ROOT: usize = 48;
    pub const FS_ROOT_GEN: usize = 56;
}

// ── F-INTEGRITY: structural-integrity anomaly kinds ───────────────────────────

/// One decoded `btrfs_root_backup` entry — the tree-root / fs-root logical
/// addresses and the generations they were written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootBackup {
    /// `tree_root` — logical address of the root tree in this backup.
    pub tree_root: u64,
    /// `tree_root_gen` — the generation the root tree was written in.
    pub tree_root_gen: u64,
    /// `fs_root` — logical address of the `FS_TREE` root in this backup.
    pub fs_root: u64,
    /// `fs_root_gen` — the generation the `FS_TREE` root was written in.
    pub fs_root_gen: u64,
}

/// Classification of a btrfs structural-integrity anomaly (F-INTEGRITY). Each
/// variant carries the evidence needed to reproduce the observation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// The superblock's own crc32c (over `[0x20 .. sectorsize]`) does not verify
    /// — corruption or post-write tampering of the superblock.
    SuperblockCrcMismatch {
        /// Absolute byte offset of the superblock in the image (65536).
        offset: u64,
    },
    /// A metadata node/leaf whose stored crc32c does not verify — corruption or
    /// post-write tampering of that tree block.
    NodeCrcMismatch {
        /// The node's own logical address (`btrfs_header.bytenr`).
        bytenr: u64,
        /// Absolute byte offset of the node in the image.
        offset: u64,
    },
    /// A `btrfs_root_backup` entry inconsistent with the current committed
    /// generation — a backup newer than the superblock's own generation, or a
    /// backup root that does not resolve to a readable node. Consistent with a
    /// rollback / tampered backup-roots array.
    BackupRootDivergence {
        /// The backup slot (`0..4`).
        slot: usize,
        /// Human-readable reason (which field diverged and how).
        reason: &'static str,
        /// The backup generation that diverged.
        backup_gen: u64,
        /// The current committed generation.
        current_gen: u64,
    },
    /// An `ORPHAN_ITEM` (key type 48, objectid `ORPHAN_OBJECTID`) in the `FS_TREE`
    /// — an inode unlinked while still open / pending cleanup, a recovery lead.
    OrphanedInode {
        /// The orphaned inode number (the `ORPHAN_ITEM` key's `offset`).
        inode: u64,
    },
    /// A root/geometry field beyond what the image can hold — an allocation-bomb
    /// / corruption guard.
    ImpossibleGeometry {
        /// The offending field name.
        field: &'static str,
        /// The value read from the structure.
        value: u64,
        /// The sane upper bound derived from the image size / spec.
        limit: u64,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::SuperblockCrcMismatch { .. }
            | AnomalyKind::NodeCrcMismatch { .. }
            | AnomalyKind::BackupRootDivergence { .. }
            | AnomalyKind::ImpossibleGeometry { .. } => Severity::High,
            AnomalyKind::OrphanedInode { .. } => Severity::Medium,
        }
    }

    /// Stable machine-readable, scheme-prefixed code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::SuperblockCrcMismatch { .. } => "BTRFS-SUPERBLOCK-CRC-MISMATCH",
            AnomalyKind::NodeCrcMismatch { .. } => "BTRFS-CRC-MISMATCH",
            AnomalyKind::BackupRootDivergence { .. } => "BTRFS-BACKUP-ROOT-DIVERGENCE",
            AnomalyKind::OrphanedInode { .. } => "BTRFS-ORPHANED-INODE",
            AnomalyKind::ImpossibleGeometry { .. } => "BTRFS-IMPOSSIBLE-GEOMETRY",
        }
    }

    /// Human-readable, "consistent with" note.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::SuperblockCrcMismatch { offset } => format!(
                "superblock at byte {offset}: stored crc32c does not verify — consistent with corruption or post-write tampering"
            ),
            AnomalyKind::NodeCrcMismatch { bytenr, offset } => format!(
                "metadata node at logical {bytenr} (byte {offset}): stored crc32c does not verify — consistent with corruption or post-write tampering"
            ),
            AnomalyKind::BackupRootDivergence {
                slot,
                reason,
                backup_gen,
                current_gen,
            } => format!(
                "btrfs_root_backup[{slot}]: {reason} (backup generation {backup_gen} vs current {current_gen}) — consistent with rollback or a tampered backup-roots array"
            ),
            AnomalyKind::OrphanedInode { inode } => format!(
                "FS_TREE ORPHAN_ITEM for inode {inode} — an inode unlinked while still open or pending cleanup, a recovery lead"
            ),
            AnomalyKind::ImpossibleGeometry {
                field,
                value,
                limit,
            } => format!(
                "geometry field {field} = {value} exceeds the sane bound {limit} for this image — consistent with corruption or an allocation-bomb"
            ),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::SuperblockCrcMismatch { offset } => vec![Evidence {
                field: "superblock".to_string(),
                value: "crc32c mismatch".to_string(),
                location: Some(Location::ByteOffset(*offset)),
            }],
            AnomalyKind::NodeCrcMismatch { bytenr, offset } => vec![Evidence {
                field: "node".to_string(),
                value: format!("logical {bytenr}"),
                location: Some(Location::ByteOffset(*offset)),
            }],
            AnomalyKind::BackupRootDivergence {
                slot,
                reason,
                backup_gen,
                current_gen,
            } => vec![Evidence {
                field: "btrfs_root_backup".to_string(),
                value: format!("slot {slot}: {reason} gen={backup_gen} current={current_gen}"),
                location: Some(Location::Other {
                    space: "btrfs:backup_root".to_string(),
                    value: *slot as u64,
                }),
            }],
            AnomalyKind::OrphanedInode { inode } => vec![Evidence {
                field: "orphan_item".to_string(),
                value: format!("inode {inode}"),
                location: Some(Location::Other {
                    space: "btrfs:inode".to_string(),
                    value: *inode,
                }),
            }],
            AnomalyKind::ImpossibleGeometry {
                field,
                value,
                limit,
            } => vec![Evidence {
                field: (*field).to_string(),
                value: format!("{value} (limit {limit})"),
                location: None,
            }],
        }
    }
}

/// A btrfs structural-integrity anomaly: an observation graded by severity, with
/// a stable code and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly with its evidence.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

// ── F-INTEGRITY: the image auditor ────────────────────────────────────────────

/// Audit a whole btrfs image for structural-integrity anomalies (F-INTEGRITY):
/// verify the superblock csum, sweep the tree nodes reachable from the
/// superblock roots for crc32c mismatches, check the `btrfs_root_backup[4]`
/// array for divergence, scan the `FS_TREE` for `ORPHAN_ITEM`s, and guard against
/// impossible geometry.
///
/// A clean image yields an empty vector. Malformed input never panics.
#[must_use]
pub fn audit_image(image: &[u8]) -> Vec<Anomaly> {
    let mut out = Vec::new();

    // Locate + parse the superblock at physical offset 65536. Too small, or not
    // btrfs: nothing to audit (never panic).
    let sb_start = BTRFS_SUPER_INFO_OFFSET as usize;
    let Some(sb_block) = image.get(sb_start..sb_start.saturating_add(BTRFS_SUPER_INFO_SIZE)) else {
        return out;
    };
    let Ok(sb) = Superblock::parse(sb_block) else {
        return out;
    };

    // The superblock's own crc32c.
    if sb.crc_valid == Some(false) {
        out.push(Anomaly::new(AnomalyKind::SuperblockCrcMismatch {
            offset: BTRFS_SUPER_INFO_OFFSET,
        }));
    }

    let image_len = image.len() as u64;

    // Impossible geometry: a root/chunk_root logical address the chunk map cannot
    // translate to a readable node within the image.
    let map = ChunkMap::walk(image, &sb).unwrap_or_default();
    check_root_reachable(&mut out, image, &sb, &map, "root", sb.root);
    check_root_reachable(&mut out, image, &sb, &map, "chunk_root", sb.chunk_root);

    // Node crc32c sweep over every node reachable from the superblock roots and
    // the backup roots (bounded, dedup by logical address).
    sweep_node_crcs(&mut out, image, &sb, &map);

    // btrfs_root_backup[4] divergence vs the current committed generation.
    check_backup_roots(&mut out, sb_block, sb.generation, image_len);

    // ORPHAN_ITEM scan across the FS_TREE leaf.
    scan_orphans(&mut out, image, &sb, &map);

    out
}

/// Flag a root logical address that does not resolve to a readable node.
fn check_root_reachable(
    out: &mut Vec<Anomaly>,
    image: &[u8],
    sb: &Superblock,
    map: &ChunkMap,
    field: &'static str,
    logical: u64,
) {
    if logical == 0 {
        return; // 0 = "none" (e.g. log_root); not a geometry error
    }
    if read_node(image, sb, map, logical).is_err() {
        out.push(Anomaly::new(AnomalyKind::ImpossibleGeometry {
            field,
            value: logical,
            limit: image.len() as u64,
        }));
    }
}

/// Decode the `btrfs_root_backup[4]` array from the superblock block.
#[must_use]
pub fn parse_backup_roots(sb_block: &[u8]) -> Vec<RootBackup> {
    let mut out = Vec::with_capacity(NUM_BACKUP_ROOTS);
    for slot in 0..NUM_BACKUP_ROOTS {
        let base = BACKUP_ROOTS_OFFSET + slot * ROOT_BACKUP_SIZE;
        let Some(entry) = sb_block.get(base..base.saturating_add(ROOT_BACKUP_SIZE)) else {
            break;
        };
        out.push(RootBackup {
            tree_root: le_u64(entry, backup_off::TREE_ROOT),
            tree_root_gen: le_u64(entry, backup_off::TREE_ROOT_GEN),
            fs_root: le_u64(entry, backup_off::FS_ROOT),
            fs_root_gen: le_u64(entry, backup_off::FS_ROOT_GEN),
        });
    }
    out
}

/// Flag any `btrfs_root_backup` entry inconsistent with the current committed
/// generation: a backup generation newer than the superblock's own generation
/// (a backup cannot legitimately post-date the committed state), or a backup
/// root logical address past the image.
fn check_backup_roots(out: &mut Vec<Anomaly>, sb_block: &[u8], current_gen: u64, image_len: u64) {
    for (slot, b) in parse_backup_roots(sb_block).iter().enumerate() {
        // A backup newer than the current committed generation is impossible on a
        // clean filesystem — consistent with a rolled-back or edited backup array.
        if b.tree_root_gen > current_gen {
            out.push(Anomaly::new(AnomalyKind::BackupRootDivergence {
                slot,
                reason: "tree_root generation newer than the current committed generation",
                backup_gen: b.tree_root_gen,
                current_gen,
            }));
        } else if b.fs_root_gen > current_gen {
            out.push(Anomaly::new(AnomalyKind::BackupRootDivergence {
                slot,
                reason: "fs_root generation newer than the current committed generation",
                backup_gen: b.fs_root_gen,
                current_gen,
            }));
        } else if b.tree_root != 0 && b.tree_root >= image_len {
            // A non-zero backup root that cannot possibly lie within the image.
            out.push(Anomaly::new(AnomalyKind::BackupRootDivergence {
                slot,
                reason: "tree_root logical address lies past the end of the image",
                backup_gen: b.tree_root_gen,
                current_gen,
            }));
        }
    }
}

/// Sweep node crc32c over every node reachable from the superblock roots and the
/// backup roots. Bounded by a visit budget; dedup by logical address so a shared
/// subtree is checked once.
fn sweep_node_crcs(out: &mut Vec<Anomaly>, image: &[u8], sb: &Superblock, map: &ChunkMap) {
    let mut seen: Vec<u64> = Vec::new();
    let mut stack: Vec<u64> = Vec::new();

    // Seeds: the live roots and every backup root (tree + fs).
    for logical in [sb.root, sb.chunk_root] {
        if logical != 0 {
            stack.push(logical);
        }
    }
    let sb_start = BTRFS_SUPER_INFO_OFFSET as usize;
    if let Some(sb_block) = image.get(sb_start..sb_start.saturating_add(BTRFS_SUPER_INFO_SIZE)) {
        for b in parse_backup_roots(sb_block) {
            for logical in [b.tree_root, b.fs_root] {
                if logical != 0 {
                    stack.push(logical);
                }
            }
        }
    } // cov:unreachable: the else arm is dead — audit_image validated this same superblock slice before calling the sweep

    let mut budget: usize = 8192;
    while let Some(logical) = stack.pop() {
        if budget == 0 {
            break; // cov:unreachable: the oracle trees are single leaves; only a >8192-node graph exhausts this, not craftable as a committed fixture
        }
        budget -= 1;
        if seen.contains(&logical) {
            continue;
        }
        seen.push(logical);

        let Ok(node) = read_node(image, sb, map, logical) else {
            continue;
        };
        // A swept block is a genuine metadata node iff its header self-reference
        // (`bytenr == logical`) and `fsid` match the filesystem. This keeps
        // unallocated / zeroed space (bytenr 0, blank fsid) from mis-flagging as
        // a corrupt node — the same self-consistency filter the xfs auditor uses
        // for inodes (`di_ino == ino`). A real corrupt node still self-references
        // its own logical address (the csum covers the body, not the header's
        // bytenr) so a genuine tamper is not hidden by this filter.
        if node.header.bytenr != logical || node.header.fsid != sb.fsid {
            continue;
        }
        let offset = map
            .logical_to_physical(logical)
            .map_or(logical, |(_devid, phys)| phys);
        if node.crc_valid == Some(false) {
            out.push(Anomaly::new(AnomalyKind::NodeCrcMismatch {
                bytenr: node.header.bytenr,
                offset,
            }));
        }
        // Descend into interior children so a corrupt lower node is reached too.
        if !node.is_leaf() {
            for kp in node.key_ptrs() {
                if kp.blockptr != 0 {
                    stack.push(kp.blockptr);
                }
            }
        }
    }
}

/// Scan every reachable `FS_TREE` leaf for `ORPHAN_ITEM`s (key type 48, objectid
/// `ORPHAN_OBJECTID`). Each names an inode unlinked while open / pending cleanup.
///
/// `FS_TREE` roots are reached two ways: the current tree via the root tree
/// (`fs_tree_root`), and the older generations named directly in the
/// `btrfs_root_backup[4]` array. Both are scanned so an orphan lead survives even
/// when the live root tree is unreadable; results are deduplicated by inode.
fn scan_orphans(out: &mut Vec<Anomaly>, image: &[u8], sb: &Superblock, map: &ChunkMap) {
    let mut fs_roots: Vec<u64> = Vec::new();
    if let Ok(root_item) = btrfs_core::fs_tree_root(image, sb, map) {
        fs_roots.push(root_item.bytenr);
    }
    let sb_start = BTRFS_SUPER_INFO_OFFSET as usize;
    if let Some(sb_block) = image.get(sb_start..sb_start.saturating_add(BTRFS_SUPER_INFO_SIZE)) {
        for b in parse_backup_roots(sb_block) {
            if b.fs_root != 0 && !fs_roots.contains(&b.fs_root) {
                fs_roots.push(b.fs_root);
            }
        }
    } // cov:unreachable: the else arm is dead — audit_image validated this same superblock slice before calling scan_orphans

    let mut seen_inodes: Vec<u64> = Vec::new();
    for logical in fs_roots {
        let Ok(leaf) = read_node(image, sb, map, logical) else {
            continue;
        };
        // Only a genuine FS_TREE leaf carries FS_TREE orphan items.
        if leaf.header.owner != FS_TREE_OBJECTID {
            continue;
        }
        for (key, _data) in leaf.leaf_items() {
            if key.objectid == ORPHAN_OBJECTID
                && key.key_type == ORPHAN_ITEM_KEY
                && !seen_inodes.contains(&key.offset)
            {
                seen_inodes.push(key.offset);
                out.push(Anomaly::new(AnomalyKind::OrphanedInode {
                    inode: key.offset,
                }));
            }
        }
    }
}

/// Audit an image and convert each F-INTEGRITY anomaly to a canonical [`Finding`]
/// tagged with `scope`.
#[must_use]
pub fn audit_findings(image: &[u8], scope: &str) -> Vec<Finding> {
    let source = Source {
        analyzer: "btrfs-forensic".to_string(),
        scope: scope.to_string(),
        version: None,
    };
    audit_image(image)
        .iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
}

// ── F-CARVE: CoW deleted-file recovery ────────────────────────────────────────

/// A file recovered from an older CoW generation: present in a previous
/// `FS_TREE` (reached through a `btrfs_root_backup` entry) but absent from the
/// current `FS_TREE`, so it was deleted. Its content was carved from the old
/// extents while they survive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFile {
    /// The recovered file's name (its directory-entry name in the old `FS_TREE`).
    pub path: String,
    /// The inode objectid.
    pub inode: u64,
    /// The old `FS_TREE` generation the file was recovered from.
    pub generation: u64,
    /// The inode's logical size in bytes.
    pub size: u64,
    /// The carved file content (truncated to `size`).
    pub content: Vec<u8>,
    /// The carved content's sha256, lower-hex (the recovery gate).
    pub content_sha256: String,
}

/// Recover deleted files by diffing an OLDER-generation `FS_TREE` `old` against
/// the CURRENT `FS_TREE` `current`: an inode present in `old` but absent from
/// `current` was deleted. Each such inode's content is carved from the old extents
/// via `image` + `map` (inline extents live in the leaf, so an empty
/// [`ChunkMap`] and empty `image` suffice for them; a regular extent needs the
/// real logical→physical `map` and the `image` bytes).
///
/// This is the leaf-level entry point (used by the committed deletion-oracle
/// fixtures with an empty map); [`recover_deleted`] wraps it over a whole image,
/// locating `old` and `current` through the superblock roots and backup roots and
/// passing the real chunk map.
///
/// Malformed input never panics.
#[must_use]
pub fn recover_deleted_from_leaves(
    old: &Node,
    current: &Node,
    image: &[u8],
    map: &ChunkMap,
    sectorsize: u32,
) -> Vec<RecoveredFile> {
    // Only diff FS_TREEs (owner 5); a non-FS_TREE pair yields nothing.
    if old.header.owner != FS_TREE_OBJECTID {
        return Vec::new();
    }

    // The inode set of each leaf, and a name map (child inode -> its dir-entry
    // name) from the old leaf's DIR_ITEM/DIR_INDEX items.
    let current_inodes = inode_set(current);
    let old_names = dir_names(old);
    let generation = old.header.generation;

    let mut out = Vec::new();
    for (key, data) in old.leaf_items() {
        if key.key_type != INODE_ITEM_KEY {
            continue;
        }
        let ino = key.objectid;
        // Reserved objectids (root dir 256 and below) are not user deletions.
        if ino < 257 {
            continue;
        }
        if current_inodes.contains(&ino) {
            continue; // still present → not deleted
        }
        // Only carve a file that also still has an EXTENT_DATA item in the old
        // leaf (a directory or a metadata-only inode has nothing to carve).
        if !old
            .leaf_items()
            .any(|(k, _)| k.objectid == ino && k.key_type == EXTENT_DATA_KEY)
        {
            continue;
        }
        let size = le_u64(data, INODE_SIZE_FIELD);
        // Carve the content from the old leaf via the reader (inline extents live
        // in the leaf; regular extents are read from `image` through `map`).
        let content = read_file_from_leaf(old, image, map, sectorsize, ino).unwrap_or_default();
        let content_sha256 = sha256_hex(&content);
        out.push(RecoveredFile {
            path: old_names
                .get_name(ino)
                .unwrap_or_else(|| format!("inode_{ino}")),
            inode: ino,
            generation,
            size,
            content,
            content_sha256,
        });
    }
    out
}

/// Recover deleted files over a whole btrfs `image`: parse the superblock, read
/// the CURRENT `FS_TREE` (via the root tree), then walk each older `FS_TREE` root
/// in the `btrfs_root_backup[4]` array and diff it against the current `FS_TREE`,
/// carving any inode present in the old generation but absent now.
///
/// Recovery succeeds only while the old extents are unoverwritten; if the current
/// kernel did not retain an older `FS_TREE` root, this returns nothing rather than
/// fabricating a result.
///
/// Malformed input never panics.
#[must_use]
pub fn recover_deleted(image: &[u8]) -> Vec<RecoveredFile> {
    let sb_start = BTRFS_SUPER_INFO_OFFSET as usize;
    let Some(sb_block) = image.get(sb_start..sb_start.saturating_add(BTRFS_SUPER_INFO_SIZE)) else {
        return Vec::new();
    };
    let Ok(sb) = Superblock::parse(sb_block) else {
        return Vec::new();
    };
    let map = ChunkMap::walk(image, &sb).unwrap_or_default();

    // The current FS_TREE leaf (via the live root tree).
    let Ok(cur_root) = btrfs_core::fs_tree_root(image, &sb, &map) else {
        return Vec::new();
    };
    let Ok(current) = read_node(image, &sb, &map, cur_root.bytenr) else {
        return Vec::new(); // cov:unreachable: fs_tree_root just resolved this bytenr through the same map
    };

    // Diff each older FS_TREE root retained in the backup array against current.
    let mut out: Vec<RecoveredFile> = Vec::new();
    for b in parse_backup_roots(sb_block) {
        if b.fs_root == 0 || b.fs_root == cur_root.bytenr {
            continue;
        }
        let Ok(old) = read_node(image, &sb, &map, b.fs_root) else {
            continue; // cov:unreachable: a self-consistent image's backup fs_root resolves through the same map; guarded for a corrupt backup pointer
        };
        for rec in recover_deleted_from_leaves(&old, &current, image, &map, sb.sectorsize) {
            if !out.iter().any(|r| r.inode == rec.inode) {
                out.push(rec);
            }
        }
    }
    out
}

// ── shared private helpers ────────────────────────────────────────────────────

/// `btrfs_inode_item.size` field offset within an `INODE_ITEM`'s data.
const INODE_SIZE_FIELD: usize = 16;

// `btrfs_dir_item` field offsets (child location key + name).
mod dir_off {
    pub const NAME_LEN: usize = 27;
    pub const NAME: usize = 30;
}

/// `BTRFS_DIR_ITEM_KEY` / `BTRFS_DIR_INDEX_KEY` — directory-entry item types.
const DIR_ITEM_KEY: u8 = 84;
const DIR_INDEX_KEY: u8 = 96;

/// The set of `INODE_ITEM` objectids present in a leaf.
fn inode_set(leaf: &Node) -> Vec<u64> {
    leaf.leaf_items()
        .filter(|(k, _)| k.key_type == INODE_ITEM_KEY)
        .map(|(k, _)| k.objectid)
        .collect()
}

/// A child-inode → directory-entry-name map built from a leaf's `DIR_ITEM` /
/// `DIR_INDEX` items (the entry's `location.objectid` is the child inode).
struct DirNames {
    entries: Vec<(u64, String)>,
}

impl DirNames {
    fn get_name(&self, ino: u64) -> Option<String> {
        self.entries
            .iter()
            .find(|(child, _)| *child == ino)
            .map(|(_, name)| name.clone())
    }
}

/// Build the child-inode → name map from a leaf's directory items.
fn dir_names(leaf: &Node) -> DirNames {
    let mut entries: Vec<(u64, String)> = Vec::new();
    for (key, data) in leaf.leaf_items() {
        if key.key_type != DIR_ITEM_KEY && key.key_type != DIR_INDEX_KEY {
            continue;
        }
        if data.len() < dir_off::NAME {
            continue;
        }
        let child = le_u64(data, 0); // location.objectid
        let name_len = le_u16(data, dir_off::NAME_LEN) as usize;
        let avail = data.len().saturating_sub(dir_off::NAME);
        let take = name_len.min(avail);
        let name_bytes = data.get(dir_off::NAME..dir_off::NAME + take).unwrap_or(&[]);
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        if entries.iter().all(|(c, _)| *c != child) {
            entries.push((child, name));
        }
    }
    DirNames { entries }
}

/// Bounds-checked little-endian `u16` read (yields `0` out of range). The
/// analyzer parses raw node/superblock bytes directly (the reader/analyzer
/// split), so it carries its own panic-free readers.
fn le_u16(d: &[u8], o: usize) -> u16 {
    d.get(o..o.saturating_add(2))
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map_or(0, u16::from_le_bytes)
}

/// Bounds-checked little-endian `u64` read (yields `0` out of range).
fn le_u64(d: &[u8], o: usize) -> u64 {
    d.get(o..o.saturating_add(8))
        .and_then(|b| <[u8; 8]>::try_from(b).ok())
        .map_or(0, u64::from_le_bytes)
}

/// SHA-256 of `data`, lower-hex. A small pure-Rust implementation (the crate
/// forbids `unsafe` and this avoids a heavyweight dependency for a single hash);
/// its output is the recovery gate compared to the mint-recorded ground truth.
fn sha256_hex(data: &[u8]) -> String {
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
            wi.clone_from(&u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]));
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
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(64);
    for x in h {
        let _ = write!(hex, "{x:08x}");
    }
    hex
}

#[cfg(test)]
mod unit {
    use super::{le_u16, le_u64, parse_backup_roots, sha256_hex};

    #[test]
    fn parse_backup_roots_truncates_a_short_superblock() {
        // A superblock block that ends inside the backup array yields only the
        // whole entries that fit (the `break` on a partial entry) — never an
        // over-read. One-and-a-half entries' worth of bytes → exactly one entry.
        let mut sb = vec![0u8; super::BACKUP_ROOTS_OFFSET + super::ROOT_BACKUP_SIZE + 40];
        // slot 0 tree_root = 12345 so the decoded entry is identifiable.
        let base = super::BACKUP_ROOTS_OFFSET;
        sb[base..base + 8].copy_from_slice(&12_345u64.to_le_bytes());
        let backups = parse_backup_roots(&sb);
        assert_eq!(backups.len(), 1, "only the one whole entry that fits");
        assert_eq!(backups[0].tree_root, 12_345);

        // A block ending before the array starts yields nothing.
        let tiny = vec![0u8; super::BACKUP_ROOTS_OFFSET - 1];
        assert!(parse_backup_roots(&tiny).is_empty());
    }

    #[test]
    fn sha256_of_empty_and_known_input() {
        // Empty-input digest (the single padding block), and a known vector.
        assert_eq!(
            sha256_hex(&[]),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn le_readers_yield_zero_out_of_range() {
        assert_eq!(le_u16(&[0x12], 0), 0);
        assert_eq!(le_u16(&[0x34, 0x12], 0), 0x1234);
        assert_eq!(le_u64(&[0, 0, 0], 0), 0);
        assert_eq!(le_u64(&[1, 0, 0, 0, 0, 0, 0, 0], 0), 1);
    }
}
