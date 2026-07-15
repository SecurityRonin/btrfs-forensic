//! P2 root-tree navigation + FS-tree inode / directory / path resolution.
//!
//! The superblock's `root` logical address names the **ROOT_TREE**, which holds
//! a `ROOT_ITEM` (key type [`ROOT_ITEM_KEY`]) per tree; the one keyed by
//! objectid [`FS_TREE_OBJECTID`] (5) carries the FS_TREE's own root `bytenr`
//! (logical) and `level`. The FS_TREE then holds, per inode, an `INODE_ITEM`
//! ([`INODE_ITEM_KEY`], the metadata), `INODE_REF`s ([`INODE_REF_KEY`],
//! name↔parent links), and `DIR_ITEM`/`DIR_INDEX` entries ([`DIR_ITEM_KEY`] /
//! [`DIR_INDEX_KEY`], directory children).
//!
//! Struct layouts (`btrfs_root_item`, `btrfs_inode_item`, `btrfs_timespec`,
//! `btrfs_inode_ref`, `btrfs_dir_item`) were transcribed from the on-disk ABI
//! and **verified byte-for-byte against `btrfs inspect-internal dump-tree`**
//! plus an independent mount-ro `stat` on the minted oracle (see
//! `tests/data/README.md`, "P2 ground truth").
//!
//! # Scope
//!
//! P2 navigates within the FS_TREE **leaf** the oracle presents (a single
//! `nodesize` node). The public `read_inode` / `list_dir` / `read_by_path`
//! entry points take a parsed [`Node`] so they work on the committed fixture and
//! on any FS_TREE leaf read via `read_node`. Multi-leaf FS trees (interior
//! descent within the FS tree) arrive with a later phase; here every inode /
//! directory of the oracle lives in one leaf, matching dump-tree.
//!
//! # Safety
//!
//! This parses untrusted, attacker-controllable images. Every field is read
//! through the bounds-checked [`crate::bytes`] helpers, and every `name_len` /
//! `data_len` is clamped to the item data actually present, so a lying length
//! yields a truncated name rather than an over-read or panic (the Paranoid
//! Gatekeeper standard).

use crate::bytes::{le_u16, le_u32, le_u64, u8_at};
use crate::error::BtrfsError;
use crate::node::{read_node, ChunkMap, Node};
use crate::superblock::Superblock;

/// `BTRFS_FS_TREE_OBJECTID` — the default subvolume / FS tree objectid (5).
pub const FS_TREE_OBJECTID: u64 = 5;

/// `BTRFS_FIRST_FREE_OBJECTID` — the FS_TREE's root directory inode (256); the
/// first normal (non-reserved) objectid, where path resolution begins.
pub const FS_TREE_ROOT_DIR_OBJECTID: u64 = 256;

/// `BTRFS_INODE_ITEM_KEY` — a `btrfs_inode_item` (inode metadata).
pub const INODE_ITEM_KEY: u8 = 1;

/// `BTRFS_INODE_REF_KEY` — a `btrfs_inode_ref` (name + parent-dir link).
pub const INODE_REF_KEY: u8 = 12;

/// `BTRFS_DIR_ITEM_KEY` — a `btrfs_dir_item` keyed by name hash.
pub const DIR_ITEM_KEY: u8 = 84;

/// `BTRFS_DIR_INDEX_KEY` — a `btrfs_dir_item` keyed by sequential index.
pub const DIR_INDEX_KEY: u8 = 96;

/// `BTRFS_ROOT_ITEM_KEY` — a `btrfs_root_item` in the root tree (132).
pub const ROOT_ITEM_KEY: u8 = 132;

/// `sizeof(btrfs_inode_item)` on disk = 160 bytes: the scalar block (up to
/// `reserved[4]` = 112 bytes) + four 12-byte [`Timestamp`]s.
pub const INODE_ITEM_SIZE: usize = 160;

/// `sizeof(btrfs_timespec)` on disk: `sec(u64) + nsec(u32)` = 12 bytes.
pub const TIMESTAMP_SIZE: usize = 12;

// `btrfs_inode_item` field offsets (verified vs dump-tree + stat).
mod inode_off {
    pub const GENERATION: usize = 0;
    pub const TRANSID: usize = 8;
    pub const SIZE: usize = 16;
    pub const NBYTES: usize = 24;
    pub const NLINK: usize = 40;
    pub const UID: usize = 44;
    pub const GID: usize = 48;
    pub const MODE: usize = 52;
    pub const FLAGS: usize = 64;
    // The four timestamps begin after the 112-byte scalar block.
    pub const ATIME: usize = 112;
    pub const CTIME: usize = 124;
    pub const MTIME: usize = 136;
    pub const OTIME: usize = 148;
}

// `btrfs_root_item` field offsets (the leading 160 bytes are an embedded
// `btrfs_inode_item`, so the root-item scalars start at 160).
mod root_off {
    pub const GENERATION: usize = 160;
    pub const ROOT_DIRID: usize = 168;
    pub const BYTENR: usize = 176;
    pub const LEVEL: usize = 238;
}

// `btrfs_dir_item` field offsets: a 17-byte location key, then `transid(u64)`,
// `data_len(u16)@25`, `name_len(u16)@27`, `type(u8)@29`, `name[]@30`.
mod dir_off {
    pub const NAME_LEN: usize = 27;
    pub const TYPE: usize = 29;
    pub const NAME: usize = 30;
}

/// A `btrfs_timespec`: seconds since the Unix epoch + nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timestamp {
    /// `sec` — signed seconds since 1970-01-01 (stored as `u64` on disk; btrfs
    /// timestamps are post-epoch on real images).
    pub sec: u64,
    /// `nsec` — the nanosecond fraction (`0..1_000_000_000`).
    pub nsec: u32,
}

impl Timestamp {
    /// Decode a 12-byte `btrfs_timespec` at `off` within `data`
    /// (bounds-checked; out-of-range fields read as 0).
    #[must_use]
    fn parse(data: &[u8], off: usize) -> Self {
        Timestamp {
            sec: le_u64(data, off),
            nsec: le_u32(data, off + 8),
        }
    }
}

/// A decoded `btrfs_inode_item`: file/dir metadata + the four timestamps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Inode {
    /// The inode's own objectid (the FS_TREE key objectid it was found under).
    pub objectid: u64,
    /// `generation` — the transaction id that created the inode.
    pub generation: u64,
    /// `transid` — the transaction id of the last metadata change.
    pub transid: u64,
    /// `size` — the logical file size in bytes (directory entry-name bytes for a
    /// directory).
    pub size: u64,
    /// `nbytes` — bytes actually allocated on disk (0 for a hole-only / empty).
    pub nbytes: u64,
    /// `nlink` — the hard-link count.
    pub nlink: u32,
    /// `uid` — owner user id.
    pub uid: u32,
    /// `gid` — owner group id.
    pub gid: u32,
    /// `mode` — the POSIX mode bits, including the file-type bits (e.g.
    /// `0o100644` for a regular file, `0o40755` for a directory).
    pub mode: u32,
    /// `flags` — the `BTRFS_INODE_*` flag bits.
    pub flags: u64,
    /// `atime` — last access time.
    pub atime: Timestamp,
    /// `ctime` — last status-change (inode) time.
    pub ctime: Timestamp,
    /// `mtime` — last data-modification time.
    pub mtime: Timestamp,
    /// `otime` — creation (birth) time.
    pub otime: Timestamp,
}

/// The POSIX file-type mask (`S_IFMT`): the high bits of `mode` selecting the
/// object kind.
const S_IFMT: u32 = 0o170_000;
/// `S_IFDIR` — the mode bits marking a directory.
const S_IFDIR: u32 = 0o40_000;
/// `S_IFREG` — the mode bits marking a regular file.
const S_IFREG: u32 = 0o100_000;

impl Inode {
    /// Decode a `btrfs_inode_item` (`data`) for objectid `objectid`. All four
    /// timestamps are decoded; out-of-range fields read as 0 (bounds-checked).
    #[must_use]
    fn parse(objectid: u64, data: &[u8]) -> Self {
        Inode {
            objectid,
            generation: le_u64(data, inode_off::GENERATION),
            transid: le_u64(data, inode_off::TRANSID),
            size: le_u64(data, inode_off::SIZE),
            nbytes: le_u64(data, inode_off::NBYTES),
            nlink: le_u32(data, inode_off::NLINK),
            uid: le_u32(data, inode_off::UID),
            gid: le_u32(data, inode_off::GID),
            mode: le_u32(data, inode_off::MODE),
            flags: le_u64(data, inode_off::FLAGS),
            atime: Timestamp::parse(data, inode_off::ATIME),
            ctime: Timestamp::parse(data, inode_off::CTIME),
            mtime: Timestamp::parse(data, inode_off::MTIME),
            otime: Timestamp::parse(data, inode_off::OTIME),
        }
    }

    /// `true` if the mode's type bits mark a directory.
    #[must_use]
    pub fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }

    /// `true` if the mode's type bits mark a regular file.
    #[must_use]
    pub fn is_file(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
}

/// The `btrfs_dir_item` `type` byte — the kind of the child a directory entry
/// points at. Only the members the oracle exercises are named; any other value
/// is preserved in [`DirItemType::Other`] with its raw byte (fail-loud: the
/// unknown value is shown, never dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirItemType {
    /// A regular file (`BTRFS_FT_REG_FILE` = 1).
    File,
    /// A directory (`BTRFS_FT_DIR` = 2).
    Dir,
    /// A symbolic link (`BTRFS_FT_SYMLINK` = 7).
    Symlink,
    /// Any other `BTRFS_FT_*` value, carrying the raw byte so an "unknown type"
    /// is identifiable rather than silently dropped.
    Other(u8),
}

impl DirItemType {
    /// Classify a raw `btrfs_dir_item` `type` byte.
    #[must_use]
    fn from_byte(b: u8) -> Self {
        match b {
            1 => DirItemType::File,
            2 => DirItemType::Dir,
            7 => DirItemType::Symlink,
            other => DirItemType::Other(other),
        }
    }
}

/// One directory entry: a child's name, its inode objectid, and its declared
/// type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct DirEntry {
    /// The entry name (UTF-8 lossy; a directory entry name is raw bytes on disk,
    /// decoded permissively so a non-UTF-8 name is surfaced, not dropped).
    pub name: String,
    /// The child inode's objectid (`location.objectid` of the dir item).
    pub child: u64,
    /// The child's declared type.
    pub item_type: DirItemType,
}

/// The FS_TREE root as located in the root tree: where the FS tree's own root
/// node lives and how deep it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct FsTreeRoot {
    /// `bytenr` — the FS_TREE root node's **logical** address.
    pub bytenr: u64,
    /// `level` — the FS_TREE root node's B-tree level (0 = a single leaf).
    pub level: u8,
    /// `root_dirid` — the FS tree's root directory objectid (256).
    pub root_dirid: u64,
    /// `generation` — the transaction id the FS tree root was written in.
    pub generation: u64,
}

/// Locate the FS_TREE ([`FS_TREE_OBJECTID`]) `ROOT_ITEM` by walking the root
/// tree from the superblock's `root` logical address, returning where the FS
/// tree's own root node lives.
///
/// Reads the root-tree node via [`read_node`]; if it is a leaf, scans its
/// `ROOT_ITEM`s for the FS_TREE entry. (The oracle's root tree is a single
/// leaf; interior root-tree descent is a later phase — an FS_TREE ROOT_ITEM in
/// an interior root tree would require following key-pointers, out of P2 scope.)
///
/// # Errors
///
/// - Any error from [`read_node`] translating/reading `sb.root`.
/// - [`BtrfsError::Truncated`] naming `FS_TREE ROOT_ITEM` when the root-tree
///   leaf carries no FS_TREE `ROOT_ITEM` (a loud miss, never a silent `None`).
pub fn fs_tree_root(
    image: &[u8],
    sb: &Superblock,
    chunk_map: &ChunkMap,
) -> Result<FsTreeRoot, BtrfsError> {
    let node = read_node(image, sb, chunk_map, sb.root)?;
    for (key, data) in node.leaf_items() {
        if key.objectid == FS_TREE_OBJECTID && key.key_type == ROOT_ITEM_KEY {
            return Ok(FsTreeRoot {
                bytenr: le_u64(data, root_off::BYTENR),
                level: u8_at(data, root_off::LEVEL),
                root_dirid: le_u64(data, root_off::ROOT_DIRID),
                generation: le_u64(data, root_off::GENERATION),
            });
        }
    }
    Err(BtrfsError::Truncated {
        structure: "FS_TREE ROOT_ITEM (objectid 5) in root tree",
        need: FS_TREE_OBJECTID as usize,
        have: node.header.nritems as usize,
    })
}

/// Read the `INODE_ITEM` for `objectid` from an FS_TREE `leaf`, or `None` if the
/// leaf holds no inode item for it.
#[must_use]
pub fn read_inode(leaf: &Node, objectid: u64) -> Option<Inode> {
    leaf.leaf_items()
        .find(|(key, _)| key.objectid == objectid && key.key_type == INODE_ITEM_KEY)
        .map(|(_, data)| Inode::parse(objectid, data))
}

/// List a directory's entries from an FS_TREE `leaf`: every `DIR_ITEM` /
/// `DIR_INDEX` keyed by `dir_objectid`, deduplicated by name (both a `DIR_ITEM`
/// and a `DIR_INDEX` name each child; the listing surfaces each name once).
///
/// Bounds-checked: an out-of-range `name_len` yields a name clamped to the item
/// data actually present, never an over-read.
#[must_use]
pub fn list_dir(leaf: &Node, dir_objectid: u64) -> Vec<DirEntry> {
    let mut out: Vec<DirEntry> = Vec::new();
    for (key, data) in leaf.leaf_items() {
        if key.objectid != dir_objectid
            || (key.key_type != DIR_ITEM_KEY && key.key_type != DIR_INDEX_KEY)
        {
            continue;
        }
        let Some(entry) = parse_dir_item(data) else {
            continue;
        };
        if out
            .iter()
            .any(|e| e.name == entry.name && e.child == entry.child)
        {
            continue;
        }
        out.push(entry);
    }
    out
}

/// Decode a single `btrfs_dir_item` body into a [`DirEntry`], or `None` if the
/// item is too short to hold even the fixed prefix.
///
/// The name is clamped to whatever bytes remain after the fixed prefix, so a
/// lying `name_len` truncates rather than over-reads.
#[must_use]
fn parse_dir_item(data: &[u8]) -> Option<DirEntry> {
    if data.len() < dir_off::NAME {
        return None;
    }
    let child = le_u64(data, 0); // location.objectid (start of the 17-byte key)
    let type_byte = u8_at(data, dir_off::TYPE);
    let name_len = le_u16(data, dir_off::NAME_LEN) as usize;

    // The name occupies `name_len` bytes right after the fixed prefix (the
    // optional xattr `data_len` bytes follow it). Clamp the name to the bytes
    // actually present so a hostile `name_len` truncates rather than over-reads.
    let name_start = dir_off::NAME;
    let avail = data.len().saturating_sub(name_start);
    let take = name_len.min(avail);
    let name_bytes = data.get(name_start..name_start + take).unwrap_or(&[]);

    Some(DirEntry {
        name: String::from_utf8_lossy(name_bytes).into_owned(),
        child,
        item_type: DirItemType::from_byte(type_byte),
    })
}

/// Resolve a slash-separated `path` to `(objectid, Inode)` within an FS_TREE
/// `leaf`, starting from the FS_TREE root directory ([`FS_TREE_ROOT_DIR_OBJECTID`]).
///
/// A leading slash is optional and redundant / trailing separators are ignored.
/// The empty path (`""` or `"/"`) resolves to the root directory itself.
/// Returns `None` if any component is missing or descends through a non-directory.
#[must_use]
pub fn read_by_path(leaf: &Node, path: &str) -> Option<(u64, Inode)> {
    let mut current = FS_TREE_ROOT_DIR_OBJECTID;
    let mut inode = read_inode(leaf, current)?;

    for component in path.split('/').filter(|c| !c.is_empty()) {
        // To descend, the current inode must be a directory.
        if !inode.is_dir() {
            return None;
        }
        let entry = list_dir(leaf, current)
            .into_iter()
            .find(|e| e.name == component)?;
        current = entry.child;
        inode = read_inode(leaf, current)?;
    }

    Some((current, inode))
}
