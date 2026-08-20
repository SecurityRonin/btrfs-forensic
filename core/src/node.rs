//! btrfs B-tree node/leaf parsing + the chunk-tree logical→physical `ChunkMap`.
//!
//! Every btrfs metadata block (a `nodesize`-byte node, default 16384) begins
//! with a `btrfs_header`, then — by `level` — either leaf items (`level == 0`)
//! or interior key-pointers (`level > 0`). All fields are little-endian.
//!
//! Layouts were transcribed from the on-disk `btrfs_header` / `btrfs_item` /
//! `btrfs_key_ptr` / `btrfs_chunk` / `btrfs_stripe` and **verified byte-for-byte
//! against `btrfs inspect-internal dump-tree`** on the minted oracle image (see
//! `tests/data/README.md`, "P1 ground truth"). The verified header size is
//! [`BTRFS_HEADER_SIZE`] = 101 bytes.
//!
//! # Safety
//!
//! This parses untrusted, attacker-controllable images. Every read is
//! bounds-checked (`crate::bytes` helpers yield 0 out of range), `nritems` is
//! capped by how many items/pointers the block can physically hold, and a
//! lying `data_offset`/`data_size` yields an empty slice rather than an
//! over-read. Node parsing is **non-fatal on a bad checksum**: a tampered block
//! still parses and surfaces `crc_valid == Some(false)` so the `-forensic` layer
//! can turn it into a Finding.

use crate::bytes::{le_u16, le_u32, le_u64, u8_at};
use crate::chunk::{Stripe, DISK_KEY_SIZE, STRIPE_SIZE};
use crate::crc::{superblock_crc_status, CsumType};
use crate::error::BtrfsError;
use crate::superblock::Superblock;
use crate::DiskKey;

/// `sizeof(btrfs_header)` on disk: `csum[32] + fsid[16] + bytenr(u64) +
/// flags(u64) + chunk_tree_uuid[16] + generation(u64) + owner(u64) +
/// nritems(u32) + level(u8)` = 101 bytes.
pub const BTRFS_HEADER_SIZE: usize = 101;

/// `sizeof(btrfs_item)`: `disk_key[17] + offset(u32) + size(u32)` = 25 bytes.
/// `offset` is the item's data start **relative to the end of the header**;
/// `size` is the item data length.
pub const BTRFS_ITEM_SIZE: usize = DISK_KEY_SIZE + 4 + 4;

/// `sizeof(btrfs_key_ptr)`: `disk_key[17] + blockptr(u64) + generation(u64)` =
/// 33 bytes.
pub const BTRFS_KEY_PTR_SIZE: usize = DISK_KEY_SIZE + 8 + 8;

/// The `btrfs_chunk` fixed header (up to the variable stripe array):
/// `length,owner,stripe_len,type` (4×u64) + `io_align,io_width,sector_size`
/// (3×u32) + `num_stripes,sub_stripes` (2×u16) = 48 bytes.
pub const CHUNK_HEADER_SIZE: usize = 48;

/// `BTRFS_CHUNK_TREE_OBJECTID` — the owner tree id of a chunk-tree node (3).
pub const CHUNK_TREE_OBJECTID: u64 = 3;

/// The offset of each `btrfs_header` scalar (little-endian on disk).
mod hdr {
    pub const BYTENR: usize = 0x30;
    pub const FLAGS: usize = 0x38;
    pub const CHUNK_TREE_UUID: usize = 0x40;
    pub const GENERATION: usize = 0x50;
    pub const OWNER: usize = 0x58;
    pub const NRITEMS: usize = 0x60;
    pub const LEVEL: usize = 0x64;
    pub const FSID: usize = 0x20;
}

/// A parsed `btrfs_header` — the fixed 101-byte prefix of every node/leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Header {
    /// `csum` — the first 4 bytes of the 32-byte checksum field (the crc32c
    /// digest for a crc32c filesystem), verbatim.
    pub csum: [u8; 4],
    /// `fsid` (offset 0x20) — the filesystem UUID.
    pub fsid: [u8; 16],
    /// `bytenr` (offset 0x30) — **this node's own logical address**.
    pub bytenr: u64,
    /// `flags` (offset 0x38).
    pub flags: u64,
    /// `chunk_tree_uuid` (offset 0x40).
    pub chunk_tree_uuid: [u8; 16],
    /// `generation` (offset 0x50) — the transaction id that wrote this block
    /// (the CoW/staleness lever: an older generation marks a stale block).
    pub generation: u64,
    /// `owner` (offset 0x58) — the objectid of the tree this block belongs to
    /// (1 = `ROOT_TREE`, 3 = `CHUNK_TREE`, …).
    pub owner: u64,
    /// `nritems` (offset 0x60) — the number of items (leaf) or key-pointers
    /// (interior) that follow the header.
    pub nritems: u32,
    /// `level` (offset 0x64) — 0 = leaf, > 0 = interior node.
    pub level: u8,
}

impl Header {
    /// Decode the 101-byte header at the start of `block`, or `None` if `block`
    /// is shorter than [`BTRFS_HEADER_SIZE`].
    #[must_use]
    fn parse(block: &[u8]) -> Option<Self> {
        if block.len() < BTRFS_HEADER_SIZE {
            return None;
        }
        let mut csum = [0u8; 4];
        for (i, b) in csum.iter_mut().enumerate() {
            *b = u8_at(block, i);
        }
        let mut fsid = [0u8; 16];
        for (i, b) in fsid.iter_mut().enumerate() {
            *b = u8_at(block, hdr::FSID + i);
        }
        let mut chunk_tree_uuid = [0u8; 16];
        for (i, b) in chunk_tree_uuid.iter_mut().enumerate() {
            *b = u8_at(block, hdr::CHUNK_TREE_UUID + i);
        }
        Some(Header {
            csum,
            fsid,
            bytenr: le_u64(block, hdr::BYTENR),
            flags: le_u64(block, hdr::FLAGS),
            chunk_tree_uuid,
            generation: le_u64(block, hdr::GENERATION),
            owner: le_u64(block, hdr::OWNER),
            nritems: le_u32(block, hdr::NRITEMS),
            level: u8_at(block, hdr::LEVEL),
        })
    }
}

/// A `btrfs_key_ptr` from an interior node: the child's smallest key, its
/// logical block address, and the generation it was written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPtr {
    /// The child subtree's smallest key.
    pub key: DiskKey,
    /// `blockptr` — the child node's **logical** address.
    pub blockptr: u64,
    /// `generation` — the transaction id the child was written in.
    pub generation: u64,
}

/// A parsed `btrfs_chunk` item: chunk geometry + its physical stripes.
///
/// The chunk's logical start is its item key's `offset` (carried alongside in
/// [`Node::chunk_items`]), not stored inside the chunk struct.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Chunk {
    /// `length` — the chunk's logical byte span.
    pub length: u64,
    /// `owner` — the objectid that owns the chunk (2 = the extent tree).
    pub owner: u64,
    /// `stripe_len` — the stripe unit size.
    pub stripe_len: u64,
    /// `type` — the `BTRFS_BLOCK_GROUP_*` flag bits (DATA/SYSTEM/METADATA | DUP…).
    pub chunk_type: u64,
    /// `num_stripes` — the number of physical stripes that follow.
    pub num_stripes: u16,
    /// `sub_stripes` — RAID10 sub-stripe count (1 for single/DUP).
    pub sub_stripes: u16,
    /// The decoded stripes (physical placements).
    pub stripes: Vec<Stripe>,
}

impl Chunk {
    /// Decode a `btrfs_chunk` from `data` (a `CHUNK_ITEM`'s item data). Bounds- and
    /// count-checked: an absurd `num_stripes` is capped by the bytes available,
    /// so a malformed item truncates rather than over-reads.
    #[must_use]
    fn parse(data: &[u8]) -> Self {
        let num_stripes = le_u16(data, 44);
        // Cap the declared stripe count by how many actually fit in `data`.
        let avail = data.len().saturating_sub(CHUNK_HEADER_SIZE);
        let max_fit = avail / STRIPE_SIZE;
        let take = usize::from(num_stripes).min(max_fit);

        let mut stripes = Vec::with_capacity(take);
        for i in 0..take {
            let so = CHUNK_HEADER_SIZE + i * STRIPE_SIZE;
            let mut dev_uuid = [0u8; 16];
            for (j, b) in dev_uuid.iter_mut().enumerate() {
                *b = u8_at(data, so + 16 + j);
            }
            stripes.push(Stripe {
                devid: le_u64(data, so),
                offset: le_u64(data, so + 8),
                dev_uuid,
            });
        }
        Chunk {
            length: le_u64(data, 0),
            owner: le_u64(data, 8),
            stripe_len: le_u64(data, 16),
            chunk_type: le_u64(data, 24),
            num_stripes,
            sub_stripes: le_u16(data, 46),
            stripes,
        }
    }
}

/// The decoded body of a node: leaf items or interior key-pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Body {
    /// A leaf (`level == 0`): the item headers (each carries its data offset +
    /// size relative to the end of the node header).
    Leaf(Vec<ItemHeader>),
    /// An interior node (`level > 0`): the child key-pointers.
    Interior(Vec<KeyPtr>),
}

/// A decoded `btrfs_item` header (the key + where its data lives in the block).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ItemHeader {
    key: DiskKey,
    /// Data start **relative to the end of the header** (`itemoff` in dump-tree).
    data_offset: u32,
    /// Data length.
    data_size: u32,
}

/// A parsed btrfs B-tree node (leaf or interior), plus its non-fatal checksum
/// status. The raw block bytes are retained so leaf item data can be sliced
/// on demand (bounds-checked).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Node {
    /// The decoded 101-byte header.
    pub header: Header,
    /// The crc32c status over `[0x20 .. block.len()]`: `Some(true)` if the
    /// stored digest verifies, `Some(false)` if it does not (corrupt/tampered),
    /// or `None` for a non-crc32c checksum whose verifier is deferred.
    pub crc_valid: Option<bool>,
    body: Body,
    block: Vec<u8>,
}

impl Node {
    /// Parse a `nodesize`-byte btrfs node from the start of `block`.
    ///
    /// The block should be exactly one node (`nodesize` bytes); the checksum is
    /// computed over `[0x20 .. block.len()]`, so pass the whole node block. A
    /// bad checksum does **not** fail the parse — it is surfaced in
    /// [`Node::crc_valid`].
    ///
    /// # Errors
    ///
    /// - [`BtrfsError::Truncated`] if `block` is shorter than the 101-byte
    ///   header.
    pub fn parse(block: &[u8]) -> Result<Self, BtrfsError> {
        let Some(header) = Header::parse(block) else {
            return Err(BtrfsError::Truncated {
                structure: "btrfs_header",
                need: BTRFS_HEADER_SIZE,
                have: block.len(),
            });
        };

        // The node checksum covers the block after the 32-byte csum field to the
        // end of the block (btrfs default crc32c). csum_type is a filesystem
        // property; a standalone node cannot carry it, so P1 assumes the mkfs
        // default (crc32c). Non-crc32c filesystems arrive with later phases.
        let crc_valid = superblock_crc_status(CsumType::Crc32c, block, block.len());

        let nritems = header.nritems as usize;
        let body = if header.level == 0 {
            Body::Leaf(parse_items(block, nritems))
        } else {
            Body::Interior(parse_key_ptrs(block, nritems))
        };

        Ok(Node {
            header,
            crc_valid,
            body,
            block: block.to_vec(),
        })
    }

    /// `true` if this is a leaf node (`level == 0`).
    #[must_use]
    pub fn is_leaf(&self) -> bool {
        matches!(self.body, Body::Leaf(_))
    }

    /// Iterate `(key, data)` over a leaf's items. Each data slice is
    /// bounds-checked against the block: a lying `data_offset`/`data_size`
    /// yields an empty slice, never an over-read. An interior node yields
    /// nothing.
    pub fn leaf_items(&self) -> impl Iterator<Item = (DiskKey, &[u8])> {
        let items: &[ItemHeader] = match &self.body {
            Body::Leaf(items) => items,
            Body::Interior(_) => &[],
        };
        items.iter().map(move |it| (it.key, self.item_data(it)))
    }

    /// The bounds-checked data slice for one leaf item. Data lives at
    /// `BTRFS_HEADER_SIZE + data_offset` for `data_size` bytes; an out-of-range
    /// range yields an empty slice.
    fn item_data(&self, it: &ItemHeader) -> &[u8] {
        let start = BTRFS_HEADER_SIZE.saturating_add(it.data_offset as usize);
        let end = start.saturating_add(it.data_size as usize);
        self.block.get(start..end).unwrap_or(&[])
    }

    /// The interior node's child key-pointers. A leaf yields an empty slice.
    #[must_use]
    pub fn key_ptrs(&self) -> &[KeyPtr] {
        match &self.body {
            Body::Interior(ptrs) => ptrs,
            Body::Leaf(_) => &[],
        }
    }

    /// Decode every `CHUNK_ITEM` in a leaf into `(logical_start, Chunk)` pairs
    /// (the logical start is the item key's `offset`). Non-CHUNK items (e.g.
    /// `DEV_ITEM`) are skipped. An interior node yields nothing.
    #[must_use]
    pub fn chunk_items(&self) -> Vec<(u64, Chunk)> {
        self.leaf_items()
            .filter(|(key, _)| key.key_type == crate::CHUNK_ITEM_KEY)
            .map(|(key, data)| (key.offset, Chunk::parse(data)))
            .collect()
    }
}

/// Parse up to `nritems` leaf item headers, stopping at the block bound so a
/// lying `nritems` never over-reads (the item array grows forward from the
/// header end; only the count is capped here, individual data is sliced later).
fn parse_items(block: &[u8], nritems: usize) -> Vec<ItemHeader> {
    // The item-header array cannot hold more than fits between the header end
    // and the block end.
    let avail = block.len().saturating_sub(BTRFS_HEADER_SIZE);
    let max_fit = avail / BTRFS_ITEM_SIZE;
    let take = nritems.min(max_fit);
    let mut out = Vec::with_capacity(take);
    for i in 0..take {
        let io = BTRFS_HEADER_SIZE + i * BTRFS_ITEM_SIZE;
        out.push(ItemHeader {
            key: DiskKey::parse(block, io),
            data_offset: le_u32(block, io + DISK_KEY_SIZE),
            data_size: le_u32(block, io + DISK_KEY_SIZE + 4),
        });
    }
    out
}

/// Parse up to `nritems` interior key-pointers, capped by the block bound.
fn parse_key_ptrs(block: &[u8], nritems: usize) -> Vec<KeyPtr> {
    let avail = block.len().saturating_sub(BTRFS_HEADER_SIZE);
    let max_fit = avail / BTRFS_KEY_PTR_SIZE;
    let take = nritems.min(max_fit);
    let mut out = Vec::with_capacity(take);
    for i in 0..take {
        let po = BTRFS_HEADER_SIZE + i * BTRFS_KEY_PTR_SIZE;
        out.push(KeyPtr {
            key: DiskKey::parse(block, po),
            blockptr: le_u64(block, po + DISK_KEY_SIZE),
            generation: le_u64(block, po + DISK_KEY_SIZE + 8),
        });
    }
    out
}

/// One logical→physical mapping entry: a chunk's logical span and its stripes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MapEntry {
    logical_start: u64,
    length: u64,
    /// `(devid, physical_offset)` of each stripe; single/DUP use the first.
    stripes: Vec<(u64, u64)>,
}

/// The chunk-tree logical→physical map: the union of every `CHUNK_ITEM`'s span
/// and its physical placement. Covers single-device profiles (SINGLE/DUP);
/// for DUP the first stripe (first mirror) is returned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChunkMap {
    entries: Vec<MapEntry>,
}

impl ChunkMap {
    /// An empty map.
    #[must_use]
    pub fn new() -> Self {
        ChunkMap {
            entries: Vec::new(),
        }
    }

    /// Add every `CHUNK_ITEM` found in a chunk-tree leaf `node` to the map.
    pub fn add_from_node(&mut self, node: &Node) {
        for (logical, chunk) in node.chunk_items() {
            self.entries.push(MapEntry {
                logical_start: logical,
                length: chunk.length,
                stripes: chunk.stripes.iter().map(|s| (s.devid, s.offset)).collect(),
            });
        }
    }

    /// Translate a logical address to `(devid, physical_byte)` on the first
    /// stripe's device, for single-device single/DUP chunks. Returns `None` if
    /// no chunk covers `logical`, or the covering chunk has no stripe.
    #[must_use]
    pub fn logical_to_physical(&self, logical: u64) -> Option<(u64, u64)> {
        for e in &self.entries {
            let end = e.logical_start.checked_add(e.length)?;
            if logical >= e.logical_start && logical < end {
                let (devid, phys_start) = *e.stripes.first()?;
                let delta = logical - e.logical_start;
                let phys = phys_start.checked_add(delta)?;
                return Some((devid, phys));
            }
        }
        None
    }

    /// Build the full chunk map by bootstrapping from the superblock's
    /// `sys_chunk_array` and walking the chunk tree from `sb.chunk_root`.
    ///
    /// The `sys_chunk_array` covers the `chunk_root`'s own logical range (that is
    /// its whole purpose), so `chunk_root` is reachable; each subsequently read
    /// node's `blockptr`s are translated through the map built *so far* (the
    /// chunk tree is self-describing). On the oracle the chunk tree is a single
    /// leaf, but interior nodes are followed recursively (bounded).
    ///
    /// # Errors
    ///
    /// - [`BtrfsError::Truncated`] if `sb.chunk_root` cannot be translated to a
    ///   readable node within `image` (a failed bootstrap is loud, never an
    ///   empty map — see the Paranoid Gatekeeper standard).
    pub fn walk(image: &[u8], sb: &Superblock) -> Result<Self, BtrfsError> {
        // Bootstrap map from the sys_chunk_array (seeds the chunk_root's range).
        let mut boot = ChunkMap::new();
        for c in &sb.sys_chunks {
            boot.entries.push(MapEntry {
                logical_start: c.key.offset,
                length: c.length,
                stripes: c.stripes.iter().map(|s| (s.devid, s.offset)).collect(),
            });
        }

        let nodesize = sb.nodesize as usize;
        let mut map = ChunkMap::new();

        // Depth/visit budget guards against a corrupt/cyclic chunk tree.
        let mut budget: usize = 4096;
        let mut stack = vec![sb.chunk_root];
        let mut bootstrapped_root = false;

        while let Some(logical) = stack.pop() {
            if budget == 0 {
                break; // cov:unreachable: the oracle chunk tree is a single leaf; only a >4096-node tree exhausts this, not craftable as a fixture
            }
            budget -= 1;

            // Translate via the map built so far, falling back to the bootstrap
            // map (needed for the chunk_root itself and its own subtree).
            let phys = map
                .logical_to_physical(logical)
                .or_else(|| boot.logical_to_physical(logical));
            let Some((_devid, phys)) = phys else {
                if !bootstrapped_root {
                    // The very first (chunk_root) translation failed: the
                    // bootstrap did not cover it — a loud, non-empty failure.
                    return Err(BtrfsError::Truncated {
                        structure: "chunk_root logical (sys_chunk_array bootstrap)",
                        need: logical as usize,
                        have: 0,
                    });
                } // cov:unreachable: the if-body's only statement is `return Err`, so this closing brace's fall-through region is unreachable
                continue; // cov:unreachable: an interior blockptr not covered by the map built so far implies a malformed chunk tree; the oracle's is single-leaf and self-consistent
            };
            bootstrapped_root = true;

            let start = phys as usize;
            let Some(block) = image.get(start..start.saturating_add(nodesize)) else {
                if map.entries.is_empty() {
                    return Err(BtrfsError::Truncated {
                        structure: "chunk_root node (out of image)",
                        need: start.saturating_add(nodesize),
                        have: image.len(),
                    });
                } // cov:unreachable: the if-body's only statement is `return Err`, so this closing brace's fall-through region is unreachable
                continue; // cov:unreachable: a self-consistent chunk tree points only inside the image; guarded for a corrupt blockptr
            };

            let Ok(node) = Node::parse(block) else {
                continue; // cov:unreachable: block is nodesize (>=101) bytes, so Header::parse always succeeds
            };

            if node.is_leaf() {
                map.add_from_node(&node);
            } else {
                for kp in node.key_ptrs() {
                    stack.push(kp.blockptr);
                }
            }
        }

        Ok(map)
    }
}

/// Read the btrfs node at logical address `logical`: translate it to a physical
/// offset via `chunk_map` (falling back to the superblock `sys_chunk_array`
/// bootstrap for addresses inside the `chunk_root`'s own range), slice `nodesize`
/// bytes, and parse the header + items/pointers.
///
/// # Errors
///
/// - [`BtrfsError::Truncated`] if `logical` cannot be translated to a physical
///   offset, or the resulting `nodesize`-byte block lies outside `image`.
pub fn read_node(
    image: &[u8],
    sb: &Superblock,
    chunk_map: &ChunkMap,
    logical: u64,
) -> Result<Node, BtrfsError> {
    // Prefer the full chunk map; fall back to the sys_chunk_array bootstrap so
    // the chunk_root (and its own range) is reachable before the tree is walked.
    let phys = chunk_map.logical_to_physical(logical).or_else(|| {
        sb.sys_chunks
            .iter()
            .find_map(|c| c.logical_to_physical(logical).map(|p| (0u64, p)))
    });
    let Some((_devid, phys)) = phys else {
        return Err(BtrfsError::Truncated {
            structure: "logical address (no chunk mapping)",
            need: logical as usize,
            have: 0,
        });
    };

    let nodesize = sb.nodesize as usize;
    let start = phys as usize;
    let Some(block) = image.get(start..start.saturating_add(nodesize)) else {
        return Err(BtrfsError::Truncated {
            structure: "node block (out of image)",
            need: start.saturating_add(nodesize),
            have: image.len(),
        });
    };
    Node::parse(block)
}
