//! P3 EXTENT_DATA → file content: assemble a file's bytes from its
//! `btrfs_file_extent_item`s (inline, regular, prealloc, hole), decompressing
//! zlib / LZO / zstd extents.
//!
//! The FS_TREE keys a file's data as `EXTENT_DATA` ([`EXTENT_DATA_KEY`] = 108)
//! items, one per file-logical region, ordered by the key's `offset` (the
//! file-logical byte where the region starts). Each item is a
//! `btrfs_file_extent_item`:
//!
//! ```text
//! generation(u64)@0  ram_bytes(u64)@8  compression(u8)@16  encryption(u8)@17
//! other_encoding(u16)@18  type(u8)@20
//!   type 0 = INLINE   : the data bytes follow the 21-byte header, in the leaf
//!                       (possibly compressed to ram_bytes)
//!   type 1 = REG / 2 = PREALLOC :
//!       disk_bytenr(u64)@21   disk_num_bytes(u64)@29
//!       offset(u64)@37        num_bytes(u64)@45
//!       disk_bytenr == 0  ⇒  a HOLE (num_bytes zeros, no image read)
//! ```
//!
//! Offsets verified byte-for-byte against `btrfs inspect-internal dump-tree`
//! on the minted oracle (small.txt/leaf.txt inline, mid.bin regular; see
//! `tests/data/README.md`, "P2 ground truth" — the same FS_TREE leaf).
//!
//! # Compression (batteries-included)
//!
//! zlib (`flate2`), zstd (`ruzstd`, pure-Rust), and btrfs-framed LZO (`lzo` +
//! the [MS-agnostic] per-sector framing from the kernel `fs/btrfs/lzo.c`) are
//! **compiled in unconditionally** — never behind a feature the analyst must
//! know to enable. `ram_bytes` is the decompressed size.
//!
//! # Safety
//!
//! Parses untrusted, attacker-controllable images. Every field is read through
//! the bounds-checked [`crate::bytes`] helpers; every `num_bytes` / `ram_bytes`
//! / `disk_num_bytes` is range-checked against the image length before it can
//! size an allocation, so a lying length yields a loud
//! [`BtrfsError::AllocationBomb`] rather than an OOM (the Paranoid Gatekeeper
//! standard). Compression output is capped at `ram_bytes`.

use std::io::Read;

use crate::bytes::{le_u64, u8_at};
use crate::error::BtrfsError;
use crate::fstree::{read_by_path, INODE_ITEM_KEY};
use crate::node::{read_node, ChunkMap, Node};
use crate::superblock::Superblock;

/// `BTRFS_EXTENT_DATA_KEY` — a `btrfs_file_extent_item` (file data).
pub const EXTENT_DATA_KEY: u8 = 108;

/// The fixed `btrfs_file_extent_item` header length before the type-specific
/// tail (inline data, or the regular/prealloc `disk_bytenr` block).
const EXTENT_HEADER_LEN: usize = 21;

// `btrfs_file_extent_item` field offsets (verified vs dump-tree).
mod ext_off {
    pub const RAM_BYTES: usize = 8;
    pub const COMPRESSION: usize = 16;
    pub const TYPE: usize = 20;
    // Regular / prealloc tail (from offset 21):
    pub const DISK_BYTENR: usize = 21;
    pub const OFFSET: usize = 37;
    pub const NUM_BYTES: usize = 45;
}

/// `btrfs_file_extent_item` `type` byte.
const EXTENT_TYPE_INLINE: u8 = 0;
const EXTENT_TYPE_REG: u8 = 1;
const EXTENT_TYPE_PREALLOC: u8 = 2;

/// The compression algorithm of an extent (`btrfs_file_extent_item.compression`).
/// Unknown values carry their raw byte so an unsupported codec is identifiable
/// (fail-loud: the offending value is shown, never dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Compression {
    /// `0` — no compression; the extent bytes are the file bytes.
    None,
    /// `1` — zlib (a plain zlib stream per extent; `flate2`).
    Zlib,
    /// `2` — LZO, in btrfs's per-sector framing (`lzo` crate + framing).
    Lzo,
    /// `3` — zstd (one zstd frame per extent; `ruzstd`, pure-Rust).
    Zstd,
    /// Any other `BTRFS_COMPRESS_*` value, carrying the raw byte.
    Other(u8),
}

impl Compression {
    /// Classify a raw `compression` byte.
    #[must_use]
    pub fn from_byte(b: u8) -> Self {
        match b {
            0 => Compression::None,
            1 => Compression::Zlib,
            2 => Compression::Lzo,
            3 => Compression::Zstd,
            other => Compression::Other(other),
        }
    }
}

/// The floor for the logical-content allocation bound (64 MiB), used when the
/// image is empty (always-on synthetic leaves) so a small hole/size still
/// allocates while a `u64`-scale lying length is still rejected.
const LOGICAL_ALLOC_FLOOR: u64 = 64 * 1024 * 1024;

/// Assemble the file content for objectid `ino` from an already-parsed FS_TREE
/// `leaf`, reading regular extents from `image` via `map`.
///
/// The inode's `size` (from its `INODE_ITEM`) truncates the assembled bytes;
/// extents are taken in file-logical (`key.offset`) order and holes
/// (`disk_bytenr == 0`) contribute zeros. `sectorsize` is needed for LZO
/// framing.
///
/// # Errors
///
/// - [`BtrfsError::Truncated`] if the leaf holds no `INODE_ITEM` for `ino` (a
///   loud miss — an absent inode is never an empty file).
/// - [`BtrfsError::AllocationBomb`] if any extent's length field exceeds the
///   image length.
/// - Any error from translating/reading a regular extent's `disk_bytenr`, or a
///   decompression failure.
pub fn read_file_from_leaf(
    leaf: &Node,
    image: &[u8],
    map: &ChunkMap,
    sectorsize: u32,
    ino: u64,
) -> Result<Vec<u8>, BtrfsError> {
    // The inode must exist in this leaf — a loud miss, never an empty file.
    let size = leaf
        .leaf_items()
        .find(|(k, _)| k.objectid == ino && k.key_type == INODE_ITEM_KEY)
        .map(|(_, data)| le_u64(data, crate::fstree::INODE_SIZE_OFFSET))
        .ok_or(BtrfsError::Truncated {
            structure: "INODE_ITEM for the requested objectid (read_file)",
            need: ino as usize,
            have: 0,
        })?;

    // Collect the file's EXTENT_DATA items in file-logical (key.offset) order.
    let mut extents: Vec<(u64, &[u8])> = leaf
        .leaf_items()
        .filter(|(k, _)| k.objectid == ino && k.key_type == EXTENT_DATA_KEY)
        .map(|(k, data)| (k.offset, data))
        .collect();
    extents.sort_by_key(|(file_off, _)| *file_off);

    // The logical-content allocation bound: a file's assembled bytes cannot
    // reasonably exceed the image it lives in, but always-on synthetic leaves
    // pass an empty image while still holding small holes, so floor it at
    // [`LOGICAL_ALLOC_FLOOR`]. A `size` / `num_bytes` above this bound is a lying
    // length rejected as an allocation bomb (never blindly allocated).
    let image_len = image.len() as u64;
    let logical_bound = image_len.max(LOGICAL_ALLOC_FLOOR);
    guard_alloc("inode size", size, logical_bound)?;
    let mut out: Vec<u8> = Vec::new();

    for (_file_off, data) in extents {
        let etype = u8_at(data, ext_off::TYPE);
        let ram_bytes = le_u64(data, ext_off::RAM_BYTES);
        let compression = Compression::from_byte(u8_at(data, ext_off::COMPRESSION));

        match etype {
            EXTENT_TYPE_INLINE => {
                let payload = data.get(EXTENT_HEADER_LEN..).unwrap_or(&[]);
                let bytes = decompress_extent(compression, payload, ram_bytes, sectorsize)?;
                out.extend_from_slice(&bytes);
            }
            EXTENT_TYPE_REG | EXTENT_TYPE_PREALLOC => {
                let disk_bytenr = le_u64(data, ext_off::DISK_BYTENR);
                let ext_offset = le_u64(data, ext_off::OFFSET);
                let num_bytes = le_u64(data, ext_off::NUM_BYTES);

                if disk_bytenr == 0 {
                    // A HOLE: num_bytes zeros, no image read. Guard the count.
                    guard_alloc("hole num_bytes", num_bytes, logical_bound)?;
                    out.resize(out.len() + num_bytes as usize, 0);
                    continue;
                }

                let bytes = read_regular_extent(
                    image,
                    map,
                    sectorsize,
                    compression,
                    disk_bytenr,
                    ext_offset,
                    num_bytes,
                    ram_bytes,
                )?;
                out.extend_from_slice(&bytes);
            }
            _ => {
                // An unknown extent type: fail loud with the offending value
                // rather than silently produce wrong (short) content.
                return Err(BtrfsError::Truncated {
                    structure: "btrfs_file_extent_item type (unknown extent type)",
                    need: etype as usize,
                    have: 0,
                });
            }
        }
    }

    // The inode's logical size is authoritative: truncate a tail that extent
    // rounding produced, or extend a sparse tail with zeros. `size` was already
    // guarded against `logical_bound` above, so the resize cannot bomb.
    let size = size as usize;
    if out.len() > size {
        out.truncate(size);
    } else if out.len() < size {
        // A sparse tail past the last extent (NO_HOLES filesystems omit trailing
        // hole items): the file logically continues as zeros to `size`.
        out.resize(size, 0);
    }
    Ok(out)
}

/// Read one regular/prealloc extent's bytes: translate `disk_bytenr` (logical)
/// to a physical offset via `map`, slice the extent's compressed source, and
/// (for a compressed extent) decompress it, then take the `[offset, offset +
/// num_bytes)` window that this file-extent references.
#[allow(clippy::too_many_arguments)]
fn read_regular_extent(
    image: &[u8],
    map: &ChunkMap,
    sectorsize: u32,
    compression: Compression,
    disk_bytenr: u64,
    ext_offset: u64,
    num_bytes: u64,
    ram_bytes: u64,
) -> Result<Vec<u8>, BtrfsError> {
    let image_len = image.len() as u64;
    guard_alloc("extent num_bytes", num_bytes, image_len)?;

    let (_devid, phys) = map
        .logical_to_physical(disk_bytenr)
        .ok_or(BtrfsError::Truncated {
            structure: "extent disk_bytenr (no chunk mapping)",
            need: disk_bytenr as usize,
            have: 0,
        })?;

    if compression == Compression::None {
        // Uncompressed: the file bytes are `num_bytes` at physical
        // `phys + ext_offset` (ext_offset is the intra-extent byte offset).
        let start = phys.saturating_add(ext_offset) as usize;
        let end = start.saturating_add(num_bytes as usize);
        let slice = image.get(start..end).ok_or(BtrfsError::Truncated {
            structure: "regular extent data (out of image)",
            need: end,
            have: image.len(),
        })?;
        return Ok(slice.to_vec());
    }

    // Compressed: the whole extent is `ram_bytes` uncompressed; the compressed
    // source occupies the extent's chunk region. btrfs stores the *compressed*
    // bytes as one unit; decompress it to `ram_bytes`, then take the file's
    // `[ext_offset, ext_offset + num_bytes)` window.
    // The compressed source length is disk_num_bytes; for our reader we take the
    // compressed bytes up to the image end and let the codec stop at frame end.
    let start = phys as usize;
    // Cap the compressed source read at ram_bytes' worst case is not knowable
    // here; the codecs are self-terminating (zlib/zstd stop at stream end, LZO
    // uses its own length header), so pass from `start` to image end.
    let src = image.get(start..).ok_or(BtrfsError::Truncated {
        structure: "compressed extent source (out of image)",
        need: start,
        have: image.len(),
    })?;
    let whole = decompress_extent(compression, src, ram_bytes, sectorsize)?;

    let win_start = ext_offset as usize;
    let win_end = win_start.saturating_add(num_bytes as usize);
    let window = whole
        .get(win_start..win_end.min(whole.len()))
        .unwrap_or(&[]);
    Ok(window.to_vec())
}

/// Decompress one extent's `src` bytes to at most `ram_bytes` output using
/// `algo`. `sectorsize` is needed only for LZO's per-sector framing.
///
/// Batteries-included: zlib / zstd / btrfs-LZO are always compiled in.
///
/// # Errors
///
/// - [`BtrfsError::AllocationBomb`] if `ram_bytes` is implausibly large versus
///   `src` (a lying decompressed size, capped before any pre-allocation).
/// - [`BtrfsError::Truncated`] if a codec fails (malformed compressed data) or
///   the algorithm is unsupported (`Compression::Other`), naming the value.
pub fn decompress_extent(
    algo: Compression,
    src: &[u8],
    ram_bytes: u64,
    sectorsize: u32,
) -> Result<Vec<u8>, BtrfsError> {
    if algo == Compression::None {
        // No compression: the source *is* the content, truncated to ram_bytes.
        let take = (ram_bytes as usize).min(src.len());
        return Ok(src.get(..take).unwrap_or(src).to_vec());
    }

    // Allocation-bomb guard: a compressed stream expands by a bounded ratio.
    // Reject a claimed ram_bytes wildly larger than the source could produce.
    // btrfs compressed extents are per-128KiB; a 1024× cap over the source (plus
    // a small floor for tiny inputs) is far above any real ratio yet blocks a
    // multi-GiB claim from a few-byte source.
    let bound = (src.len() as u64)
        .saturating_mul(1024)
        .saturating_add(1 << 20);
    guard_alloc("compressed ram_bytes", ram_bytes, bound)?;
    let cap = ram_bytes as usize;

    match algo {
        Compression::Zlib => decompress_zlib(src, cap),
        Compression::Zstd => decompress_zstd(src, cap),
        Compression::Lzo => decompress_lzo_btrfs(src, cap, sectorsize),
        // An unknown/unsupported codec fails loud with the offending byte.
        // `Compression::None` returned early at the top of the function, so the
        // wildcard here only ever binds `Other(b)`; the `0` fallback byte is a
        // guard that cannot fire.
        other => Err(BtrfsError::Truncated {
            structure: "extent compression algorithm (unsupported codec)",
            need: usize::from(unsupported_codec_byte(other)),
            have: 0,
        }),
    }
}

/// The raw byte to report for an unsupported codec. Only `Other(b)` reaches this
/// (both `None` — early-returned — and the three real codecs are handled), so
/// the non-`Other` fallback is an unreachable guard.
fn unsupported_codec_byte(algo: Compression) -> u8 {
    match algo {
        Compression::Other(b) => b,
        _ => 0, // cov:unreachable: only Compression::Other reaches decompress_extent's wildcard arm; None returns early and Zlib/Lzo/Zstd are matched before it
    }
}

/// Decompress a plain zlib stream (btrfs zlib extent) to at most `cap` bytes.
fn decompress_zlib(src: &[u8], cap: usize) -> Result<Vec<u8>, BtrfsError> {
    let dec = flate2::read::ZlibDecoder::new(src);
    let mut out = Vec::with_capacity(cap);
    // Bound the read at cap so a corrupt stream cannot spin producing bytes.
    match dec.take(cap as u64).read_to_end(&mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(BtrfsError::Truncated {
            structure: "zlib extent stream (decompression failed)",
            need: cap,
            have: out.len(),
        }),
    }
}

/// Decompress a single zstd frame (btrfs zstd extent) to at most `cap` bytes.
fn decompress_zstd(src: &[u8], cap: usize) -> Result<Vec<u8>, BtrfsError> {
    let dec = ruzstd::decoding::StreamingDecoder::new(src).map_err(|_| BtrfsError::Truncated {
        structure: "zstd extent frame (bad frame header)",
        need: cap,
        have: 0,
    })?;
    let mut out = Vec::with_capacity(cap);
    match dec.take(cap as u64).read_to_end(&mut out) {
        Ok(_) => Ok(out),
        Err(_) => Err(BtrfsError::Truncated {
            structure: "zstd extent frame (decompression failed)",
            need: cap,
            have: out.len(),
        }),
    }
}

/// Decompress a btrfs-framed LZO extent to at most `cap` bytes.
///
/// btrfs LZO framing (kernel `fs/btrfs/lzo.c`): a 4-byte LE32 header = the total
/// compressed size (including the header), then one or more segments. Each
/// segment is a 4-byte LE32 length + an LZO1X block yielding up to one sector of
/// output. A **segment header never crosses a `sectorsize` boundary** — if the 4
/// header bytes would not fit in the current sector, the writer pads with zeros
/// to the next sector boundary; the segment *payload* is contiguous (may span
/// sectors). Each LZO1X block is decoded via the `lzo` crate.
fn decompress_lzo_btrfs(src: &[u8], cap: usize, sectorsize: u32) -> Result<Vec<u8>, BtrfsError> {
    const LZO_LEN: usize = 4;
    let sectorsize = (sectorsize as usize).max(1);

    let total = le_u64(&le32_padded(src, 0), 0) as usize; // total compressed incl. header
    let total = total.min(src.len()).max(LZO_LEN);
    let mut cur = LZO_LEN;
    let mut out: Vec<u8> = Vec::with_capacity(cap);
    // A generous per-segment output buffer: one sector, plus LZO worst-case slack.
    let seg_out_cap = sectorsize
        .saturating_add(sectorsize / 16)
        .saturating_add(64);

    while cur < total && out.len() < cap {
        // The segment header must fit inside the current sector; if not, skip
        // the padding to the next sector boundary.
        if cur % sectorsize + LZO_LEN > sectorsize {
            let next = cur
                .checked_add(sectorsize - cur % sectorsize)
                .unwrap_or(total);
            cur = next;
            if cur >= total {
                break; // cov:unreachable: btrfs always places a segment (or ends) before this padding runs off the total; guarded for a corrupt frame
            }
        }

        let Some(seg_len_bytes) = src.get(cur..cur + LZO_LEN) else {
            break; // cov:unreachable: cur < total <= src.len() and the header fits the sector by the check above, so the 4 bytes are present
        };
        let seg_len = u32::from_le_bytes([
            seg_len_bytes[0],
            seg_len_bytes[1],
            seg_len_bytes[2],
            seg_len_bytes[3],
        ]) as usize;
        cur += LZO_LEN;

        if seg_len == 0 {
            break; // cov:unreachable: a real btrfs LZO frame has no zero-length segment; guarded so a corrupt count cannot loop forever
        }
        let Some(seg) = src.get(cur..cur.saturating_add(seg_len).min(src.len())) else {
            break; // cov:unreachable: the slice is clamped to src.len(), so get() always returns Some
        };
        cur = cur.saturating_add(seg_len);

        let mut dst = vec![0u8; seg_out_cap];
        match lzo::decompress_into(seg, &mut dst) {
            Ok(n) => {
                let want = (cap - out.len()).min(n);
                out.extend_from_slice(dst.get(..want).unwrap_or(&dst[..n]));
            }
            Err(_) => {
                return Err(BtrfsError::Truncated {
                    structure: "LZO extent segment (decompression failed)",
                    need: seg_len,
                    have: out.len(),
                });
            }
        }
    }

    out.truncate(cap);
    Ok(out)
}

/// Read a 4-byte LE prefix from `src` at `off` into an 8-byte buffer so
/// [`le_u64`] can decode it uniformly (the high 4 bytes are 0).
fn le32_padded(src: &[u8], off: usize) -> [u8; 8] {
    let mut b = [0u8; 8];
    if let Some(s) = src.get(off..off + 4) {
        b[..4].copy_from_slice(s);
    }
    b
}

/// Reject a length/count field that exceeds `bound` as an allocation bomb.
fn guard_alloc(field: &'static str, claimed: u64, bound: u64) -> Result<(), BtrfsError> {
    if claimed > bound {
        return Err(BtrfsError::AllocationBomb {
            field,
            claimed,
            bound,
        });
    }
    Ok(())
}

/// Assemble the file content for objectid `ino` over the whole `image`: locate
/// the FS_TREE root from the root tree, read its leaf, and delegate to
/// [`read_file_from_leaf`].
///
/// # Errors
///
/// - Any error from [`crate::fs_tree_root`] / [`read_node`] locating and
///   reading the FS_TREE leaf, or from [`read_file_from_leaf`].
pub fn read_file(
    image: &[u8],
    sb: &Superblock,
    map: &ChunkMap,
    ino: u64,
) -> Result<Vec<u8>, BtrfsError> {
    let leaf = fs_tree_leaf(image, sb, map)?;
    read_file_from_leaf(&leaf, image, map, sb.sectorsize, ino)
}

/// Resolve `path` from the FS_TREE root directory and read the resolved inode's
/// content over the whole `image`.
///
/// # Errors
///
/// - [`BtrfsError::Truncated`] naming the path if it does not resolve (a loud
///   miss, never an empty file).
/// - Any error from locating/reading the FS_TREE leaf or assembling content.
pub fn read_by_path_content(
    image: &[u8],
    sb: &Superblock,
    map: &ChunkMap,
    path: &str,
) -> Result<Vec<u8>, BtrfsError> {
    let leaf = fs_tree_leaf(image, sb, map)?;
    let (ino, _inode) = read_by_path(&leaf, path).ok_or(BtrfsError::Truncated {
        structure: "path (unresolved in FS_TREE)",
        need: path.len(),
        have: 0,
    })?;
    read_file_from_leaf(&leaf, image, map, sb.sectorsize, ino)
}

/// Locate and read the FS_TREE leaf node for the whole image.
fn fs_tree_leaf(image: &[u8], sb: &Superblock, map: &ChunkMap) -> Result<Node, BtrfsError> {
    let root = crate::fstree::fs_tree_root(image, sb, map)?;
    read_node(image, sb, map, root.bytenr)
}
