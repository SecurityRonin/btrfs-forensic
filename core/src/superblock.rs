//! btrfs superblock (`btrfs_super_block`) parse + `sys_chunk_array` bootstrap.
//!
//! The primary superblock sits at **physical byte offset 65536 (0x10000)** of
//! the device (NOT offset 0), in a [`BTRFS_SUPER_INFO_SIZE`]-byte block. All
//! fields are little-endian. The magic `_BHRfS_M` lives at **offset 0x40 within
//! the superblock** (0x40 = past the 32-byte csum + 16-byte fsid).
//!
//! Field offsets below were transcribed from the kernel/btrfs-progs on-disk
//! `struct btrfs_super_block` and then **verified byte-for-byte against
//! `btrfs inspect-internal dump-super -f` on the minted oracle image** (see
//! `tests/data/README.md`). Each offset comment marks the field it decodes.

use crate::bytes::{le_u16, le_u32, le_u64, u8_at};
use crate::chunk::{SysChunk, SYS_CHUNK_ARRAY_OFFSET};
use crate::crc::{superblock_crc_status, CsumType, BTRFS_CSUM_SIZE};
use crate::error::BtrfsError;

/// `BTRFS_SUPER_INFO_OFFSET` — the primary superblock's physical byte offset.
pub const BTRFS_SUPER_INFO_OFFSET: u64 = 65536;

/// `BTRFS_SUPER_INFO_SIZE` — the superblock block size (4096 bytes).
pub const BTRFS_SUPER_INFO_SIZE: usize = 4096;

/// The btrfs magic, ASCII `"_BHRfS_M"`, at superblock offset 0x40 (little-endian
/// `u64` = `0x4D5F_5366_5248_425F`).
pub const BTRFS_MAGIC: [u8; 8] = *b"_BHRfS_M";

/// Offset of the magic within the superblock.
const MAGIC_OFFSET: usize = 0x40;

/// `BTRFS_FSID_SIZE` — the filesystem UUID width.
pub const BTRFS_FSID_SIZE: usize = 16;

/// `BTRFS_LABEL_SIZE` — the filesystem label field width.
pub const BTRFS_LABEL_SIZE: usize = 256;

/// Minimum bytes required to parse every scalar field this reader extracts. The
/// last scalar is `log_root_level` at 0xc8 (+1 = 0xc9); the label and
/// `sys_chunk_array` extend further but are bounds-checked individually so a
/// short-but-past-0xc9 buffer still yields the geometry.
const SB_MIN_LEN: usize = 0xc9;

/// A parsed btrfs superblock — the filesystem geometry, tree-root logical
/// addresses, checksum descriptor, and the decoded `sys_chunk_array` bootstrap
/// map (the P1 seed for logical→physical translation).
///
/// `#[non_exhaustive]` so later phases add fields without a breaking change.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Superblock {
    /// The 8-byte magic at offset 0x40 — validated to equal [`BTRFS_MAGIC`].
    pub magic: [u8; 8],
    /// `csum` (offset 0x0) — the first 4 bytes of the 32-byte checksum field
    /// (the crc32c digest for a crc32c filesystem), verbatim.
    pub csum: [u8; 4],
    /// `fsid` (offset 0x20) — the filesystem UUID.
    pub fsid: [u8; BTRFS_FSID_SIZE],
    /// `bytenr` (offset 0x30) — the physical byte address of THIS superblock
    /// copy (65536 for the primary).
    pub bytenr: u64,
    /// `flags` (offset 0x38).
    pub flags: u64,
    /// `generation` (offset 0x48) — the transaction id this superblock committed
    /// (the highest valid copy is the latest committed state — the CoW lever).
    pub generation: u64,
    /// `root` (offset 0x50) — logical address of the root tree.
    pub root: u64,
    /// `chunk_root` (offset 0x58) — logical address of the chunk tree.
    pub chunk_root: u64,
    /// `log_root` (offset 0x60) — logical address of the log tree (0 = none).
    pub log_root: u64,
    /// `total_bytes` (offset 0x70) — filesystem size in bytes.
    pub total_bytes: u64,
    /// `bytes_used` (offset 0x78) — bytes in use.
    pub bytes_used: u64,
    /// `root_dir_objectid` (offset 0x80) — the root directory objectid (6).
    pub root_dir_objectid: u64,
    /// `num_devices` (offset 0x88).
    pub num_devices: u64,
    /// `sectorsize` (offset 0x90) — data block size in bytes.
    pub sectorsize: u32,
    /// `nodesize` (offset 0x94) — B-tree node size in bytes.
    pub nodesize: u32,
    /// `stripesize` (offset 0x9c).
    pub stripesize: u32,
    /// `sys_chunk_array_size` (offset 0xa0) — valid byte length of the
    /// `sys_chunk_array` bootstrap region.
    pub sys_chunk_array_size: u32,
    /// `chunk_root_generation` (offset 0xa4).
    pub chunk_root_generation: u64,
    /// `compat_flags` (offset 0xac).
    pub compat_flags: u64,
    /// `compat_ro_flags` (offset 0xb4).
    pub compat_ro_flags: u64,
    /// `incompat_flags` (offset 0xbc).
    pub incompat_flags: u64,
    /// `csum_type` (offset 0xc4) — decoded checksum algorithm.
    pub csum_type: CsumType,
    /// `root_level` (offset 0xc6) — B-tree level of the root tree (0 = leaf).
    pub root_level: u8,
    /// `chunk_root_level` (offset 0xc7) — B-tree level of the chunk tree.
    pub chunk_root_level: u8,
    /// `log_root_level` (offset 0xc8).
    pub log_root_level: u8,
    /// `label` (offset 0xab within `dev_item`… → absolute 0x12b) — the
    /// NUL-trimmed filesystem label, lossily decoded from up to 256 bytes.
    pub label: String,
    /// The decoded `sys_chunk_array` bootstrap chunk map — the SYSTEM
    /// block-group logical→physical entries needed to read the chunk tree in P1.
    /// Full chunk-tree walking is P1; P0 decodes the bootstrap structs only.
    pub sys_chunks: Vec<SysChunk>,
    /// The crc32c status of this superblock over its `sectorsize`-byte block:
    /// `Some(true)` if the stored csum verifies, `Some(false)` if it does not
    /// (corrupt/tampered), or `None` for a non-crc32c checksum type (deferred).
    /// **Non-fatal** — a bad csum does not fail the parse.
    pub crc_valid: Option<bool>,
}

impl Superblock {
    /// Parse a btrfs superblock from the start of `block`.
    ///
    /// `block` must begin at the superblock (the caller slices the 4096-byte
    /// block at physical offset 65536; passing the whole `sectorsize` block lets
    /// the crc32c cover the correct range). The magic is validated at offset
    /// 0x40 (not 0) — a wrong-image identity error names the offending 8 bytes.
    ///
    /// # Errors
    ///
    /// - [`BtrfsError::BadMagic`] if offset 0x40 is not `_BHRfS_M` — the eight
    ///   offending bytes are carried in the error.
    /// - [`BtrfsError::Truncated`] if `block` is shorter than the scalar fields.
    pub fn parse(block: &[u8]) -> Result<Self, BtrfsError> {
        // Validate magic (at 0x40) before length so a wrong-image identity error
        // names the offending bytes (fail loud with the value).
        let mut magic = [0u8; 8];
        for (i, b) in magic.iter_mut().enumerate() {
            *b = u8_at(block, MAGIC_OFFSET + i);
        }
        if magic != BTRFS_MAGIC {
            return Err(BtrfsError::BadMagic { bytes: magic });
        }

        if block.len() < SB_MIN_LEN {
            return Err(BtrfsError::Truncated {
                structure: "superblock",
                need: SB_MIN_LEN,
                have: block.len(),
            });
        }

        // Offsets VERIFIED against `dump-super -f` on the oracle (README).
        let mut csum = [0u8; 4];
        for (i, b) in csum.iter_mut().enumerate() {
            *b = u8_at(block, i);
        }
        let mut fsid = [0u8; BTRFS_FSID_SIZE];
        for (i, b) in fsid.iter_mut().enumerate() {
            *b = u8_at(block, 0x20 + i);
        }

        let sectorsize = le_u32(block, 0x90);
        let csum_type = CsumType::from_code(le_u16(block, 0xc4));

        // The csum covers `[BTRFS_CSUM_SIZE .. sectorsize]`. Clamp the covered
        // length to the block we were actually handed so a short buffer verifies
        // as `Some(false)` rather than reaching out of range.
        let covered = (sectorsize as usize).min(block.len()).max(BTRFS_CSUM_SIZE);
        let crc_valid = superblock_crc_status(csum_type, block, covered);

        let sys_chunk_array_size = le_u32(block, 0xa0);
        let sys_chunks = SysChunk::parse_array(block, SYS_CHUNK_ARRAY_OFFSET, sys_chunk_array_size);

        let label = decode_label(block, 0x12b);

        Ok(Self {
            magic,
            csum,
            fsid,
            bytenr: le_u64(block, 0x30),
            flags: le_u64(block, 0x38),
            generation: le_u64(block, 0x48),
            root: le_u64(block, 0x50),
            chunk_root: le_u64(block, 0x58),
            log_root: le_u64(block, 0x60),
            total_bytes: le_u64(block, 0x70),
            bytes_used: le_u64(block, 0x78),
            root_dir_objectid: le_u64(block, 0x80),
            num_devices: le_u64(block, 0x88),
            sectorsize,
            nodesize: le_u32(block, 0x94),
            stripesize: le_u32(block, 0x9c),
            sys_chunk_array_size,
            chunk_root_generation: le_u64(block, 0xa4),
            compat_flags: le_u64(block, 0xac),
            compat_ro_flags: le_u64(block, 0xb4),
            incompat_flags: le_u64(block, 0xbc),
            csum_type,
            root_level: u8_at(block, 0xc6),
            chunk_root_level: u8_at(block, 0xc7),
            log_root_level: u8_at(block, 0xc8),
            label,
            sys_chunks,
            crc_valid,
        })
    }

    /// The filesystem UUID rendered as the canonical `8-4-4-4-12` string.
    #[must_use]
    pub fn fsid_string(&self) -> String {
        uuid_string(&self.fsid)
    }
}

/// Decode the NUL-terminated btrfs label at `off` (up to [`BTRFS_LABEL_SIZE`]
/// bytes), lossily as UTF-8 and trimmed at the first NUL. Out-of-range yields an
/// empty string (never panics).
fn decode_label(block: &[u8], off: usize) -> String {
    let end = off.saturating_add(BTRFS_LABEL_SIZE).min(block.len());
    let raw = block.get(off..end).unwrap_or(&[]);
    let trimmed = raw.split(|&b| b == 0).next().unwrap_or(&[]);
    String::from_utf8_lossy(trimmed).into_owned()
}

/// Render a 16-byte UUID as the canonical `8-4-4-4-12` lower-hex string.
fn uuid_string(u: &[u8; 16]) -> String {
    let h: Vec<String> = u.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}{}{}{}-{}{}-{}{}-{}{}-{}{}{}{}{}{}",
        h[0],
        h[1],
        h[2],
        h[3],
        h[4],
        h[5],
        h[6],
        h[7],
        h[8],
        h[9],
        h[10],
        h[11],
        h[12],
        h[13],
        h[14],
        h[15]
    )
}
