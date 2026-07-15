//! btrfs superblock (`btrfs_super_block`) parse + `sys_chunk_array` bootstrap —
//! RED stub. The full-field decode arrives in the GREEN commit.

use crate::bytes::u8_at;
use crate::chunk::SysChunk;
use crate::crc::CsumType;
use crate::error::BtrfsError;

/// `BTRFS_SUPER_INFO_OFFSET` — the primary superblock's physical byte offset.
pub const BTRFS_SUPER_INFO_OFFSET: u64 = 65536;

/// `BTRFS_SUPER_INFO_SIZE` — the superblock block size (4096 bytes).
pub const BTRFS_SUPER_INFO_SIZE: usize = 4096;

/// The btrfs magic, ASCII `"_BHRfS_M"`, at superblock offset 0x40.
pub const BTRFS_MAGIC: [u8; 8] = *b"_BHRfS_M";

/// Offset of the magic within the superblock.
const MAGIC_OFFSET: usize = 0x40;

/// `BTRFS_FSID_SIZE`.
pub const BTRFS_FSID_SIZE: usize = 16;

/// `BTRFS_LABEL_SIZE`.
pub const BTRFS_LABEL_SIZE: usize = 256;

/// A parsed btrfs superblock (RED stub — fields present, decode not yet done).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Superblock {
    /// magic at 0x40.
    pub magic: [u8; 8],
    /// `csum` first 4 bytes.
    pub csum: [u8; 4],
    /// `fsid`.
    pub fsid: [u8; BTRFS_FSID_SIZE],
    /// `bytenr`.
    pub bytenr: u64,
    /// `flags`.
    pub flags: u64,
    /// `generation`.
    pub generation: u64,
    /// `root` logical.
    pub root: u64,
    /// `chunk_root` logical.
    pub chunk_root: u64,
    /// `log_root` logical.
    pub log_root: u64,
    /// `total_bytes`.
    pub total_bytes: u64,
    /// `bytes_used`.
    pub bytes_used: u64,
    /// `root_dir_objectid`.
    pub root_dir_objectid: u64,
    /// `num_devices`.
    pub num_devices: u64,
    /// `sectorsize`.
    pub sectorsize: u32,
    /// `nodesize`.
    pub nodesize: u32,
    /// `stripesize`.
    pub stripesize: u32,
    /// `sys_chunk_array_size`.
    pub sys_chunk_array_size: u32,
    /// `chunk_root_generation`.
    pub chunk_root_generation: u64,
    /// `compat_flags`.
    pub compat_flags: u64,
    /// `compat_ro_flags`.
    pub compat_ro_flags: u64,
    /// `incompat_flags`.
    pub incompat_flags: u64,
    /// `csum_type`.
    pub csum_type: CsumType,
    /// `root_level`.
    pub root_level: u8,
    /// `chunk_root_level`.
    pub chunk_root_level: u8,
    /// `log_root_level`.
    pub log_root_level: u8,
    /// `label`.
    pub label: String,
    /// decoded `sys_chunk_array`.
    pub sys_chunks: Vec<SysChunk>,
    /// crc32c status.
    pub crc_valid: Option<bool>,
}

impl Superblock {
    /// RED stub: validate magic + length, then return an all-default superblock
    /// (every oracle assertion fails until the GREEN decode lands).
    pub fn parse(block: &[u8]) -> Result<Self, BtrfsError> {
        let mut magic = [0u8; 8];
        for (i, b) in magic.iter_mut().enumerate() {
            *b = u8_at(block, MAGIC_OFFSET + i);
        }
        if magic != BTRFS_MAGIC {
            return Err(BtrfsError::BadMagic { bytes: magic });
        }
        if block.len() < 0xc9 {
            return Err(BtrfsError::Truncated {
                structure: "superblock",
                need: 0xc9,
                have: block.len(),
            });
        }
        Ok(Self {
            magic,
            csum: [0; 4],
            fsid: [0; BTRFS_FSID_SIZE],
            bytenr: 0,
            flags: 0,
            generation: 0,
            root: 0,
            chunk_root: 0,
            log_root: 0,
            total_bytes: 0,
            bytes_used: 0,
            root_dir_objectid: 0,
            num_devices: 0,
            sectorsize: 0,
            nodesize: 0,
            stripesize: 0,
            sys_chunk_array_size: 0,
            chunk_root_generation: 0,
            compat_flags: 0,
            compat_ro_flags: 0,
            incompat_flags: 0,
            csum_type: CsumType::Unknown(0xffff),
            root_level: 0,
            chunk_root_level: 0,
            log_root_level: 0,
            label: String::new(),
            sys_chunks: Vec::new(),
            crc_valid: None,
        })
    }

    /// RED stub.
    #[must_use]
    pub fn fsid_string(&self) -> String {
        String::new()
    }
}
