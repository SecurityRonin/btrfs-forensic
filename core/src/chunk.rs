//! btrfs `sys_chunk_array` bootstrap chunk map (the P1 seed).
//!
//! Every btrfs tree except the superblock is addressed by **logical** address;
//! nothing is readable until a logical→physical map exists. The bootstrap for
//! that map lives inside the superblock: the `sys_chunk_array` region (offset
//! [`SYS_CHUNK_ARRAY_OFFSET`] = 0x32b, `sys_chunk_array_size` bytes valid) holds
//! a packed sequence of `[btrfs_disk_key][btrfs_chunk + btrfs_stripe…]` entries
//! describing the SYSTEM block groups — enough to reach the chunk tree at the
//! `chunk_root` logical address.
//!
//! P0 decodes these structs (key + chunk geometry + stripes) so the mapping is
//! available; **full chunk-tree walking is P1**. Struct layouts were transcribed
//! from the on-disk `btrfs_disk_key` / `btrfs_chunk` / `btrfs_stripe` and
//! **verified byte-for-byte against `dump-super -f`** on the oracle image (see
//! `tests/data/README.md`).

use crate::bytes::{le_u16, le_u64, u8_at};

/// Offset of the `sys_chunk_array` within the superblock block.
pub const SYS_CHUNK_ARRAY_OFFSET: usize = 0x32b;

/// `btrfs_disk_key` on-disk size: `objectid(u64) + type(u8) + offset(u64)`.
pub const DISK_KEY_SIZE: usize = 17;

/// The `btrfs_chunk` fixed header size, up to (but excluding) the variable
/// stripe array: `length,owner,stripe_len,type` (4×u64) + `io_align,io_width,
/// sector_size` (3×u32) + `num_stripes,sub_stripes` (2×u16) = 48 bytes.
pub const CHUNK_HEADER_SIZE: usize = 48;

/// `btrfs_stripe` on-disk size: `devid(u64) + offset(u64) + dev_uuid[16]`.
pub const STRIPE_SIZE: usize = 32;

/// `BTRFS_CHUNK_ITEM_KEY` — the disk-key type byte of a chunk item (228).
pub const CHUNK_ITEM_KEY: u8 = 228;

// btrfs_chunk `type` block-group flag bits.
/// `BTRFS_BLOCK_GROUP_DATA` (1 << 0).
pub const BLOCK_GROUP_DATA: u64 = 1 << 0;
/// `BTRFS_BLOCK_GROUP_SYSTEM` (1 << 1).
pub const BLOCK_GROUP_SYSTEM: u64 = 1 << 1;
/// `BTRFS_BLOCK_GROUP_METADATA` (1 << 2).
pub const BLOCK_GROUP_METADATA: u64 = 1 << 2;
/// `BTRFS_BLOCK_GROUP_DUP` (1 << 5).
pub const BLOCK_GROUP_DUP: u64 = 1 << 5;

/// A `btrfs_disk_key` — the `(objectid, type, offset)` tuple every btrfs item is
/// keyed by. Fields are LE on disk; compared as host integers on the tuple
/// (that ordering is P2's concern; P0 just carries the decoded values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskKey {
    /// `objectid` — for a sys chunk item this is `FIRST_CHUNK_TREE_OBJECTID`
    /// (256).
    pub objectid: u64,
    /// `type` — the item-type byte (228 = `CHUNK_ITEM` for a sys chunk entry).
    pub key_type: u8,
    /// `offset` — for a chunk item this is the chunk's logical start address.
    pub offset: u64,
}

impl DiskKey {
    /// Decode a `btrfs_disk_key` at `off` (bounds-checked; out-of-range fields
    /// read as 0).
    #[must_use]
    pub fn parse(data: &[u8], off: usize) -> Self {
        DiskKey {
            objectid: le_u64(data, off),
            key_type: u8_at(data, off + 8),
            offset: le_u64(data, off + 9),
        }
    }
}

/// One stripe of a chunk: a physical placement on a device. For single-device
/// single/DUP the physical byte address of a logical address `l` within the
/// chunk is `stripe.offset + (l - chunk_key.offset)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stripe {
    /// `devid` — the device this stripe lives on.
    pub devid: u64,
    /// `offset` — the physical byte offset on the device where the chunk's data
    /// begins for this stripe.
    pub offset: u64,
    /// `dev_uuid` — the device UUID.
    pub dev_uuid: [u8; 16],
}

/// A decoded chunk map entry from the `sys_chunk_array`: the chunk's logical
/// key, its geometry, and its stripes. This is the bootstrap logical→physical
/// record for a SYSTEM block group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysChunk {
    /// The chunk item's disk key; `key.offset` is the chunk's logical start.
    pub key: DiskKey,
    /// `length` — the chunk's logical byte span.
    pub length: u64,
    /// `owner` — the objectid that owns the chunk (2 = the extent tree).
    pub owner: u64,
    /// `stripe_len` — the RAID stripe unit (irrelevant for single/DUP mapping).
    pub stripe_len: u64,
    /// `type` — the block-group flags (`BLOCK_GROUP_SYSTEM | BLOCK_GROUP_DUP`,
    /// etc.).
    pub chunk_type: u64,
    /// `num_stripes` — the number of physical stripes that follow.
    pub num_stripes: u16,
    /// `sub_stripes` — RAID10 sub-stripe count (1 for single/DUP).
    pub sub_stripes: u16,
    /// The decoded stripes (physical placements).
    pub stripes: Vec<Stripe>,
}

impl SysChunk {
    /// Translate a logical address `logical` to a physical byte offset on the
    /// first stripe's device, for single-device single/DUP chunks.
    ///
    /// Returns `None` if `logical` lies outside this chunk's `[key.offset ..
    /// key.offset + length)` span, or if the chunk has no stripes. For DUP there
    /// are two stripes on the same device; the first mirror (`stripes[0]`) is
    /// chosen (both hold identical data). Multi-device / striped RAID mapping is
    /// deferred to a later phase.
    #[must_use]
    pub fn logical_to_physical(&self, logical: u64) -> Option<u64> {
        let start = self.key.offset;
        let end = start.checked_add(self.length)?;
        if logical < start || logical >= end {
            return None;
        }
        let stripe = self.stripes.first()?;
        let delta = logical - start;
        stripe.offset.checked_add(delta)
    }

    /// Parse the packed `sys_chunk_array` starting at `array_off` for
    /// `array_size` valid bytes, yielding one [`SysChunk`] per
    /// `[disk_key][chunk + stripes]` entry.
    ///
    /// Bounds-checked and panic-free: parsing stops at the first entry that does
    /// not wholly fit within the declared `array_size` (or the block), and an
    /// absurd `num_stripes` is capped by the remaining bytes — a malformed array
    /// truncates rather than over-reads or panics.
    #[must_use]
    pub fn parse_array(block: &[u8], array_off: usize, array_size: u32) -> Vec<SysChunk> {
        let mut out = Vec::new();
        // The valid region is `[array_off .. array_off + array_size]`, clamped to
        // the block we were handed.
        let declared_end = array_off.saturating_add(array_size as usize);
        let end = declared_end.min(block.len());

        let mut p = array_off;
        loop {
            // A whole entry needs at least a disk key + a chunk header.
            let key_end = p.saturating_add(DISK_KEY_SIZE);
            let hdr_end = key_end.saturating_add(CHUNK_HEADER_SIZE);
            if hdr_end > end {
                break;
            }

            let key = DiskKey::parse(block, p);
            let c = key_end; // chunk header starts right after the 17-byte key
            let length = le_u64(block, c);
            let owner = le_u64(block, c + 8);
            let stripe_len = le_u64(block, c + 16);
            let chunk_type = le_u64(block, c + 24);
            // io_align (c+32), io_width (c+36), sector_size (c+40) are geometry
            // hints not needed for single/DUP logical→physical mapping.
            let num_stripes = le_u16(block, c + 44);
            let sub_stripes = le_u16(block, c + 46);

            let stripes_start = c.saturating_add(CHUNK_HEADER_SIZE);
            let stripes_bytes = usize::from(num_stripes).saturating_mul(STRIPE_SIZE);
            let stripes_end = stripes_start.saturating_add(stripes_bytes);
            if stripes_end > end {
                // A declared stripe count that overruns the valid region is a
                // malformed/truncated array — stop rather than over-read.
                break;
            }

            let mut stripes = Vec::with_capacity(usize::from(num_stripes));
            let mut s = stripes_start;
            for _ in 0..num_stripes {
                let devid = le_u64(block, s);
                let offset = le_u64(block, s + 8);
                let mut dev_uuid = [0u8; 16];
                for (i, b) in dev_uuid.iter_mut().enumerate() {
                    *b = u8_at(block, s + 16 + i);
                }
                stripes.push(Stripe {
                    devid,
                    offset,
                    dev_uuid,
                });
                s = s.saturating_add(STRIPE_SIZE);
            }

            out.push(SysChunk {
                key,
                length,
                owner,
                stripe_len,
                chunk_type,
                num_stripes,
                sub_stripes,
                stripes,
            });

            p = stripes_end;
        }
        out
    }
}

#[cfg(test)]
mod unit {
    use super::{
        DiskKey, Stripe, SysChunk, CHUNK_HEADER_SIZE, DISK_KEY_SIZE, STRIPE_SIZE,
        SYS_CHUNK_ARRAY_OFFSET,
    };

    /// Build a minimal chunk entry: 17-byte key + 48-byte chunk header (with the
    /// given `num_stripes` at header offset 44) + `present_stripes` stripes.
    fn chunk_entry(key_offset: u64, num_stripes: u16, present_stripes: usize) -> Vec<u8> {
        let mut e = vec![0u8; DISK_KEY_SIZE + CHUNK_HEADER_SIZE + present_stripes * STRIPE_SIZE];
        // disk key: objectid=256, type=228, offset=key_offset
        e[0..8].copy_from_slice(&256u64.to_le_bytes());
        e[8] = 228;
        e[9..17].copy_from_slice(&key_offset.to_le_bytes());
        // chunk header: length at c+0, num_stripes at c+44
        let c = DISK_KEY_SIZE;
        e[c..c + 8].copy_from_slice(&8_388_608u64.to_le_bytes());
        e[c + 44..c + 46].copy_from_slice(&num_stripes.to_le_bytes());
        e
    }

    #[test]
    fn parse_array_stops_when_stripes_overrun_the_declared_region() {
        // A chunk header claims 2 stripes but the array only carries the header:
        // `stripes_end > end` must break rather than over-read (chunk.rs:171).
        let entry = chunk_entry(22_020_096, 2, 0);
        let mut block = vec![0u8; SYS_CHUNK_ARRAY_OFFSET + entry.len()];
        block[SYS_CHUNK_ARRAY_OFFSET..].copy_from_slice(&entry);
        let size = entry.len() as u32; // declares only the header, not the 2 stripes
        let chunks = SysChunk::parse_array(&block, SYS_CHUNK_ARRAY_OFFSET, size);
        assert!(chunks.is_empty(), "overrunning stripe count truncates");
    }

    #[test]
    fn logical_to_physical_guards_out_of_span_and_empty_stripes() {
        let c = SysChunk {
            key: DiskKey {
                objectid: 256,
                key_type: 228,
                offset: 1000,
            },
            length: 100,
            owner: 2,
            stripe_len: 65536,
            chunk_type: 0x22,
            num_stripes: 1,
            sub_stripes: 1,
            stripes: vec![Stripe {
                devid: 1,
                offset: 5000,
                dev_uuid: [0u8; 16],
            }],
        };
        assert_eq!(c.logical_to_physical(1000), Some(5000), "start maps");
        assert_eq!(c.logical_to_physical(1050), Some(5050), "mid maps");
        assert_eq!(c.logical_to_physical(999), None, "below span");
        assert_eq!(c.logical_to_physical(1100), None, "at/above end");

        // No stripes → cannot map even an in-span address.
        let mut no_stripes = c.clone();
        no_stripes.stripes.clear();
        assert_eq!(no_stripes.logical_to_physical(1000), None);

        // A hostile chunk whose `key.offset + length` overflows u64: the span end
        // is unrepresentable, so the mapping guards to `None` rather than
        // wrapping (chunk.rs `checked_add` short-circuit).
        let overflow = SysChunk {
            key: DiskKey {
                objectid: 256,
                key_type: 228,
                offset: u64::MAX - 10,
            },
            length: 100,
            ..c
        };
        assert_eq!(overflow.logical_to_physical(u64::MAX - 5), None);
    }
}
