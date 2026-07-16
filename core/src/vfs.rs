//! `impl FileSystem for BtrfsFs` — the forensic-vfs adapter (behind the `vfs`
//! feature).
//!
//! Presents a btrfs image as a node-addressed, read-only [`forensic_vfs::FileSystem`].
//! btrfs nodes are objectids, mapped to [`FileId::Opaque`]; directory and run
//! enumerations are owned `Send` streams; every fallible btrfs-core call is
//! translated to a typed [`VfsError`], never an `unwrap`/panic.
//!
//! ## Mapping notes / known limits
//! - **`FsKind::Other`.** The published forensic-vfs `FsKind` enum has no `Btrfs`
//!   variant yet, so btrfs reports `Other`. Adding a `Btrfs` variant is the
//!   proper seam (a forensic-vfs release), not worked around here.
//! - **Whole-image buffering.** btrfs-core's traversal API operates on an
//!   in-memory `&[u8]`, so `open` reads the entire source into memory once. A
//!   streaming path is future work in btrfs-core.
//! - **Single FS-tree leaf.** btrfs-core's `fs_tree_root` resolves the FS tree's
//!   root *leaf*; interior root-tree descent is a later btrfs-core phase. Nodes
//!   outside that leaf are not yet reachable — a documented btrfs-core limit,
//!   surfaced here as an empty listing / not-found, never a panic.
//! - **`extents` empty.** btrfs-core exposes no public extent map (only whole-file
//!   `read_file`), so `extents` returns an empty stream; `read_at` reads the file
//!   and windows the requested range.
//! - **`FileId::Opaque` drops the btrfs generation** (objectid only).

use forensic_vfs::{
    Allocation, DirEntry as VfsDirEntry, DirStream, ExtentStream, FileId, FileSystem, FsKind,
    FsMeta, ImageSource, MacbTimes, NodeKind, NodeStream, ResidencyKind, SectorSizes, StreamId,
    TimeResolution, TimeSource, TimeStamp, TimeZonePolicy, VfsError, VfsResult,
};

use crate::{
    fs_tree_root, list_dir, read_file, read_inode, read_node, ChunkMap, DirItemType, Inode, Node,
    Superblock, Timestamp, BTRFS_SUPER_INFO_OFFSET,
};

/// A mounted btrfs image presented as a read-only [`FileSystem`].
pub struct BtrfsFs {
    image: Vec<u8>,
    sb: Superblock,
    map: ChunkMap,
    /// The FS-tree root leaf (btrfs-core traverses a single leaf; see module docs).
    leaf: Node,
    root_dirid: u64,
}

/// Extract the btrfs objectid a [`FileId`] addresses; any other identity domain
/// is a caller error, surfaced loud rather than silently mis-read.
fn oid_of(id: FileId) -> VfsResult<u64> {
    match id {
        FileId::Opaque(oid) => Ok(oid),
        other => Err(VfsError::Unsupported {
            layer: "btrfs file-id",
            scheme: format!("{other:?}"),
        }),
    }
}

/// btrfs has a single unnamed data stream; a named-stream id is refused loud.
fn require_default_stream(stream: StreamId) -> VfsResult<()> {
    match stream {
        StreamId::Default => Ok(()),
        other => Err(VfsError::Unsupported {
            layer: "btrfs stream",
            scheme: format!("{other:?}"),
        }),
    }
}

/// Fill `buf` from `src` at `off`, tolerating short reads and stopping at EOF.
fn fill(src: &dyn ImageSource, mut off: u64, mut buf: &mut [u8]) -> VfsResult<()> {
    while !buf.is_empty() {
        let n = src.read_at(off, buf)?;
        if n == 0 {
            break;
        }
        off = off.saturating_add(n as u64);
        let Some(rest) = buf.get_mut(n..) else {
            break; // cov:unreachable: read_at returns n <= buf.len()
        };
        buf = rest;
    }
    Ok(())
}

/// A btrfs directory-item type mapped to the unified node kind.
fn dirent_kind(t: &DirItemType) -> NodeKind {
    match t {
        DirItemType::File => NodeKind::File,
        DirItemType::Dir => NodeKind::Dir,
        DirItemType::Symlink => NodeKind::Symlink,
        DirItemType::Other(_) => NodeKind::Other,
    }
}

/// An inode's `mode` file-type bits mapped to the unified node kind.
fn inode_kind(inode: &Inode) -> NodeKind {
    // S_IFMT mask (0o170000) selects the type bits of the POSIX mode.
    match inode.mode & 0o170000 {
        0o100000 => NodeKind::File,
        0o040000 => NodeKind::Dir,
        0o120000 => NodeKind::Symlink,
        0o020000 | 0o060000 => NodeKind::Device,
        _ => NodeKind::Other,
    }
}

/// A btrfs `Timestamp` (Unix seconds + nanoseconds, UTC) as a unified stamp.
fn stamp(t: &Timestamp) -> TimeStamp {
    TimeStamp {
        unix_nanos: i128::from(t.sec) * 1_000_000_000 + i128::from(t.nsec),
        source: TimeSource::InodeTable,
        resolution: TimeResolution::Nanos,
    }
}

impl BtrfsFs {
    /// Buffer `source` and parse the superblock, chunk map, and FS-tree root leaf.
    /// Returns a typed [`VfsError`] (never a panic) on any malformed structure.
    pub fn open(source: &dyn ImageSource) -> VfsResult<Self> {
        let len = source.len();
        let mut image = vec![0u8; len as usize];
        fill(source, 0, &mut image)?;

        let sb_slice =
            image
                .get(BTRFS_SUPER_INFO_OFFSET as usize..)
                .ok_or(VfsError::OutOfRange {
                    what: "btrfs superblock offset",
                    offset: BTRFS_SUPER_INFO_OFFSET,
                    len: 1,
                    bound: len,
                })?;
        let sb = Superblock::parse(sb_slice).map_err(map_btrfs_err)?;
        let map = ChunkMap::walk(&image, &sb).map_err(map_btrfs_err)?;
        let root = fs_tree_root(&image, &sb, &map).map_err(map_btrfs_err)?;
        let leaf = read_node(&image, &sb, &map, root.bytenr).map_err(map_btrfs_err)?;

        Ok(Self {
            image,
            sb,
            map,
            leaf,
            root_dirid: root.root_dirid,
        })
    }
}

/// Translate a btrfs-core error into the VFS error type.
fn map_btrfs_err(e: crate::BtrfsError) -> VfsError {
    VfsError::Decode {
        layer: "btrfs",
        offset: 0,
        detail: e.to_string(),
        bytes: forensic_vfs::SmallHex::new(&[]),
    }
}

impl FileSystem for BtrfsFs {
    fn kind(&self) -> FsKind {
        FsKind::Other
    }

    fn root(&self) -> FileId {
        FileId::Opaque(self.root_dirid)
    }

    fn sector_sizes(&self) -> SectorSizes {
        SectorSizes {
            logical: 512,
            physical: 512,
            cluster_or_block: self.sb.sectorsize,
        }
    }

    fn timestamp_zone(&self) -> TimeZonePolicy {
        TimeZonePolicy::Utc
    }

    fn read_dir(&self, ino: FileId) -> VfsResult<DirStream> {
        let dir_oid = oid_of(ino)?;
        let out: Vec<VfsResult<VfsDirEntry>> = list_dir(&self.leaf, dir_oid)
            .into_iter()
            .map(|e| {
                Ok(VfsDirEntry {
                    name: e.name.into_bytes(),
                    id: FileId::Opaque(e.child),
                    kind: dirent_kind(&e.item_type),
                })
            })
            .collect();
        Ok(DirStream::new(out.into_iter()))
    }

    fn extents(&self, _ino: FileId, _stream: StreamId) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }

    fn lookup(&self, parent: FileId, name: &[u8]) -> VfsResult<Option<FileId>> {
        let dir_oid = oid_of(parent)?;
        let found = list_dir(&self.leaf, dir_oid)
            .into_iter()
            .find(|e| e.name.as_bytes() == name)
            .map(|e| FileId::Opaque(e.child));
        Ok(found)
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        let oid = oid_of(ino)?;
        let inode = read_inode(&self.leaf, oid).ok_or(VfsError::OutOfRange {
            what: "btrfs inode (not in FS-tree root leaf)",
            offset: oid,
            len: 1,
            bound: 0,
        })?;
        // otime (btrfs "creation" time) of exactly zero is treated as absent —
        // forensically distinct from an epoch-zero birth.
        let born = if inode.otime.sec != 0 {
            Some(stamp(&inode.otime))
        } else {
            None
        };
        Ok(FsMeta {
            ino: inode.objectid,
            kind: inode_kind(&inode),
            allocated: Allocation::Allocated,
            size: inode.size,
            nlink: inode.nlink,
            uid: Some(inode.uid),
            gid: Some(inode.gid),
            mode: Some(inode.mode),
            times: MacbTimes {
                modified: Some(stamp(&inode.mtime)),
                accessed: Some(stamp(&inode.atime)),
                changed: Some(stamp(&inode.ctime)),
                born,
            },
            streams: Vec::new(),
            residency: ResidencyKind::NonResident,
            link_target: None,
        })
    }

    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let oid = oid_of(ino)?;
        require_default_stream(stream)?;
        // btrfs-core reads a whole file (no ranged API); window the requested
        // range out of the returned bytes.
        let data = read_file(&self.image, &self.sb, &self.map, oid).map_err(map_btrfs_err)?;
        let start = off.min(data.len() as u64) as usize;
        let Some(avail) = data.get(start..) else {
            return Ok(0); // cov:unreachable: start <= data.len() by the min above
        };
        let n = avail.len().min(buf.len());
        let Some(dst) = buf.get_mut(..n) else {
            return Ok(0); // cov:unreachable: n <= buf.len() by the min above
        };
        dst.copy_from_slice(&avail[..n]);
        Ok(n)
    }

    fn read_link(&self, ino: FileId, cap: usize) -> VfsResult<Vec<u8>> {
        let oid = oid_of(ino)?;
        let Some(inode) = read_inode(&self.leaf, oid) else {
            return Ok(Vec::new());
        };
        if inode_kind(&inode) != NodeKind::Symlink {
            // A non-symlink reads as an empty target (matches the ext4 adapter).
            return Ok(Vec::new());
        }
        // btrfs stores a symlink target as the node's inline file content.
        let mut target = read_file(&self.image, &self.sb, &self.map, oid).map_err(map_btrfs_err)?;
        target.truncate(cap);
        Ok(target)
    }

    fn deleted(&self) -> VfsResult<NodeStream> {
        Ok(NodeStream::empty())
    }

    fn unallocated(&self) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }
}

#[cfg(test)]
mod tests {
    use super::BtrfsFs;
    use forensic_vfs::{
        FileId, FileSystem, FsKind, ImageSource, NodeKind, StreamId, VfsError, VfsResult,
    };

    // ── Always-on VFS adapter coverage over a crafted, walkable btrfs image ──────
    //
    // The oracle test below needs the 256 MiB deletion image (BTRFS_DEL_ORACLE),
    // absent on CI. These always-on tests drive the same adapter over a small
    // crafted image whose on-disk layout is the verified btrfs layout: an identity
    // sys_chunk_array, a ROOT_TREE leaf holding the FS_TREE ROOT_ITEM, and a
    // FS_TREE leaf with a directory, a file (inline extent + timestamps), and a
    // symlink. A minimal in-memory `ImageSource` feeds `BtrfsFs::open` — no image
    // file on disk, so the path is always exercised.

    const NODESIZE: usize = 16_384;
    const HDR_END: usize = 101;
    const ITEM_STRIDE: usize = 25;
    const SUPER_OFFSET: usize = 65_536;
    const SUPER_SIZE: usize = 4096;
    const ROOT_LOGICAL: u64 = 0x20_000;
    const FS_LEAF_LOGICAL: u64 = 0x30_000;
    const CHUNK_LEN: u64 = 4 * 1024 * 1024;

    /// A read-only in-memory [`ImageSource`] over an owned image buffer.
    struct MemSource(Vec<u8>);
    impl ImageSource for MemSource {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
            let start = (offset as usize).min(self.0.len());
            let avail = &self.0[start..];
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            Ok(n)
        }
    }

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

    /// Build a leaf node (`owner`, level 0) with `items = (objectid, type, key_off,
    /// data)` laid out backward from the node end, and a fixed-up crc32c.
    fn build_leaf(owner: u64, items: &[(u64, u8, u64, Vec<u8>)]) -> Vec<u8> {
        let mut node = vec![0u8; NODESIZE];
        node[0x30..0x38].copy_from_slice(&30_654_464u64.to_le_bytes()); // bytenr
        node[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
        node[0x60..0x64].copy_from_slice(&(items.len() as u32).to_le_bytes());
        node[0x64] = 0; // leaf
        let mut tail = NODESIZE;
        for (i, (oid, ty, koff, data)) in items.iter().enumerate() {
            let io = HDR_END + i * ITEM_STRIDE;
            node[io..io + 8].copy_from_slice(&oid.to_le_bytes());
            node[io + 8] = *ty;
            node[io + 9..io + 17].copy_from_slice(&koff.to_le_bytes());
            tail -= data.len();
            let doff = (tail - HDR_END) as u32;
            node[io + 17..io + 21].copy_from_slice(&doff.to_le_bytes());
            node[io + 21..io + 25].copy_from_slice(&(data.len() as u32).to_le_bytes());
            node[tail..tail + data.len()].copy_from_slice(data);
        }
        let c = crc32c(&node[0x20..]);
        node[0..4].copy_from_slice(&c.to_le_bytes());
        node
    }

    /// A 160-byte INODE_ITEM: size@16, nlink@40, uid@44, gid@48, mode@52, and the
    /// four 12-byte timestamps (atime@112, ctime@124, mtime@136, otime@148).
    #[allow(clippy::too_many_arguments)]
    fn inode_item(size: u64, mode: u32, nlink: u32, uid: u32, gid: u32, otime_sec: u64) -> Vec<u8> {
        let mut d = vec![0u8; 160];
        d[16..24].copy_from_slice(&size.to_le_bytes());
        d[40..44].copy_from_slice(&nlink.to_le_bytes());
        d[44..48].copy_from_slice(&uid.to_le_bytes());
        d[48..52].copy_from_slice(&gid.to_le_bytes());
        d[52..56].copy_from_slice(&mode.to_le_bytes());
        d[112..120].copy_from_slice(&111u64.to_le_bytes()); // atime.sec
        d[124..132].copy_from_slice(&222u64.to_le_bytes()); // ctime.sec
        d[136..144].copy_from_slice(&333u64.to_le_bytes()); // mtime.sec
        d[148..156].copy_from_slice(&otime_sec.to_le_bytes()); // otime.sec
        d
    }

    /// An inline EXTENT_DATA (type 0) carrying `payload` (ram_bytes = len).
    fn inline_extent(payload: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 21 + payload.len()];
        d[8..16].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        d[20] = 0; // inline
        d[21..].copy_from_slice(payload);
        d
    }

    /// A DIR_ITEM body: location key[17] + transid(8) + data_len(2) + name_len(2) +
    /// type(1) + name. `ft` is the btrfs FT_* type byte.
    fn dir_item(child: u64, ft: u8, name: &[u8]) -> Vec<u8> {
        let mut d = vec![0u8; 30 + name.len()];
        d[0..8].copy_from_slice(&child.to_le_bytes());
        d[8] = 1; // location.type = INODE_ITEM
        d[27..29].copy_from_slice(&(name.len() as u16).to_le_bytes());
        d[29] = ft;
        d[30..].copy_from_slice(name);
        d
    }

    /// A CHUNK_TREE leaf (chunk_root) with one CHUNK_ITEM identity-mapping
    /// `[0, CHUNK_LEN)`, so `ChunkMap::walk` yields an identity map.
    fn build_chunk_leaf() -> Vec<u8> {
        let mut node = vec![0u8; NODESIZE];
        node[0x30..0x38].copy_from_slice(&0u64.to_le_bytes()); // bytenr
        node[0x58..0x60].copy_from_slice(&3u64.to_le_bytes()); // owner = CHUNK_TREE
        node[0x60..0x64].copy_from_slice(&1u32.to_le_bytes()); // nritems
        node[0x64] = 0; // leaf
        let mut chunk = vec![0u8; 48 + 32];
        chunk[0..8].copy_from_slice(&CHUNK_LEN.to_le_bytes()); // length
        chunk[24..32].copy_from_slice(&0x1u64.to_le_bytes()); // type DATA
        chunk[44..46].copy_from_slice(&1u16.to_le_bytes()); // num_stripes
        chunk[46..48].copy_from_slice(&1u16.to_le_bytes()); // sub_stripes
        chunk[48..56].copy_from_slice(&1u64.to_le_bytes()); // stripe devid
        chunk[56..64].copy_from_slice(&0u64.to_le_bytes()); // stripe offset (identity)
        let data_tail = NODESIZE - chunk.len();
        let io = HDR_END;
        node[io..io + 8].copy_from_slice(&256u64.to_le_bytes()); // FIRST_CHUNK_TREE
        node[io + 8] = 228; // CHUNK_ITEM
        node[io + 9..io + 17].copy_from_slice(&0u64.to_le_bytes()); // logical 0
        node[io + 17..io + 21].copy_from_slice(&((data_tail - HDR_END) as u32).to_le_bytes());
        node[io + 21..io + 25].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
        node[data_tail..data_tail + chunk.len()].copy_from_slice(&chunk);
        let c = crc32c(&node[0x20..]);
        node[0..4].copy_from_slice(&c.to_le_bytes());
        node
    }

    /// A superblock whose `root` = ROOT_LOGICAL, `chunk_root` = 0, and whose
    /// sys_chunk_array identity-maps `[0, CHUNK_LEN)`.
    fn build_super() -> Vec<u8> {
        let mut sb = vec![0u8; SUPER_SIZE];
        sb[0x40..0x48].copy_from_slice(b"_BHRfS_M");
        sb[0x30..0x38].copy_from_slice(&65536u64.to_le_bytes()); // bytenr
        sb[0x50..0x58].copy_from_slice(&ROOT_LOGICAL.to_le_bytes()); // root
        sb[0x58..0x60].copy_from_slice(&0u64.to_le_bytes()); // chunk_root logical 0
        sb[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes()); // sectorsize
        sb[0x94..0x98].copy_from_slice(&(NODESIZE as u32).to_le_bytes()); // nodesize
        let arr = 0x32busize;
        sb[arr..arr + 8].copy_from_slice(&256u64.to_le_bytes());
        sb[arr + 8] = 228;
        sb[arr + 9..arr + 17].copy_from_slice(&0u64.to_le_bytes()); // logical 0
        let mut ci = vec![0u8; 48 + 32];
        ci[0..8].copy_from_slice(&CHUNK_LEN.to_le_bytes());
        ci[24..32].copy_from_slice(&0x2u64.to_le_bytes()); // SYSTEM
        ci[44..46].copy_from_slice(&1u16.to_le_bytes());
        ci[46..48].copy_from_slice(&1u16.to_le_bytes());
        ci[48..56].copy_from_slice(&1u64.to_le_bytes());
        ci[56..64].copy_from_slice(&0u64.to_le_bytes());
        sb[arr + 17..arr + 17 + ci.len()].copy_from_slice(&ci);
        sb[0xa0..0xa4].copy_from_slice(&((17 + ci.len()) as u32).to_le_bytes());
        sb
    }

    /// Assemble a walkable in-memory btrfs image: chunk leaf @0, superblock
    /// @0x10000, ROOT_TREE leaf @ROOT_LOGICAL, FS_TREE leaf @FS_LEAF_LOGICAL. The
    /// FS_TREE root dir (256) holds `note.txt` (257, a file with an inline extent),
    /// `link` (258, a symlink whose target is its inline content), and `sub` (259,
    /// a directory). Returns the image bytes.
    fn walkable_image() -> Vec<u8> {
        let mut img = vec![0u8; CHUNK_LEN as usize];
        img[0..NODESIZE].copy_from_slice(&build_chunk_leaf());
        img[SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE].copy_from_slice(&build_super());

        // ROOT_TREE leaf: FS_TREE (objectid 5) ROOT_ITEM whose bytenr@176 =
        // FS_LEAF_LOGICAL, root_dirid@168 = 256, level@238 = 0.
        let mut root_item = vec![0u8; 239];
        root_item[168..176].copy_from_slice(&256u64.to_le_bytes()); // root_dirid
        root_item[176..184].copy_from_slice(&FS_LEAF_LOGICAL.to_le_bytes()); // bytenr
        let root_leaf = build_leaf(
            1, /* ROOT_TREE */
            &[(5, 132 /* ROOT_ITEM */, 0, root_item)],
        );
        img[ROOT_LOGICAL as usize..ROOT_LOGICAL as usize + NODESIZE].copy_from_slice(&root_leaf);

        // FS_TREE leaf.
        let link_target = b"target/path";
        let fs_leaf = build_leaf(
            5, /* FS_TREE */
            &[
                // root dir 256 (dir) with three entries.
                (256, 1, 0, inode_item(0, 0o040_755, 2, 0, 0, 500)),
                (256, 84, 10, dir_item(257, 1 /* FT_REG */, b"note.txt")),
                (256, 84, 20, dir_item(258, 7 /* FT_SYMLINK */, b"link")),
                (256, 84, 30, dir_item(259, 2 /* FT_DIR */, b"sub")),
                // note.txt 257 (regular file, inline content, otime present).
                (257, 1, 0, inode_item(9, 0o100_644, 1, 1000, 1000, 700)),
                (257, 108, 0, inline_extent(b"note body")),
                // link 258 (symlink; target is its inline content, otime = 0 → born None).
                (
                    258,
                    1,
                    0,
                    inode_item(link_target.len() as u64, 0o120_777, 1, 0, 0, 0),
                ),
                (258, 108, 0, inline_extent(link_target)),
                // sub 259 (empty directory).
                (259, 1, 0, inode_item(0, 0o040_755, 2, 0, 0, 0)),
                // dev 260: a device node named with an UNKNOWN dir-item FT type
                // (99 → DirItemType::Other → NodeKind::Other in read_dir), whose
                // INODE mode is a char/block device (0o020000 → NodeKind::Device).
                (256, 84, 40, dir_item(260, 99 /* unknown FT */, b"dev")),
                (260, 1, 0, inode_item(0, 0o020_000, 1, 0, 0, 0)),
                // fifo 261: a mode that classifies to none of file/dir/symlink/
                // device (0o010000 FIFO → the inode_kind `_ => Other` arm).
                (261, 1, 0, inode_item(0, 0o010_000, 1, 0, 0, 0)),
            ],
        );
        img[FS_LEAF_LOGICAL as usize..FS_LEAF_LOGICAL as usize + fs_leaf.len()]
            .copy_from_slice(&fs_leaf);
        img
    }

    fn open_crafted() -> BtrfsFs {
        BtrfsFs::open(&MemSource(walkable_image())).expect("open crafted walkable btrfs image")
    }

    #[test]
    fn open_and_root_metadata_over_crafted_image() {
        let fs = open_crafted();
        assert_eq!(fs.kind(), FsKind::Other);
        assert_eq!(fs.root(), FileId::Opaque(256));
        let ss = fs.sector_sizes();
        assert_eq!(ss.logical, 512);
        assert_eq!(ss.physical, 512);
        assert_eq!(ss.cluster_or_block, 4096, "btrfs sectorsize");
        assert!(matches!(
            fs.timestamp_zone(),
            forensic_vfs::TimeZonePolicy::Utc
        ));
        assert!(fs.extents(FileId::Opaque(257), StreamId::Default).is_ok());
        assert!(fs.deleted().is_ok());
        assert!(fs.unallocated().is_ok());
    }

    #[test]
    fn read_dir_and_lookup_classify_children() {
        let fs = open_crafted();
        let entries: Vec<_> = fs
            .read_dir(FileId::Opaque(256))
            .expect("read_dir root")
            .collect::<Result<_, _>>()
            .expect("dir entries");
        let note = entries.iter().find(|e| e.name == b"note.txt").unwrap();
        assert_eq!(note.id, FileId::Opaque(257));
        assert_eq!(note.kind, NodeKind::File);
        let link = entries.iter().find(|e| e.name == b"link").unwrap();
        assert_eq!(link.kind, NodeKind::Symlink);
        let sub = entries.iter().find(|e| e.name == b"sub").unwrap();
        assert_eq!(sub.kind, NodeKind::Dir);
        // An unknown dir-item FT type maps to NodeKind::Other (unknown value not
        // dropped, classified as Other).
        let dev = entries.iter().find(|e| e.name == b"dev").unwrap();
        assert_eq!(dev.kind, NodeKind::Other, "unknown FT type → Other");

        assert_eq!(
            fs.lookup(FileId::Opaque(256), b"note.txt").unwrap(),
            Some(FileId::Opaque(257))
        );
        assert_eq!(fs.lookup(FileId::Opaque(256), b"absent").unwrap(), None);
    }

    #[test]
    fn meta_classifies_device_and_other_inode_kinds() {
        let fs = open_crafted();
        // A char/block device inode mode (0o020000) → NodeKind::Device.
        assert_eq!(fs.meta(FileId::Opaque(260)).unwrap().kind, NodeKind::Device);
        // A FIFO mode (0o010000) classifies to none of the named kinds → Other.
        assert_eq!(fs.meta(FileId::Opaque(261)).unwrap().kind, NodeKind::Other);
    }

    #[test]
    fn open_tolerates_a_source_that_short_reads_before_eof() {
        // A source whose `len()` exceeds the bytes it will actually return: `fill`
        // must stop at the first zero-length read rather than spin (the `n == 0`
        // break). The prefix it did return still holds a valid btrfs image.
        struct ShortSource {
            data: Vec<u8>,
            reported_len: u64,
        }
        impl ImageSource for ShortSource {
            fn len(&self) -> u64 {
                self.reported_len
            }
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
                let start = offset as usize;
                if start >= self.data.len() {
                    return Ok(0); // past the real data → short read
                }
                let avail = &self.data[start..];
                let n = avail.len().min(buf.len());
                buf[..n].copy_from_slice(&avail[..n]);
                Ok(n)
            }
        }
        let data = walkable_image();
        let reported_len = data.len() as u64 + 4096; // claim more than we serve
        let fs = BtrfsFs::open(&ShortSource { data, reported_len })
            .expect("open despite the trailing short read");
        assert_eq!(fs.root(), FileId::Opaque(256));
    }

    #[test]
    fn meta_decodes_inode_kind_size_and_times() {
        let fs = open_crafted();
        // File: otime present → born Some.
        let m = fs.meta(FileId::Opaque(257)).unwrap();
        assert_eq!(m.ino, 257);
        assert_eq!(m.kind, NodeKind::File);
        assert_eq!(m.size, 9);
        assert_eq!(m.nlink, 1);
        assert_eq!(m.uid, Some(1000));
        assert_eq!(m.gid, Some(1000));
        assert_eq!(m.mode, Some(0o100_644));
        assert!(m.times.born.is_some(), "otime != 0 → born present");
        assert!(m.times.modified.is_some());
        // Directory: otime == 0 → born None.
        let d = fs.meta(FileId::Opaque(259)).unwrap();
        assert_eq!(d.kind, NodeKind::Dir);
        assert!(d.times.born.is_none(), "otime == 0 → born absent");
        // Absent inode → loud OutOfRange, never a fabricated blank.
        assert!(matches!(
            fs.meta(FileId::Opaque(9999)),
            Err(VfsError::OutOfRange { .. })
        ));
    }

    #[test]
    fn read_at_windows_the_file_content() {
        let fs = open_crafted();
        let mut buf = vec![0u8; 4];
        let n = fs
            .read_at(FileId::Opaque(257), StreamId::Default, 5, &mut buf)
            .unwrap();
        assert_eq!(&buf[..n], b"body", "read_at windows from offset 5");
        // A read past EOF returns 0 bytes.
        let n = fs
            .read_at(FileId::Opaque(257), StreamId::Default, 1000, &mut buf)
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_link_returns_symlink_target_and_empty_for_non_symlink() {
        let fs = open_crafted();
        let target = fs.read_link(FileId::Opaque(258), 4096).unwrap();
        assert_eq!(target, b"target/path", "symlink target = inline content");
        // A cap truncates the target.
        let capped = fs.read_link(FileId::Opaque(258), 6).unwrap();
        assert_eq!(capped, b"target");
        // A non-symlink (regular file) reads as an empty target.
        assert!(fs.read_link(FileId::Opaque(257), 4096).unwrap().is_empty());
        // An absent inode reads as an empty target (no panic).
        assert!(fs.read_link(FileId::Opaque(9999), 4096).unwrap().is_empty());
    }

    #[test]
    fn non_opaque_file_id_and_named_stream_are_refused_loud() {
        let fs = open_crafted();
        // A non-Opaque FileId is an unsupported identity domain.
        assert!(matches!(
            fs.read_dir(FileId::NtfsRef { entry: 1, seq: 0 }),
            Err(VfsError::Unsupported { .. })
        ));
        // A named stream is refused (btrfs has a single unnamed data stream).
        let mut buf = [0u8; 4];
        assert!(matches!(
            fs.read_at(FileId::Opaque(257), StreamId::Named(7), 0, &mut buf),
            Err(VfsError::Unsupported { .. })
        ));
    }

    #[test]
    fn open_malformed_source_is_a_loud_error_not_a_panic() {
        // A too-short source (no superblock) surfaces a typed VfsError.
        assert!(BtrfsFs::open(&MemSource(vec![0u8; 16])).is_err());
        // A source long enough for the superblock offset but with no valid
        // superblock magic fails loud in Superblock::parse.
        assert!(BtrfsFs::open(&MemSource(vec![0u8; SUPER_OFFSET + SUPER_SIZE])).is_err());
    }

    // The env-gated Tier-2 oracle test (over the 256 MiB deletion image) lives in
    // `core/tests/vfs_oracle.rs` — as an integration test its body is not counted
    // by the CI coverage gate (which lacks the oracle), matching every other
    // env-gated fixture test; the always-on tests above cover the adapter itself.
}
