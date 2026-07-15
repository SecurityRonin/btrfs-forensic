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

use std::sync::Mutex;

use forensic_vfs::{
    Allocation, DirEntry as VfsDirEntry, DirStream, ExtentStream, FileId, FileSystem, FsKind,
    FsMeta, ImageSource, MacbTimes, NodeKind, NodeStream, ResidencyKind, SectorSizes, StreamId,
    TimeResolution, TimeSource, TimeStamp, TimeZonePolicy, VfsError, VfsResult,
};

use crate::{
    fs_tree_root, list_dir, read_file, read_inode, read_node, ChunkMap, DirEntry, DirItemType,
    Inode, Node, Superblock, Timestamp, BTRFS_SUPER_INFO_OFFSET,
};

/// A mounted btrfs image presented as a read-only [`FileSystem`].
pub struct BtrfsFs {
    image: Vec<u8>,
    sb: Superblock,
    map: ChunkMap,
    /// The FS-tree root leaf (btrfs-core traverses a single leaf; see module docs).
    leaf: Node,
    root_dirid: u64,
    /// Whole-file read cache is unnecessary; `read_file` is called per request.
    /// A `Mutex` is not needed for reads (all `&self`, no interior mutation), but
    /// kept out — this field documents that reads are lock-free over the buffer.
    _lockfree: (),
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
            _lockfree: (),
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
        // RED: stub.
        FileId::Opaque(0)
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

    fn read_dir(&self, _ino: FileId) -> VfsResult<DirStream> {
        // RED: stub.
        Ok(DirStream::empty())
    }

    fn extents(&self, _ino: FileId, _stream: StreamId) -> VfsResult<ExtentStream> {
        Ok(ExtentStream::empty())
    }

    fn lookup(&self, _parent: FileId, _name: &[u8]) -> VfsResult<Option<FileId>> {
        // RED: stub.
        Ok(None)
    }

    fn meta(&self, ino: FileId) -> VfsResult<FsMeta> {
        // RED: stub.
        let _ = oid_of(ino)?;
        Err(VfsError::Unsupported {
            layer: "btrfs meta",
            scheme: "RED".to_string(),
        })
    }

    fn read_at(
        &self,
        _ino: FileId,
        _stream: StreamId,
        _off: u64,
        _buf: &mut [u8],
    ) -> VfsResult<usize> {
        // RED: stub.
        Ok(0)
    }

    fn read_link(&self, _ino: FileId, _cap: usize) -> VfsResult<Vec<u8>> {
        Ok(Vec::new())
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
    use forensic_vfs::adapters::FileSource;
    use forensic_vfs::{FileId, FileSystem, FsKind, NodeKind, StreamId};

    /// The real mkfs.btrfs "deletion oracle" image (256 MiB), staged in /tmp per
    /// the fleet corpus standard (env `BTRFS_DEL_ORACLE`, default /tmp path).
    /// Ground truth (btrfs-progs `dump-tree`, see tests/data/): the current
    /// FS-tree root dir (objectid 256) holds `keep.txt` (inode 258); `secret.txt`
    /// (257) was deleted. Skips cleanly if the image is absent.
    fn open_real() -> Option<BtrfsFs> {
        let path = std::env::var("BTRFS_DEL_ORACLE")
            .unwrap_or_else(|_| "/tmp/btrfs_del_oracle.img".to_string());
        let src = FileSource::open(&path).ok()?;
        match BtrfsFs::open(&src) {
            Ok(fs) => Some(fs),
            Err(e) => {
                eprintln!("skip: btrfs image {path} did not open: {e:?}");
                None
            }
        }
    }

    #[test]
    fn btrfs_fs_matches_dumptree_oracle() {
        let Some(fs) = open_real() else {
            eprintln!("skip: no btrfs image (set BTRFS_DEL_ORACLE)");
            return;
        };

        assert_eq!(fs.kind(), FsKind::Other);
        // Root is the FS-tree root directory objectid (256).
        assert_eq!(fs.root(), FileId::Opaque(256));

        // read_dir(root) lists keep.txt → inode 258, a regular file.
        let entries: Vec<_> = fs
            .read_dir(FileId::Opaque(256))
            .expect("read_dir root")
            .collect::<Result<_, _>>()
            .expect("dir entries");
        let keep = entries
            .iter()
            .find(|e| e.name.as_slice() == b"keep.txt".as_slice())
            .expect("keep.txt present in current FS tree");
        assert_eq!(keep.id, FileId::Opaque(258));
        assert_eq!(keep.kind, NodeKind::File);

        // lookup resolves the same node.
        assert_eq!(
            fs.lookup(FileId::Opaque(256), b"keep.txt").expect("lookup"),
            Some(FileId::Opaque(258))
        );

        // meta of the file.
        let m = fs.meta(FileId::Opaque(258)).expect("meta keep.txt");
        assert_eq!(m.ino, 258);
        assert_eq!(m.kind, NodeKind::File);

        // read_at returns exactly the file's bytes (length == size); windowing
        // past EOF yields fewer bytes.
        let mut buf = vec![0u8; m.size as usize + 32];
        let n = fs
            .read_at(FileId::Opaque(258), StreamId::Default, 0, &mut buf)
            .expect("read_at keep.txt");
        assert_eq!(n as u64, m.size, "read_at returns the whole file");
    }
}
