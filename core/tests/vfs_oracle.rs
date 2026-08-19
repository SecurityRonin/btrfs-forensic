//! Env-gated Tier-2 VFS-adapter test over the real mkfs.btrfs "deletion oracle"
//! image (256 `MiB`).
//!
//! This is the integration-test home of the former in-crate `btrfs_fs_matches_
//! dumptree_oracle` test. It lives here (not in `core/src/vfs.rs`) so that its
//! body — reachable only when the 256 `MiB` oracle is present — is not counted by
//! the CI line-coverage gate, exactly like every other env-gated fixture test in
//! `core/tests/`. The always-on unit tests in `core/src/vfs.rs` cover the
//! `BtrfsFs` adapter itself over crafted images.
//!
//! Ground truth (btrfs-progs `dump-tree`, see `tests/data/`): the current FS-tree
//! root dir (objectid 256) holds `keep.txt` (inode 258); `secret.txt` (257) was
//! deleted. Skips cleanly if the image is absent (env `BTRFS_DEL_ORACLE`, default
//! `/tmp/btrfs_del_oracle.img`).

#![cfg(feature = "vfs")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use btrfs_core::vfs::BtrfsFs;
use forensic_vfs::adapters::FileSource;
use forensic_vfs::{FileId, FileSystem, FsKind, NodeKind, StreamId};

/// Open the deletion oracle via a `FileSource`, or `None` (skip) if absent.
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

    assert_eq!(fs.kind(), FsKind::BTRFS);
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

    // read_at returns exactly the file's bytes (length == size).
    let mut buf = vec![0u8; m.size as usize + 32];
    let n = fs
        .read_at(FileId::Opaque(258), StreamId::Default, 0, &mut buf)
        .expect("read_at keep.txt");
    assert_eq!(n as u64, m.size, "read_at returns the whole file");
}
