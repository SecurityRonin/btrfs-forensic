#![no_main]
//! FS-tree semantics over a leaf: inode-item, directory-entry (`DIR_ITEM` /
//! `DIR_INDEX`), and slash-path resolution are all decoded from an
//! attacker-controlled leaf node. None may panic on malformed items.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(leaf) = btrfs_core::Node::parse(data) else {
        return;
    };
    // read_inode for a spread of objectids (incl. the FS_TREE root dir 256).
    for oid in [0u64, 256, u64::MAX] {
        std::hint::black_box(btrfs_core::read_inode(&leaf, oid));
        std::hint::black_box(btrfs_core::list_dir(&leaf, oid));
    }
    // Path resolution — arbitrary (including empty / multi-segment) paths.
    std::hint::black_box(btrfs_core::read_by_path(&leaf, ""));
    std::hint::black_box(btrfs_core::read_by_path(&leaf, "a/b/c"));
    std::hint::black_box(btrfs_core::read_by_path(&leaf, "/etc/hosts"));
});
