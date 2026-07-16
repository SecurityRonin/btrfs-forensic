#![no_main]
//! A B-tree node block (`btrfs_header` + leaf items or interior key-pointers) is
//! read straight from the image at an attacker-controlled logical address —
//! `Node::parse` and every item/key-pointer accessor over it must never panic.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(node) = btrfs_core::Node::parse(data) {
        // Drive every structural accessor: leaf item (key + slice) iteration,
        // interior key-pointers, and the chunk-item decode (chunk/node stripes).
        for (_key, item) in node.leaf_items() {
            std::hint::black_box(item);
        }
        std::hint::black_box(node.key_ptrs());
        std::hint::black_box(node.chunk_items());
        std::hint::black_box(node.is_leaf());
    }
});
