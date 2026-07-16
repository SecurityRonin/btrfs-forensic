#![no_main]
//! The `sys_chunk_array` bootstrap map (the item/key + chunk-stripe records that
//! seed logical→physical translation) is decoded from attacker-controlled
//! superblock bytes with an attacker-controlled length field. `parse_array` must
//! never panic and every per-chunk mapping lookup over the result must stay in
//! bounds.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    // Treat the first 4 bytes as the (untrusted) array_size, the rest as the
    // block — the exact shape `Superblock::parse` faces from the on-disk field.
    let array_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let block = &data[4..];
    let chunks = btrfs_core::SysChunk::parse_array(block, 0, array_size);
    // Probe every parsed chunk at a spread of logical addresses — the lookup
    // must never panic regardless of the (possibly garbage) stripe geometry.
    for chunk in &chunks {
        for logical in [0u64, 1 << 20, 1 << 40, u64::MAX] {
            std::hint::black_box(chunk.logical_to_physical(logical));
        }
    }
});
