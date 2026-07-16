#![no_main]
//! EXTENT_DATA / `btrfs_file_extent_item` content assembly and the zlib / LZO /
//! zstd decompressors are the most attacker-exposed surface (compressed extent
//! bytes + a claimed `ram_bytes`). Neither `decompress_extent` (arbitrary algo /
//! ratio) nor `read_file_from_leaf` (over a fuzzed leaf) may panic, over-read,
//! or allocation-bomb.
use btrfs_core::Compression;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    // First byte selects the (untrusted) algorithm, next 8 the claimed ram_bytes;
    // the remainder is the compressed source. sectorsize is fixed at 4096 (the
    // btrfs default) — the guard math is what we exercise, not sizing.
    let algo = Compression::from_byte(data[0]);
    let ram_bytes = u64::from_le_bytes([
        data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
    ]);
    let src = &data[9..];
    let _ = btrfs_core::decompress_extent(algo, src, ram_bytes, 4096);

    // Drive the full leaf → file assembly path over the same bytes as a leaf.
    if let Ok(leaf) = btrfs_core::Node::parse(data) {
        let map = btrfs_core::ChunkMap::new();
        for ino in [0u64, 256, u64::MAX] {
            let _ = btrfs_core::read_file_from_leaf(&leaf, data, &map, 4096, ino);
        }
    }
});
