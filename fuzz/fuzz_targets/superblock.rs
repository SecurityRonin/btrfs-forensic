#![no_main]
//! The superblock block is fully attacker-controlled — parse must never panic,
//! and neither must the crc32c descriptor / status helpers driven from it.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(sb) = btrfs_core::Superblock::parse(data) {
        // The parsed csum descriptor feeds the crc status helper — exercise it
        // over the arbitrary block too (must not panic on any covered_len).
        let _ = btrfs_core::superblock_crc_status(sb.csum_type, data, data.len());
    }
});
