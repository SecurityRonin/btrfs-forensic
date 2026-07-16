#![no_main]
//! The crc32c superblock checksum verifier and the csum-type descriptor are
//! driven with an attacker-controlled block and covered_len — the verify math
//! and the status dispatch must never panic or read out of bounds.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // First two bytes select the (untrusted) csum-type code; the rest is the
    // block. covered_len is taken as the full block length (the real caller uses
    // the superblock's own layout constant, but any value must stay panic-free).
    let code = u16::from_le_bytes([data[0], data[1]]);
    let csum_type = btrfs_core::CsumType::from_code(code);
    let block = &data[2..];
    let _ = btrfs_core::superblock_crc_status(csum_type, block, block.len());
    let _ = btrfs_core::verify_superblock_crc32c(block, block.len());
});
