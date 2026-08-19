//! P0 superblock tests.
//!
//! Two tiers:
//! - **Always-on (Tier-1 fixture):** parse the committed 4096-byte superblock
//!   fixture (`tests/data/btrfs_superblock.bin`, the block at physical offset
//!   0x10000 of the minted oracle) and assert every field equals the
//!   `btrfs inspect-internal dump-super -f` ground truth captured in
//!   `tests/data/README.md`.
//! - **Env-gated (Tier-1 full image):** when `BTRFS_ORACLE_IMG` points at the
//!   512 `MiB` oracle image, read its superblock at offset 65536 and assert the
//!   same values — proving the offset within a whole image.
//! - **Unit (robustness):** bad-magic fails loud with the offending bytes; a
//!   truncated buffer returns `Truncated`, never panics.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use btrfs_core::{
    BtrfsError, CsumType, Superblock, BTRFS_MAGIC, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE,
    CHUNK_ITEM_KEY,
};

/// The committed always-on fixture: the 4096-byte superblock block.
fn fixture() -> Vec<u8> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // core/ -> repo root
    d.push("tests/data/btrfs_superblock.bin");
    std::fs::read(&d).unwrap_or_else(|e| panic!("read fixture {}: {e}", d.display()))
}

/// Assert every geometry / root / checksum field equals the `dump-super -f`
/// ground truth (README). Shared by the fixture and the full-image tests.
fn assert_oracle_fields(sb: &Superblock) {
    assert_eq!(sb.magic, BTRFS_MAGIC, "magic");
    // csum 0xd9136f60 stored little-endian as bytes d9 13 6f 60 (dump-super shows
    // the raw on-disk byte order).
    assert_eq!(sb.csum, [0xd9, 0x13, 0x6f, 0x60], "csum bytes");
    assert_eq!(
        sb.fsid_string(),
        "fe9599cb-e209-4d5c-b734-642c457fbc01",
        "fsid"
    );
    assert_eq!(sb.bytenr, 65536, "bytenr");
    assert_eq!(sb.flags, 0x1, "flags");
    assert_eq!(sb.generation, 9, "generation");
    assert_eq!(sb.root, 30_720_000, "root logical addr");
    assert_eq!(sb.chunk_root, 22_036_480, "chunk_root logical addr");
    assert_eq!(sb.log_root, 0, "log_root");
    assert_eq!(sb.total_bytes, 536_870_912, "total_bytes");
    assert_eq!(sb.bytes_used, 212_992, "bytes_used");
    assert_eq!(sb.root_dir_objectid, 6, "root_dir_objectid");
    assert_eq!(sb.num_devices, 1, "num_devices");
    assert_eq!(sb.sectorsize, 4096, "sectorsize");
    assert_eq!(sb.nodesize, 16384, "nodesize");
    assert_eq!(sb.stripesize, 4096, "stripesize");
    assert_eq!(sb.sys_chunk_array_size, 129, "sys_chunk_array_size");
    assert_eq!(sb.chunk_root_generation, 6, "chunk_root_generation");
    assert_eq!(sb.compat_flags, 0x0, "compat_flags");
    assert_eq!(sb.compat_ro_flags, 0x3, "compat_ro_flags");
    assert_eq!(sb.incompat_flags, 0x361, "incompat_flags");
    assert_eq!(sb.csum_type, CsumType::Crc32c, "csum_type");
    assert_eq!(sb.root_level, 0, "root_level");
    assert_eq!(sb.chunk_root_level, 0, "chunk_root_level");
    assert_eq!(sb.log_root_level, 0, "log_root_level");
    assert_eq!(sb.label, "BTRFS_ORACLE", "label");

    // sys_chunk_array: exactly one SYSTEM|DUP entry (dump-super), key
    // (FIRST_CHUNK_TREE=256, CHUNK_ITEM=228, logical 22020096), 2 stripes.
    assert_eq!(sb.sys_chunks.len(), 1, "sys_chunk entry count");
    let c = &sb.sys_chunks[0];
    assert_eq!(
        c.key.objectid, 256,
        "sys chunk key objectid (FIRST_CHUNK_TREE)"
    );
    assert_eq!(
        c.key.key_type, CHUNK_ITEM_KEY,
        "sys chunk key type (CHUNK_ITEM)"
    );
    assert_eq!(c.key.offset, 22_020_096, "sys chunk key offset (logical)");
    assert_eq!(c.length, 8_388_608, "sys chunk length");
    assert_eq!(c.owner, 2, "sys chunk owner");
    assert_eq!(c.chunk_type, 0x22, "sys chunk type (SYSTEM|DUP)");
    assert_eq!(c.num_stripes, 2, "sys chunk num_stripes");
    assert_eq!(c.sub_stripes, 1, "sys chunk sub_stripes");
    assert_eq!(c.stripes.len(), 2, "decoded stripes");
    assert_eq!(c.stripes[0].devid, 1, "stripe0 devid");
    assert_eq!(c.stripes[0].offset, 22_020_096, "stripe0 physical offset");
    assert_eq!(c.stripes[1].devid, 1, "stripe1 devid");
    assert_eq!(c.stripes[1].offset, 30_408_704, "stripe1 physical offset");

    // Bootstrap logical→physical: a logical address inside the SYSTEM chunk maps
    // to stripe[0].offset + (logical - chunk_key.offset).
    assert_eq!(
        c.logical_to_physical(22_020_096),
        Some(22_020_096),
        "logical start maps to stripe0 start"
    );
    assert_eq!(
        c.logical_to_physical(22_036_480),
        Some(22_036_480),
        "chunk_root logical maps within the SYSTEM chunk"
    );
    assert_eq!(
        c.logical_to_physical(9_999_999),
        None,
        "an address outside the chunk span does not map"
    );

    // crc32c verified over [0x20 .. sectorsize] — dump-super reported [match].
    assert_eq!(
        sb.crc_valid,
        Some(true),
        "crc32c verifies (dump-super: match)"
    );
}

#[test]
fn fixture_superblock_matches_oracle() {
    let sb = Superblock::parse(&fixture()).expect("fixture superblock parses");
    assert_oracle_fields(&sb);
}

#[test]
fn full_image_superblock_matches_oracle() {
    let Ok(path) = std::env::var("BTRFS_ORACLE_IMG") else {
        eprintln!("skip: BTRFS_ORACLE_IMG unset (512 MiB oracle image not present)");
        return;
    };
    let img = std::fs::read(&path).expect("read BTRFS_ORACLE_IMG");
    let start = BTRFS_SUPER_INFO_OFFSET as usize;
    let block = &img[start..start + BTRFS_SUPER_INFO_SIZE];
    let sb = Superblock::parse(block).expect("full-image superblock parses at 0x10000");
    assert_oracle_fields(&sb);
}

#[test]
fn bad_magic_fails_loud_with_offending_bytes() {
    // A 4096-byte buffer whose bytes at 0x40 are NOT "_BHRfS_M".
    let mut data = vec![0u8; BTRFS_SUPER_INFO_SIZE];
    data[0x40..0x48].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]);

    let err = Superblock::parse(&data).unwrap_err();
    match err {
        BtrfsError::BadMagic { bytes } => {
            assert_eq!(bytes, [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]);
        }
        other => panic!("expected BadMagic, got {other:?}"),
    }
}

#[test]
fn truncated_buffer_does_not_panic() {
    // Valid magic at 0x40 but far too short to hold the whole superblock scalars.
    let mut data = vec![0u8; 0x50];
    data[0x40..0x48].copy_from_slice(&BTRFS_MAGIC);

    let err = Superblock::parse(&data).unwrap_err();
    assert!(
        matches!(err, BtrfsError::Truncated { .. }),
        "short buffer must yield Truncated, got {err:?}"
    );
}

#[test]
fn empty_buffer_does_not_panic() {
    // An empty buffer reads magic as all-zero (out of range), so identity
    // validation rejects it as BadMagic before any length check.
    let err = Superblock::parse(&[]).unwrap_err();
    match err {
        BtrfsError::BadMagic { bytes } => assert_eq!(bytes, [0u8; 8]),
        other => panic!("expected BadMagic for empty buffer, got {other:?}"),
    }
}
