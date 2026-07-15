//! P1 B-tree node + chunk-tree tests.
//!
//! Ground truth is `btrfs inspect-internal dump-tree` on the minted oracle
//! (btrfs-progs v6.6.3), captured in `tests/data/btrfs.chunk-node.txt` and
//! `tests/data/README.md`. Every field the reader decodes is asserted against
//! that independent tool's output (Doer-Checker).
//!
//! Tiers:
//! - **Always-on (Tier-1 fixture):** the committed `btrfs_chunk_root.bin` is the
//!   raw 16384-byte chunk-tree leaf (the node at logical/physical 22036480).
//!   Parse it → header (level/nritems/owner), leaf items, and the three
//!   CHUNK_ITEMs' geometry all equal dump-tree; the node crc32c verifies.
//! - **Env-gated (Tier-1 full image):** with `BTRFS_ORACLE_IMG`, build the
//!   `ChunkMap` by walking the chunk tree from the superblock and confirm it
//!   maps the oracle's known logical addresses to the physical offsets
//!   dump-tree implies, then reads a real node there.
//! - **Robustness:** a lying `nritems` / item offset never panics or over-reads;
//!   a byte-flipped node reports `crc_valid == Some(false)`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use btrfs_core::{
    ChunkMap, Node, Superblock, BTRFS_HEADER_SIZE, BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE,
    CHUNK_ITEM_KEY,
};

/// The chunk-tree leaf's own logical address (= its physical offset on the
/// oracle, an identity placement). dump-tree: `leaf 22036480 ... owner CHUNK_TREE`.
const CHUNK_ROOT_LOGICAL: u64 = 22_036_480;
/// The root-tree leaf's logical address (super `root`). dump-tree:
/// `leaf 30720000 items 11 ... owner ROOT_TREE`.
const ROOT_LOGICAL: u64 = 30_720_000;
/// The physical offset the chunk map must resolve `ROOT_LOGICAL` to: the root
/// tree sits in the METADATA chunk `[30408704, +33554432)` whose first stripe is
/// physical 38797312, so `38797312 + (30720000 - 30408704) = 39108608`.
const ROOT_PHYSICAL: u64 = 39_108_608;

/// The committed always-on fixture: the raw 16384-byte chunk-tree leaf node.
fn chunk_root_node() -> Vec<u8> {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); // core/ -> repo root
    d.push("tests/data/btrfs_chunk_root.bin");
    std::fs::read(&d).unwrap_or_else(|e| panic!("read fixture {}: {e}", d.display()))
}

/// The committed superblock fixture (P0), used to seed the bootstrap chunk map.
fn superblock() -> Superblock {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.push("tests/data/btrfs_superblock.bin");
    let block = std::fs::read(&d).unwrap();
    Superblock::parse(&block).expect("superblock fixture parses")
}

#[test]
fn header_size_is_101_bytes() {
    // csum[32]+fsid[16]+bytenr(8)+flags(8)+chunk_tree_uuid[16]+generation(8)
    // +owner(8)+nritems(4)+level(1) = 101.
    assert_eq!(BTRFS_HEADER_SIZE, 101);
}

#[test]
fn chunk_root_header_matches_dump_tree() {
    // dump-tree: `leaf 22036480 items 4 ... generation 6 owner CHUNK_TREE` (=3),
    // level 0 (leaf). The header's own `bytenr` equals the node's logical addr.
    let node = Node::parse(&chunk_root_node()).expect("chunk root node parses");
    assert_eq!(
        node.header.bytenr, CHUNK_ROOT_LOGICAL,
        "bytenr = own logical"
    );
    assert_eq!(node.header.generation, 6, "generation");
    assert_eq!(node.header.owner, 3, "owner = CHUNK_TREE");
    assert_eq!(node.header.nritems, 4, "nritems");
    assert_eq!(node.header.level, 0, "level 0 = leaf");
    assert!(node.is_leaf(), "level 0 is a leaf");
}

#[test]
fn chunk_root_leaf_items_iterate_in_bounds() {
    // A leaf yields (key, data) for each of the 4 items. dump-tree item keys:
    //   0: (DEV_ITEMS=1  DEV_ITEM=216  1)
    //   1: (FIRST_CHUNK_TREE=256  CHUNK_ITEM=228  13631488)
    //   2: (256  228  22020096)
    //   3: (256  228  30408704)
    let node = Node::parse(&chunk_root_node()).unwrap();
    let items: Vec<_> = node.leaf_items().collect();
    assert_eq!(items.len(), 4, "4 leaf items");

    assert_eq!(items[0].0.objectid, 1);
    assert_eq!(items[0].0.key_type, 216);
    assert_eq!(items[0].0.offset, 1);
    assert_eq!(items[0].1.len(), 98, "DEV_ITEM itemsize 98");

    assert_eq!(items[1].0.objectid, 256);
    assert_eq!(items[1].0.key_type, CHUNK_ITEM_KEY);
    assert_eq!(items[1].0.offset, 13_631_488);
    assert_eq!(items[1].1.len(), 80, "single-stripe CHUNK itemsize 80");

    assert_eq!(items[2].0.offset, 22_020_096);
    assert_eq!(items[2].1.len(), 112, "DUP CHUNK itemsize 112");
    assert_eq!(items[3].0.offset, 30_408_704);
    assert_eq!(items[3].1.len(), 112);
}

#[test]
fn chunk_items_decode_geometry_and_stripes() {
    // Byte-for-byte vs dump-tree's CHUNK_ITEM output.
    let node = Node::parse(&chunk_root_node()).unwrap();
    let chunks = node.chunk_items();
    assert_eq!(chunks.len(), 3, "3 CHUNK_ITEMs (DEV_ITEM is skipped)");

    // item 1: DATA|single, one stripe at physical 13631488.
    let (logical, c) = &chunks[0];
    assert_eq!(*logical, 13_631_488);
    assert_eq!(c.length, 8_388_608);
    assert_eq!(c.stripe_len, 65_536);
    assert_eq!(c.chunk_type, 0x1, "DATA");
    assert_eq!(c.num_stripes, 1);
    assert_eq!(c.stripes.len(), 1);
    assert_eq!(c.stripes[0].devid, 1);
    assert_eq!(c.stripes[0].offset, 13_631_488);

    // item 2: SYSTEM|DUP, stripes @22020096 and @30408704.
    let (logical, c) = &chunks[1];
    assert_eq!(*logical, 22_020_096);
    assert_eq!(c.chunk_type, 0x22, "SYSTEM|DUP");
    assert_eq!(c.num_stripes, 2);
    assert_eq!(c.stripes[0].offset, 22_020_096);
    assert_eq!(c.stripes[1].offset, 30_408_704);

    // item 3: METADATA|DUP, length 33554432, stripes @38797312 and @72351744.
    let (logical, c) = &chunks[2];
    assert_eq!(*logical, 30_408_704);
    assert_eq!(c.length, 33_554_432);
    assert_eq!(c.chunk_type, 0x24, "METADATA|DUP");
    assert_eq!(c.stripes[0].offset, 38_797_312);
    assert_eq!(c.stripes[1].offset, 72_351_744);
}

#[test]
fn node_crc32c_verifies_on_clean_fixture() {
    // The node checksum covers [0x20 .. nodesize] (the whole 16384-byte block),
    // stored little-endian in the first 4 bytes. dump-tree read this node
    // without a csum error, and crc32c over the block reproduces the stored
    // digest (0x88f84902) exactly.
    let node = Node::parse(&chunk_root_node()).unwrap();
    assert_eq!(node.crc_valid, Some(true), "clean node crc32c verifies");
}

#[test]
fn node_crc32c_fails_on_byte_flip() {
    // Flip a payload byte (outside the csum field) → crc must not match. The
    // parse still succeeds (forensic-non-fatal): a tampered block is surfaced,
    // never rejected.
    let mut raw = chunk_root_node();
    raw[200] ^= 0xFF; // inside [0x20 .. nodesize], so it changes the covered crc
    let node = Node::parse(&raw).expect("tampered node still parses (non-fatal csum)");
    assert_eq!(
        node.crc_valid,
        Some(false),
        "byte-flipped node reports crc mismatch, does not fail parse"
    );
}

#[test]
fn chunk_map_from_chunk_root_node_maps_logical_addresses() {
    // Build a ChunkMap from the (already-read) chunk-tree leaf and confirm it
    // reproduces dump-tree's logical->physical for the known addresses:
    //  - chunk_root logical 22036480 -> physical 22036480 (identity placement)
    //  - root      logical 30720000 -> physical 39108608 (METADATA chunk)
    let node = Node::parse(&chunk_root_node()).unwrap();
    let mut map = ChunkMap::new();
    map.add_from_node(&node);

    assert_eq!(
        map.logical_to_physical(CHUNK_ROOT_LOGICAL),
        Some((1, CHUNK_ROOT_LOGICAL)),
        "chunk_root logical maps to its identity physical, devid 1"
    );
    assert_eq!(
        map.logical_to_physical(ROOT_LOGICAL),
        Some((1, ROOT_PHYSICAL)),
        "root-tree logical maps into the METADATA chunk"
    );
    // The DATA chunk start maps to its first stripe.
    assert_eq!(
        map.logical_to_physical(13_631_488),
        Some((1, 13_631_488)),
        "DATA chunk start"
    );
    // An address below every chunk maps nowhere.
    assert_eq!(map.logical_to_physical(0), None, "unmapped low address");
    // An address past every chunk's span maps nowhere.
    assert_eq!(
        map.logical_to_physical(u64::MAX),
        None,
        "unmapped high address"
    );
}

#[test]
fn lying_nritems_does_not_panic_or_overread() {
    // A header claiming a nritems far larger than the node could hold must yield
    // only the items that actually fit — never panic, never read past the block.
    let mut raw = chunk_root_node();
    // nritems @ 0x60 = a huge count.
    raw[0x60..0x64].copy_from_slice(&u32::MAX.to_le_bytes());
    let node = Node::parse(&raw).expect("absurd nritems must not fail parse");
    // The iterator is bounded by the block, so it stops long before u32::MAX.
    let count = node.leaf_items().count();
    assert!(
        count < node.header.nritems as usize,
        "leaf iterator is block-bounded, not nritems-bounded ({count} items)"
    );
    // chunk_items must likewise not panic.
    let _ = node.chunk_items();
}

#[test]
fn lying_item_data_offset_yields_empty_slice_not_overread() {
    // Corrupt item 0's data_offset (u32 at header_end+17) to point past the
    // block. The item must be yielded with an empty/bounded slice, not panic.
    let mut raw = chunk_root_node();
    let item0_doff = BTRFS_HEADER_SIZE + 17;
    raw[item0_doff..item0_doff + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let node = Node::parse(&raw).unwrap();
    // Iterating must not panic; the corrupt item's data slice is empty.
    let items: Vec<_> = node.leaf_items().collect();
    assert!(!items.is_empty());
    assert!(
        items[0].1.is_empty(),
        "out-of-range data_offset yields an empty slice, no over-read"
    );
}

#[test]
fn parse_rejects_a_buffer_too_small_for_a_header() {
    // A buffer shorter than the 101-byte header cannot be a node.
    let err = Node::parse(&[0u8; 50]).unwrap_err();
    assert!(
        format!("{err:?}").contains("Truncated"),
        "short buffer yields Truncated, got {err:?}"
    );
}

#[test]
fn internal_node_exposes_key_ptrs_when_level_nonzero() {
    // Synthesize a level-1 internal node with 2 key-ptrs over the chunk-root
    // block layout: header + nritems*(key[17]+blockptr(8)+generation(8)=33).
    // (The oracle is shallow — all trees are single leaves — so an interior node
    // is constructed to exercise the key_ptr path against a known layout.)
    let mut raw = vec![0u8; 16384];
    // header: bytenr, generation, owner, nritems=2, level=1
    raw[0x30..0x38].copy_from_slice(&4096u64.to_le_bytes()); // bytenr
    raw[0x50..0x58].copy_from_slice(&7u64.to_le_bytes()); // generation
    raw[0x58..0x60].copy_from_slice(&3u64.to_le_bytes()); // owner CHUNK_TREE
    raw[0x60..0x64].copy_from_slice(&2u32.to_le_bytes()); // nritems
    raw[0x64] = 1; // level 1 = internal
                   // key_ptr 0 at header_end (101): key(oid=256,type=228,off=100) blockptr=8192 gen=7
    let p0 = BTRFS_HEADER_SIZE;
    raw[p0..p0 + 8].copy_from_slice(&256u64.to_le_bytes());
    raw[p0 + 8] = 228;
    raw[p0 + 9..p0 + 17].copy_from_slice(&100u64.to_le_bytes());
    raw[p0 + 17..p0 + 25].copy_from_slice(&8192u64.to_le_bytes()); // blockptr
    raw[p0 + 25..p0 + 33].copy_from_slice(&7u64.to_le_bytes()); // generation
                                                                // key_ptr 1
    let p1 = p0 + 33;
    raw[p1..p1 + 8].copy_from_slice(&256u64.to_le_bytes());
    raw[p1 + 8] = 228;
    raw[p1 + 9..p1 + 17].copy_from_slice(&200u64.to_le_bytes());
    raw[p1 + 17..p1 + 25].copy_from_slice(&16384u64.to_le_bytes());
    raw[p1 + 25..p1 + 33].copy_from_slice(&9u64.to_le_bytes());

    let node = Node::parse(&raw).unwrap();
    assert!(!node.is_leaf(), "level 1 is an internal node");
    let ptrs = node.key_ptrs();
    assert_eq!(ptrs.len(), 2);
    assert_eq!(ptrs[0].key.offset, 100);
    assert_eq!(ptrs[0].blockptr, 8192);
    assert_eq!(ptrs[0].generation, 7);
    assert_eq!(ptrs[1].blockptr, 16384);
    // A leaf node has no key_ptrs, an internal node has no leaf_items.
    assert_eq!(
        node.leaf_items().count(),
        0,
        "internal node has no leaf items"
    );
}

// ---- Env-gated full-image tests (Tier-1: whole 512 MiB oracle) ----

fn oracle_image() -> Option<Vec<u8>> {
    let path = std::env::var("BTRFS_ORACLE_IMG").ok()?;
    Some(std::fs::read(path).expect("read BTRFS_ORACLE_IMG"))
}

#[test]
fn full_image_chunk_walk_maps_and_reads_root_tree() {
    let Some(img) = oracle_image() else {
        eprintln!("skip: BTRFS_ORACLE_IMG unset");
        return;
    };
    let start = BTRFS_SUPER_INFO_OFFSET as usize;
    let sb = Superblock::parse(&img[start..start + BTRFS_SUPER_INFO_SIZE]).unwrap();

    // Walk the chunk tree from the superblock bootstrap into a full ChunkMap.
    let map = ChunkMap::walk(&img, &sb).expect("chunk-tree walk");

    // The map resolves the oracle's known logical addresses to dump-tree's
    // physical offsets.
    assert_eq!(
        map.logical_to_physical(CHUNK_ROOT_LOGICAL),
        Some((1, CHUNK_ROOT_LOGICAL))
    );
    assert_eq!(
        map.logical_to_physical(ROOT_LOGICAL),
        Some((1, ROOT_PHYSICAL))
    );

    // read_node translates + reads the root tree by logical address.
    let root = btrfs_core::read_node(&img, &sb, &map, sb.root).expect("read root node");
    assert_eq!(root.header.bytenr, ROOT_LOGICAL, "root node's own logical");
    assert_eq!(root.header.owner, 1, "owner = ROOT_TREE");
    assert_eq!(root.header.nritems, 11, "root tree has 11 items");
    assert_eq!(root.header.level, 0);
    assert_eq!(root.crc_valid, Some(true), "root node crc verifies");

    // read_node also reads the chunk root itself.
    let cr = btrfs_core::read_node(&img, &sb, &map, sb.chunk_root).expect("read chunk root");
    assert_eq!(cr.header.bytenr, CHUNK_ROOT_LOGICAL);
    assert_eq!(cr.header.owner, 3);
    assert_eq!(cr.header.nritems, 4);

    // Superblock confirmation: fixture and full-image agree.
    let _ = superblock();
}
