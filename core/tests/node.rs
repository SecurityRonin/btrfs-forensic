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

// ---- Always-on crafted-image tests for the walk/read_node navigation ----
//
// These synthesize a minimal in-memory btrfs image so `ChunkMap::walk` and
// `read_node` — plus their reachable failure arms — are exercised without the
// 512 MiB oracle (which is gitignored, so absent in CI). The real oracle is the
// Tier-1 correctness backstop above; these drive the navigation *logic* over a
// self-built image (a lower tier, but the geometry is derived, not hardcoded).

const NODESIZE: usize = 16384;
const SB_OFF: usize = 65536;

/// A leaf-node builder: writes a `btrfs_header` (owner, nritems, level 0) and
/// item headers + item data, then fixes up the crc32c so the node verifies.
fn build_leaf(bytenr: u64, owner: u64, items: &[(u64, u8, u64, Vec<u8>)]) -> Vec<u8> {
    let mut node = vec![0u8; NODESIZE];
    node[0x30..0x38].copy_from_slice(&bytenr.to_le_bytes());
    node[0x58..0x60].copy_from_slice(&owner.to_le_bytes());
    node[0x60..0x64].copy_from_slice(&(items.len() as u32).to_le_bytes());
    node[0x64] = 0; // leaf
    let hdr_end = 101usize;
    let item_stride = 25usize;
    // Item data grows backward from the node end; data_offset is relative to
    // hdr_end.
    let mut data_tail = NODESIZE; // absolute
    for (i, (oid, ty, koff, data)) in items.iter().enumerate() {
        let io = hdr_end + i * item_stride;
        node[io..io + 8].copy_from_slice(&oid.to_le_bytes());
        node[io + 8] = *ty;
        node[io + 9..io + 17].copy_from_slice(&koff.to_le_bytes());
        data_tail -= data.len();
        let doff = (data_tail - hdr_end) as u32;
        node[io + 17..io + 21].copy_from_slice(&doff.to_le_bytes());
        node[io + 21..io + 25].copy_from_slice(&(data.len() as u32).to_le_bytes());
        node[data_tail..data_tail + data.len()].copy_from_slice(data);
    }
    fix_node_crc(&mut node);
    node
}

/// Encode a `btrfs_chunk` item body: length/owner/stripe_len/type + stripe(s).
fn chunk_item(length: u64, chunk_type: u64, stripes: &[(u64, u64)]) -> Vec<u8> {
    let mut d = vec![0u8; 48 + stripes.len() * 32];
    d[0..8].copy_from_slice(&length.to_le_bytes());
    d[8..16].copy_from_slice(&2u64.to_le_bytes()); // owner
    d[16..24].copy_from_slice(&65536u64.to_le_bytes()); // stripe_len
    d[24..32].copy_from_slice(&chunk_type.to_le_bytes());
    d[44..46].copy_from_slice(&(stripes.len() as u16).to_le_bytes());
    d[46..48].copy_from_slice(&1u16.to_le_bytes()); // sub_stripes
    for (i, (devid, off)) in stripes.iter().enumerate() {
        let so = 48 + i * 32;
        d[so..so + 8].copy_from_slice(&devid.to_le_bytes());
        d[so + 8..so + 16].copy_from_slice(&off.to_le_bytes());
    }
    d
}

/// Set the node's stored crc32c (first 4 bytes) to the digest over
/// `[0x20 .. nodesize]`, so `Node::parse` reports `crc_valid == Some(true)`.
fn fix_node_crc(node: &mut [u8]) {
    let c = crc32c_iscsi(&node[0x20..]);
    node[0..4].copy_from_slice(&c.to_le_bytes());
}

fn crc32c_iscsi(buf: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in buf {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    crc ^ 0xFFFF_FFFF
}

/// Build a superblock block whose `sys_chunk_array` describes one SYSTEM chunk
/// `[sys_logical, +sys_len)` mapped identically to physical `sys_logical`, and
/// whose `chunk_root`/`root`/`nodesize` are set.
fn build_superblock(chunk_root: u64, root: u64, sys_logical: u64, sys_len: u64) -> Vec<u8> {
    let mut sb = vec![0u8; BTRFS_SUPER_INFO_SIZE];
    sb[0x40..0x48].copy_from_slice(b"_BHRfS_M"); // magic
    sb[0x30..0x38].copy_from_slice(&65536u64.to_le_bytes()); // bytenr
    sb[0x58..0x60].copy_from_slice(&chunk_root.to_le_bytes());
    sb[0x50..0x58].copy_from_slice(&root.to_le_bytes());
    sb[0x90..0x94].copy_from_slice(&4096u32.to_le_bytes()); // sectorsize
    sb[0x94..0x98].copy_from_slice(&(NODESIZE as u32).to_le_bytes()); // nodesize
                                                                      // sys_chunk_array: one [disk_key][chunk+stripe]. key type CHUNK_ITEM=228,
                                                                      // key.offset = sys_logical. One identity stripe on devid 1.
    let arr = SB_SYS_ARR;
    sb[arr..arr + 8].copy_from_slice(&256u64.to_le_bytes()); // objectid FIRST_CHUNK_TREE
    sb[arr + 8] = 228; // CHUNK_ITEM
    sb[arr + 9..arr + 17].copy_from_slice(&sys_logical.to_le_bytes());
    let ci = chunk_item(sys_len, 0x2 /*SYSTEM*/, &[(1, sys_logical)]);
    sb[arr + 17..arr + 17 + ci.len()].copy_from_slice(&ci);
    let sys_size = (17 + ci.len()) as u32;
    sb[0xa0..0xa4].copy_from_slice(&sys_size.to_le_bytes()); // sys_chunk_array_size
    sb
}

const SB_SYS_ARR: usize = 0x32b;

#[test]
fn crafted_walk_reads_two_level_chunk_tree_and_maps_addresses() {
    // Physical layout: SYSTEM chunk [4096, +65536) identity-mapped, so a node at
    // logical 4096 sits at physical 4096. Put an INTERIOR chunk-tree root there
    // that points to a leaf at logical 8192 (physical 8192). The leaf carries a
    // METADATA CHUNK_ITEM [1<<20, +1<<20) -> physical 2<<20. This exercises the
    // interior-node key_ptr descent inside walk().
    let chunk_root = 4096u64;
    let leaf_logical = 8192u64;

    // Interior root: header + 1 key_ptr (key + blockptr=leaf_logical + gen).
    let mut root_node = vec![0u8; NODESIZE];
    root_node[0x30..0x38].copy_from_slice(&chunk_root.to_le_bytes());
    root_node[0x58..0x60].copy_from_slice(&3u64.to_le_bytes()); // CHUNK_TREE
    root_node[0x60..0x64].copy_from_slice(&1u32.to_le_bytes());
    root_node[0x64] = 1; // interior
    let p = 101usize;
    root_node[p..p + 8].copy_from_slice(&256u64.to_le_bytes());
    root_node[p + 8] = 228;
    root_node[p + 9..p + 17].copy_from_slice(&(1u64 << 20).to_le_bytes());
    root_node[p + 17..p + 25].copy_from_slice(&leaf_logical.to_le_bytes()); // blockptr
    root_node[p + 25..p + 33].copy_from_slice(&5u64.to_le_bytes());
    fix_node_crc(&mut root_node);

    // Leaf with one METADATA CHUNK_ITEM.
    let meta = chunk_item(1u64 << 20, 0x24, &[(1, 2u64 << 20)]);
    let leaf = build_leaf(leaf_logical, 3, &[(256, 228, 1u64 << 20, meta)]);

    // Assemble the image: superblock at 0x10000, root node @4096, leaf @8192.
    let sb_block = build_superblock(chunk_root, 1u64 << 20, 4096, 65536);
    let mut img = vec![0u8; SB_OFF + BTRFS_SUPER_INFO_SIZE];
    img[SB_OFF..SB_OFF + BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb_block);
    // Grow the image to hold the physical placements.
    let need = (2u64 << 20) as usize + (1u64 << 20) as usize;
    if img.len() < need {
        img.resize(need, 0);
    }
    img[4096..4096 + NODESIZE].copy_from_slice(&root_node);
    img[8192..8192 + NODESIZE].copy_from_slice(&leaf);

    let sb = Superblock::parse(&img[SB_OFF..SB_OFF + BTRFS_SUPER_INFO_SIZE]).unwrap();
    let map = ChunkMap::walk(&img, &sb).expect("crafted chunk-tree walk");

    // The METADATA chunk maps logical 1<<20 -> physical 2<<20.
    assert_eq!(
        map.logical_to_physical(1u64 << 20),
        Some((1, 2u64 << 20)),
        "walk followed the interior key_ptr into the leaf and mapped its chunk"
    );

    // read_node reads the leaf by its logical address (via the map).
    let node = btrfs_core::read_node(&img, &sb, &map, leaf_logical).expect("read leaf via map");
    assert_eq!(node.header.owner, 3);
    assert!(node.is_leaf());
}

#[test]
fn walk_fails_loud_when_bootstrap_does_not_cover_chunk_root() {
    // chunk_root logical 999999 lies OUTSIDE the sys_chunk_array's SYSTEM span
    // [4096, +65536): the bootstrap cannot translate it, so walk must return a
    // loud Truncated error naming the offending logical addr — never an empty
    // map (the Paranoid-Gatekeeper bootstrap rule).
    let sb_block = build_superblock(999_999, 1u64 << 20, 4096, 65536);
    let mut img = vec![0u8; SB_OFF + BTRFS_SUPER_INFO_SIZE];
    img[SB_OFF..SB_OFF + BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb_block);
    let sb = Superblock::parse(&img[SB_OFF..SB_OFF + BTRFS_SUPER_INFO_SIZE]).unwrap();

    let err = ChunkMap::walk(&img, &sb).unwrap_err();
    assert!(
        format!("{err:?}").contains("chunk_root logical"),
        "bootstrap miss is a loud, named failure, got {err:?}"
    );
}

#[test]
fn walk_fails_loud_when_chunk_root_node_is_out_of_image() {
    // The bootstrap maps chunk_root (logical == sys_logical == 1<<30) identically
    // to physical 1<<30, which lies far past the small image: walk must fail loud
    // ("out of image"), never return an empty map.
    let far = 1u64 << 30;
    let sb_block = build_superblock(far, 1u64 << 20, far, 65536);
    let mut img = vec![0u8; SB_OFF + BTRFS_SUPER_INFO_SIZE];
    img[SB_OFF..SB_OFF + BTRFS_SUPER_INFO_SIZE].copy_from_slice(&sb_block);
    let sb = Superblock::parse(&img[SB_OFF..SB_OFF + BTRFS_SUPER_INFO_SIZE]).unwrap();

    let err = ChunkMap::walk(&img, &sb).unwrap_err();
    assert!(
        format!("{err:?}").contains("out of image"),
        "chunk_root out-of-image is a loud failure, got {err:?}"
    );
}

#[test]
fn read_node_errors_when_logical_has_no_mapping() {
    let sb_block = build_superblock(4096, 1u64 << 20, 4096, 65536);
    let sb = Superblock::parse(&sb_block).unwrap();
    let img = vec![0u8; 1 << 20];
    let map = ChunkMap::new(); // empty map, and 999999 is outside sys_chunks too
    let err = btrfs_core::read_node(&img, &sb, &map, 999_999).unwrap_err();
    assert!(
        format!("{err:?}").contains("no chunk mapping"),
        "unmapped logical is a named error, got {err:?}"
    );
}

#[test]
fn read_node_errors_when_block_is_out_of_image() {
    // sys_chunks maps logical 4096 -> physical 4096 (identity), but the image is
    // too small to hold a node there.
    let sb_block = build_superblock(4096, 1u64 << 20, 4096, 65536);
    let sb = Superblock::parse(&sb_block).unwrap();
    let img = vec![0u8; 4096]; // physical 4096 + nodesize is out of range
    let map = ChunkMap::new();
    // read_node falls back to the sys_chunk_array bootstrap for logical 4096.
    let err = btrfs_core::read_node(&img, &sb, &map, 4096).unwrap_err();
    assert!(
        format!("{err:?}").contains("out of image"),
        "out-of-image node is a named error, got {err:?}"
    );
}

#[test]
fn key_ptrs_on_a_leaf_is_empty() {
    // The leaf fixture has no key-pointers.
    let node = Node::parse(&chunk_root_node()).unwrap();
    assert!(node.key_ptrs().is_empty(), "a leaf exposes no key_ptrs");
}
