# btrfs Forensic Test Data — Provenance

**REAL-self Tier-1**: minted on a controlled Linux VM with `mkfs.btrfs`
(btrfs-progs) and cross-checked against the independent `btrfs inspect-internal`
oracle (a different implementation from this reader). See the fleet catalog at
[`issen/docs/corpus-catalog.md`](../../../issen/docs/corpus-catalog.md) for the
machine index; this README is the co-located human detail.

The 512 MiB oracle image (`btrfs.img`) is **gitignored** (`.gitignore` →
`/tests/data/*.img`). Only the extracted **4096-byte superblock fixture**
(`btrfs_superblock.bin`, the block at physical offset 0x10000) and the oracle
**text outputs** are committed. Re-mint the image from the verbatim commands
below to reproduce the full corpus.

## Minting host

- Parallels VM `Ubuntu 24.04 (with Rosetta)`, `Linux 6.8.0-86-generic aarch64`.
- `btrfs-progs v6.6.3` (`mkfs.btrfs` / `btrfs inspect-internal`).
- Host `/tmp` shared read-write into the VM at `/media/psf/tmp`.

## Verbatim mint + populate commands

```bash
rm -rf /tmp/btrfs && mkdir -p /tmp/btrfs && cd /tmp/btrfs
dd if=/dev/zero of=btrfs.img bs=1M count=512 status=none
mkfs.btrfs -f -L BTRFS_ORACLE --csum crc32c btrfs.img

sudo mkdir -p /mnt/btrfs-oracle
sudo mount -o loop btrfs.img /mnt/btrfs-oracle
echo "hello inline btrfs oracle" | sudo tee /mnt/btrfs-oracle/small.txt >/dev/null
sudo bash -c "yes ABCDEFGH | head -c 65536 > /mnt/btrfs-oracle/mid.bin"
sudo mkdir -p /mnt/btrfs-oracle/dir/sub
echo "nested leaf content" | sudo tee /mnt/btrfs-oracle/dir/sub/leaf.txt >/dev/null
sync
sudo find /mnt/btrfs-oracle -type f -exec sha256sum {} \; > btrfs.content.sha256   # content Tier-1
sudo umount /mnt/btrfs-oracle

# Extract the committed always-on fixture: the 4096-byte block at 0x10000.
dd if=btrfs.img bs=1 skip=65536 count=4096 of=btrfs_superblock.bin status=none

# Independent structural oracle (btrfs-progs, a different impl from our reader).
btrfs inspect-internal dump-super -f btrfs.img          > btrfs.dump-super.txt
btrfs filesystem show                btrfs.img          > btrfs.fs-show.txt
btrfs inspect-internal dump-tree -b 22036480 btrfs.img  > btrfs.chunk-tree.txt   # P1 chunk tree
btrfs inspect-internal dump-tree -b 22036480 btrfs.img  > btrfs.chunk-node.txt   # P1 node (same tree)

# Extract the P1 always-on fixture: the raw 16384-byte chunk-tree LEAF node.
# The chunk_root logical addr 22036480 maps (via the sys_chunk_array bootstrap)
# to the identical physical offset 22036480 on this oracle, so skip= that value.
dd if=btrfs.img bs=1 skip=22036480 count=16384 of=btrfs_chunk_root.bin status=none

# --- P2 oracle: full tree dump + FS_TREE leaf fixture ---
# The FULL tree dump (ROOT_TREE + FS_TREE + every other tree) is the P2 ground
# truth for root-item / inode / dir-item offsets.
btrfs inspect-internal dump-tree btrfs.img > btrfs.full-tree.txt

# Extract the P2 always-on fixture: the raw 16384-byte FS_TREE LEAF node.
# The FS_TREE root's logical addr 30654464 sits in the METADATA chunk
# [30408704, +33554432) whose first stripe is physical 38797312, so
# physical = 38797312 + (30654464 - 30408704) = 39043072.
dd if=btrfs.img bs=1 skip=39043072 count=16384 of=btrfs_fs_tree_leaf.bin status=none

# Independent Tier-1 content/metadata oracle (kernel driver, a different impl):
# mount read-only and capture ls -i (name->inode) + stat (size/mode/mtime).
sudo mount -o loop,ro btrfs.img /mnt/btrfs-oracle
( cd /mnt/btrfs-oracle && ls -i -R . )
for f in small.txt mid.bin dir dir/sub dir/sub/leaf.txt; do
  stat -c "ino=%i size=%s mode=%a type=%F mtime=%Y mtime_ns=%y" "/mnt/btrfs-oracle/$f"
done
sudo umount /mnt/btrfs-oracle
```

## Ground truth (from `btrfs inspect-internal dump-super -f`)

The committed `btrfs.dump-super.txt` is the verbatim capture. Key P0 field
values the always-on test asserts:

| field | value |
|---|---|
| `magic` | `_BHRfS_M` (bytes `5f 42 48 52 66 53 5f 4d` at superblock offset 0x40) |
| `csum_type` | `0 (crc32c)` |
| `csum` | `0xd9136f60` `[match]` (stored LE bytes `d9 13 6f 60`) |
| `bytenr` | `65536` |
| `fsid` | `fe9599cb-e209-4d5c-b734-642c457fbc01` |
| `label` | `BTRFS_ORACLE` |
| `generation` | `9` |
| `root` (logical) | `30720000` |
| `chunk_root` (logical) | `22036480` |
| `log_root` | `0` |
| `root_level` / `chunk_root_level` / `log_root_level` | `0 / 0 / 0` |
| `total_bytes` | `536870912` |
| `bytes_used` | `212992` |
| `root_dir_objectid` | `6` |
| `num_devices` | `1` |
| `sectorsize` | `4096` |
| `nodesize` | `16384` |
| `stripesize` | `4096` |
| `sys_array_size` | `129` |
| `chunk_root_generation` | `6` |
| `compat_ro_flags` | `0x3` (FREE_SPACE_TREE \| FREE_SPACE_TREE_VALID) |
| `incompat_flags` | `0x361` (MIXED_BACKREF \| BIG_METADATA \| EXTENDED_IREF \| SKINNY_METADATA \| NO_HOLES) |

`sys_chunk_array` (exactly **one** entry, consuming all 129 bytes):

```
item 0 key (FIRST_CHUNK_TREE=256  CHUNK_ITEM=228  logical 22020096)
    length 8388608  owner 2  stripe_len 65536  type SYSTEM|DUP (0x22)
    num_stripes 2  sub_stripes 1
        stripe 0  devid 1  offset 22020096
        stripe 1  devid 1  offset 30408704
```

Bootstrap logical→physical (single-device DUP, first mirror):
`physical = stripe[0].offset + (logical - key.offset)`, so `chunk_root`
logical `22036480` → physical `22036480` (this chunk is placed at an identity
offset on the oracle; the test also checks an out-of-span address maps to
`None`).

## P1 ground truth (from `btrfs inspect-internal dump-tree -b 22036480`)

The chunk tree is a single **leaf** at bytenr 22036480 (level 0), 4 items,
generation 6, owner `CHUNK_TREE` (3). Values the P1 always-on test asserts (all
verified byte-for-byte against the raw fixture AND dump-tree — the on-disk
`btrfs_header`/`btrfs_item`/`btrfs_key_ptr`/`btrfs_chunk`/`btrfs_stripe` offsets
in the task brief were confirmed correct, no shift):

| header field | offset | value |
|---|---|---|
| `csum` (crc32c, LE) | `0x00` | `0x88f84902` `[match]` (bytes `02 49 f8 88`) |
| `fsid` | `0x20` | `fe9599cb-…` (= superblock fsid) |
| `bytenr` (own logical) | `0x30` | `22036480` |
| `flags` | `0x38` | `0x100000000000001` (WRITTEN + backref-rev-1 bit) |
| `chunk_tree_uuid` | `0x40` | `05ec8046-…` |
| `generation` | `0x50` | `6` |
| `owner` (tree id) | `0x58` | `3` (CHUNK_TREE) |
| `nritems` | `0x60` | `4` |
| `level` | `0x64` | `0` (leaf) → **header size = 0x65 = 101 bytes** |

Leaf items start at `header_end` (101); each `btrfs_item` = `disk_key[17] +
data_offset(u32) + data_size(u32)` = 25 bytes; item **data** lives at
`header_end + data_offset` (dump-tree's `itemoff`):

| item | key (oid, type, offset) | data_offset | data_size | decoded |
|---|---|---|---|---|
| 0 | (1 DEV_ITEM=216 1) | 16185 | 98 | DEV_ITEM (skipped by chunk walk) |
| 1 | (256 CHUNK_ITEM=228 13631488) | 16105 | 80 | DATA\|single, 1 stripe @13631488 |
| 2 | (256 228 22020096) | 15993 | 112 | SYSTEM\|DUP (0x22), stripes @22020096,@30408704 |
| 3 | (256 228 30408704) | 15881 | 112 | METADATA\|DUP (0x24), len 33554432, stripes @38797312,@72351744 |

`btrfs_chunk` (data of a CHUNK_ITEM) = `length,owner,stripe_len,type` (4×u64) +
`io_align,io_width,sector_size` (3×u32) + `num_stripes,sub_stripes` (2×u16) = 48
bytes, then `num_stripes × btrfs_stripe {devid(u64), offset(u64=physical),
dev_uuid[16]}` = 32 bytes each. **Node crc32c covers `[0x20 .. nodesize=16384]`**
(the whole block, unlike the superblock which covers `sectorsize`); computed
`0x88f84902` reproduces the stored digest → `crc_valid == Some(true)`.

Chunk-map logical→physical the P1 test asserts (single-device DUP/single, first
stripe): `chunk_root` logical `22036480` → physical `22036480` (identity), `root`
logical `30720000` → physical `39108608` (METADATA chunk: `38797312 + (30720000 −
30408704)`), DATA chunk start `13631488` → `13631488`.

## P2 ground truth (root tree + FS tree, from full `dump-tree` + mount-ro `stat`)

The root tree is a single **leaf** at logical `30720000` (physical `39108608`),
11 items, owner `ROOT_TREE` (1). Its `ROOT_ITEM` (key type **132**) for the
FS_TREE (objectid **5**) points at the FS tree root:

```
item 3 key (FS_TREE ROOT_ITEM 0)
    generation 8 root_dirid 256 bytenr 30654464 ... level 0
```

`btrfs_root_item` offsets (the leading 160 bytes are an embedded
`btrfs_inode_item`): `generation@160, root_dirid@168, bytenr@176, level@238`.
`bytenr 30654464` = the FS_TREE leaf's own logical address; `level 0` = a single
leaf.

The FS_TREE is a single **leaf** at logical `30654464` → physical `39043072`
(`38797312 + (30654464 − 30408704)`), 25 items, generation 8, owner `FS_TREE`
(5). Its item-type bytes (verified against dump-tree keys): `INODE_ITEM=1,
INODE_REF=12, DIR_ITEM=84, DIR_INDEX=96, EXTENT_DATA=108`.

**Struct offsets verified byte-for-byte vs dump-tree + mount-ro `stat`:**

- `btrfs_inode_item` (160 bytes): `generation@0, transid@8, size@16, nbytes@24,
  nlink(u32)@40, uid@44, gid@48, mode(u32)@52, flags(u64)@64`, then four
  `btrfs_timespec {sec(u64), nsec(u32)}` (12 bytes each): `atime@112, ctime@124,
  mtime@136, otime@148`.
- `btrfs_inode_ref` (INODE_REF data): `index(u64)@0, name_len(u16)@8, name[]@10`;
  the item **key's `offset`** is the parent-directory objectid.
- `btrfs_dir_item` (DIR_ITEM/DIR_INDEX data): `location btrfs_disk_key[17]@0`
  (`location.objectid` = child inode), `transid(u64)@17, data_len(u16)@25,
  name_len(u16)@27, type(u8)@29, name[]@30`. dir-item `type`: `1=REG_FILE,
  2=DIR, 7=SYMLINK`.

Known-file ground truth (dump-tree inode items, confirmed by `ls -i` + `stat`):

| inode | name (path) | parent | mode | size | mtime (sec.nsec) |
|---|---|---|---|---|---|
| 256 | `/` (root dir) | — | `0o40755` | 38 | 1783927276.225047007 |
| 257 | `small.txt` | 256 | `0o100644` | 26 | 1783927276.206047007 |
| 258 | `mid.bin` | 256 | `0o100644` | 65536 | 1783927276.216047007 |
| 259 | `dir` | 256 | `0o40755` | 6 | 1783927276.226047007 |
| 260 | `dir/sub` | 259 | `0o40755` | 16 | 1783927276.231047007 |
| 261 | `dir/sub/leaf.txt` | 260 | `0o100644` | 20 | 1783927276.231047007 |

Path resolution starts from the FS_TREE root directory objectid **256**
(`BTRFS_FIRST_FREE_OBJECTID`). The P2 always-on tests assert `read_inode`,
`list_dir(256)`, and `read_by_path("/dir/sub/leaf.txt")` against this table;
the env-gated full-image test additionally locates the FS_TREE `ROOT_ITEM` from
the root tree (`fs_tree_root` → `bytenr 30654464`). Every offset above matched
the on-disk-format facts in `docs/RESEARCH.md` — no draft offset needed
correcting for P2.

## Field-offset note (Doer-Checker)

The scalar offsets in `btrfs_super_block` were **verified byte-for-byte against
`dump-super -f`** (not coded from memory). The verified offsets are:
`csum@0x0, fsid@0x20, bytenr@0x30, flags@0x38, magic@0x40, generation@0x48,
root@0x50, chunk_root@0x58, log_root@0x60, total_bytes@0x70, bytes_used@0x78,
root_dir_objectid@0x80, num_devices@0x88, sectorsize@0x90, nodesize@0x94,
stripesize@0x9c, sys_chunk_array_size@0xa0, chunk_root_generation@0xa4,
compat_flags@0xac, compat_ro_flags@0xb4, incompat_flags@0xbc, csum_type@0xc4,
root_level@0xc6, chunk_root_level@0xc7, log_root_level@0xc8, label@0x12b,
sys_chunk_array@0x32b`. (These correct the +0x18-shifted draft offsets in the
task brief, which omitted `log_root_transid` — verifying against the oracle
caught it.)

## Committed files (index)

| file | oracle | anchors |
|---|---|---|
| `btrfs_superblock.bin` (md5 `812c99bb8ddd898a011abcd3ac5c3bbe`, 4096 B) | `dd skip=65536 count=4096` | **P0 always-on superblock test** |
| `btrfs_chunk_root.bin` (md5 `316c875aa24188c9b252fa09f78f8147`, 16384 B) | `dd skip=22036480 count=16384` | **P1 always-on node/chunk test** (raw chunk-tree leaf) |
| `btrfs_fs_tree_leaf.bin` (md5 `6676c7e415f95931b9a4f0d569a2eca8`, 16384 B) | `dd skip=39043072 count=16384` | **P2 always-on inode/dir/path test** (raw FS_TREE leaf) |
| `btrfs.dump-super.txt` | `dump-super -f` | P0 superblock field ground truth |
| `btrfs.fs-show.txt` | `btrfs filesystem show` | human geometry cross-check |
| `btrfs.chunk-tree.txt` | `dump-tree -b 22036480` | **P1** full chunk-tree walk oracle (DATA/SYSTEM/METADATA chunks) |
| `btrfs.chunk-node.txt` | `dump-tree -b 22036480` | **P1** node ground truth for `btrfs_chunk_root.bin` |
| `btrfs.full-tree.txt` | `dump-tree` (all trees) | **P2** root-tree + FS-tree ground truth (root-item / inode / dir-item) |
| `btrfs.content.sha256` | `sha256sum` on mount | P5 file-content Tier-1 (later phase) |
| `btrfs.mkfs.txt` | `mkfs.btrfs` stdout | mint provenance |

## Image hash (gitignored artifact, provenance only)

```
md5  btrfs.img  58cc07f6e3e7f950152e03ee71330477
```

## Env-gated test consumption

The always-on test reads the committed `btrfs_superblock.bin`. An additional
env-gated test reads the whole image's superblock at offset 65536 when
`BTRFS_ORACLE_IMG` points at the 512 MiB `btrfs.img` (absolute path); it skips
cleanly when unset, so CI without the minted image is green while a local run
with the corpus validates the offset within a whole image.
```
BTRFS_ORACLE_IMG=/tmp/btrfs/btrfs.img cargo test -p btrfs-core
```
