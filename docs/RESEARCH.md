# btrfs Forensic Reader — Research-First Report (`btrfs-core` + `btrfs-forensic`)

Read-only Research-First deliverable. Struct layouts are transcribed byte-exact from
the canonical btrfs-progs UAPI header `kernel-shared/uapi/btrfs_tree.h` and `ctree.h`
(btrfs-progs `master`), cross-checked against the on-disk-format docs — Tier-1
provenance for the format facts (primary source = the driver's own ABI).

## 1. Authoritative spec

| Source | What | URL |
|---|---|---|
| **btrfs-progs UAPI `btrfs_tree.h`** | Canonical struct + constant defs (driver's on-disk ABI) | https://github.com/kdave/btrfs-progs/blob/master/kernel-shared/uapi/btrfs_tree.h |
| **btrfs-progs `ctree.h`** | `btrfs_super_block`, `BTRFS_SUPER_INFO_OFFSET` (65536), `BTRFS_SUPER_INFO_SIZE` (4096) | https://github.com/kdave/btrfs-progs/blob/master/kernel-shared/ctree.h |
| **On-disk Format** (readthedocs) | Field-by-field offset tables | https://btrfs.readthedocs.io/en/latest/dev/On-disk-format.html |
| **btrfs design (CoW / Rodeh B-tree)** | CoW model, subvolume/snapshot semantics | https://btrfs.readthedocs.io/en/latest/dev/dev-btrfs-design.html |
| Archived kernel.org wiki (OBSOLETE) | Historical item-type detail | https://archive.kernel.org/oldwiki/btrfs.wiki.kernel.org/index.php/On-disk_Format.html |
| Rodeh, *B-trees, Shadowing, and Clones* (ACM TOS 2008) | CoW-B-tree foundation | (cited in design doc) |

Community RE refs: `danobi/btrd` (btrfs debugger, GPL-2), `danobi/btrfs-walk`
(read-only tree walker, GPL-2) — cleanest small Rust references; `GodTamIt/btrfs-diskformat`
(BSD-2, clean-room) — cleanest Rust struct catalog.

**Global constants (verified):** `BTRFS_MAGIC = 0x4D5F53665248425F` ("_BHRfS_M", LE
u64 at SB offset 0x40); `BTRFS_SUPER_INFO_OFFSET = 65536` (0x10000),
`BTRFS_SUPER_INFO_SIZE = 4096`; `BTRFS_CSUM_SIZE = 32`, `BTRFS_FSID_SIZE = 16`,
`BTRFS_LABEL_SIZE = 256`, `BTRFS_SYSTEM_CHUNK_ARRAY_SIZE = 2048`, `BTRFS_MAX_LEVEL = 8`.
SB mirrors at **0x4000000 (64 MiB)** and **0x4000000000 (256 GiB)** if within device size.

**Core structures (dependency order):**

**(a) Superblock** — `btrfs_super_block` in the 4096-byte block at 0x10000; field
order (all `__le`, packed): `csum[32], fsid[16], bytenr(u64), flags, magic,
generation, root(u64=root-tree logical), chunk_root(u64), log_root, __unused_log_root_transid,
total_bytes, bytes_used, root_dir_objectid, num_devices, sectorsize(u32), nodesize(u32),
__unused_leafsize, stripesize, sys_chunk_array_size(u32), chunk_root_generation, compat_flags,
compat_ro_flags, incompat_flags, csum_type(u16), root_level(u8), chunk_root_level(u8),
log_root_level(u8), dev_item(98 bytes), label[256], cache_generation, uuid_tree_generation,
metadata_uuid[16], nr_global_roots, remap_root, remap_root_generation, remap_root_level,
reserved[199], sys_chunk_array[2048], super_roots[BTRFS_NUM_BACKUP_ROOTS], padding[565]`.
First-consumed: `chunk_root`, `chunk_root_level`, `root`, `root_level`, `sectorsize`,
`nodesize`, `csum_type`, `generation`, `sys_chunk_array_size` + `sys_chunk_array`.

**(b) Chunk tree + logical→physical mapping — the DEFINING complexity.** Every tree
except the SB is addressed by **logical** address; nothing is readable until this
works. Bootstrap: parse `sys_chunk_array` (packed `[disk_key][chunk + stripes]`,
`sys_chunk_array_size` bytes valid) → partial map for SYSTEM block groups → read chunk
tree at logical `chunk_root` → walk all `CHUNK_ITEM` (type 228) → full map → root
tree at logical `root` reachable. `btrfs_chunk` (key `[FIRST_CHUNK_TREE(256),
CHUNK_ITEM(228), logical_offset]`): `length, owner, stripe_len, type(BLOCK_GROUP_*),
io_align, io_width, sector_size, num_stripes(u16), sub_stripes(u16), stripe[]`.
`btrfs_stripe { devid, offset(=physical byte on device), dev_uuid[16] }`.
**Single-device (single/DUP):** `physical = stripe.offset + (logical − chunk_key.offset)`;
DUP (default single-disk metadata) has 2 stripes on the same device (pick stripe[0]).
RAID0/1/10/5/6/1c3/1c4 = defer. Type flags: `DATA(1<<0) SYSTEM(1<<1) METADATA(1<<2)
RAID0(1<<3) RAID1(1<<4) DUP(1<<5) RAID10(1<<6) RAID5(1<<7) RAID6(1<<8) RAID1C3(1<<9)
RAID1C4(1<<10)`.

**(c) B-tree node/leaf.** `btrfs_header` (101 bytes): `csum[32], fsid[16],
bytenr(u64=THIS node logical), flags, chunk_tree_uuid[16], generation, owner(u64=tree
objectid), nritems(u32), level(u8)` (level 0 = leaf). Interior: `nritems ×
btrfs_key_ptr { key: disk_key(17), blockptr(u64=child logical), generation }`. Leaf:
`nritems × btrfs_item { key: disk_key(17), offset(u32), size(u32) }` growing forward;
item **data** grows backward from the `nodesize` block end (`data = header +
item[i].offset`, len `item[i].size`). `btrfs_disk_key { objectid(u64), type(u8),
offset(u64) }` = 17 bytes.

**(d) `btrfs_key` ordering** — keys sort by the tuple **`(objectid, type, offset)`**,
compared on host-integer values (fields LE on disk, compared as u64/u8). Invariant
across every tree; binary search + interior descent both rely on it. **Comparing raw
LE bytes, or reordering type/offset, silently mis-navigates** — top risk (§4).

**(e) Tree-of-trees:** `ROOT_TREE=1, EXTENT_TREE=2, CHUNK_TREE=3, DEV_TREE=4, FS_TREE=5,
ROOT_TREE_DIR=6, CSUM_TREE=7, QUOTA=8, UUID=9, FREE_SPACE=10, BLOCK_GROUP=11;
FIRST_FREE(first normal inode)=256`. Chunk tree → **root tree** (1) holds `ROOT_ITEM`
(type 132) → each points (`bytenr`,`level`) at another tree incl. every **FS tree /
subvolume** (5 = default, others ≥256). FS tree per inode:
- `INODE_ITEM` (1) — `generation, transid, size, nbytes, block_group, nlink(u32),
  uid, gid, mode, rdev, flags, sequence, reserved[4], atime, ctime, mtime, otime`
  where each time = `btrfs_timespec { sec(u64), nsec(u32) }` (12 bytes).
- `INODE_REF` (12) — `{ index(u64), name_len(u16), name[] }` (`INODE_EXTREF`=13 overflow).
- `DIR_ITEM` (84) / `DIR_INDEX` (96) — `btrfs_dir_item { location: disk_key(17),
  transid, data_len(u16), name_len(u16), type(u8), name[]/data[] }`. DIR_ITEM keyed
  by name-hash, DIR_INDEX by sequential index.
- `EXTENT_DATA` (108) — `btrfs_file_extent_item { generation, ram_bytes, compression(u8),
  encryption(u8), other_encoding(u16), type(u8) }`. `type==INLINE(0)` → bytes inline
  after the 21-byte prefix; else (`REG(1)`/`PREALLOC(2)`): `disk_bytenr(u64, 0⇒sparse),
  disk_num_bytes, offset, num_bytes`.
- `XATTR_ITEM` (24); extent tree (168 `EXTENT_ITEM`/169 `METADATA_ITEM`); checksum tree
  (128 `EXTENT_CSUM`, keyed by `EXTENT_CSUM_OBJECTID=-10`).

**(f) CoW/generations/csum/compression:** latest committed = SB copy with highest valid
`generation`; every tree block carries `generation` → stale blocks identifiable by
older generation (the forensic lever); `super_roots[BTRFS_NUM_BACKUP_ROOTS]` holds
prior committed root sets (backup roots — point-in-time). csum types: `CRC32(0,
default crc32c), XXHASH(1), SHA256(2), BLAKE2(3)` (first `csum_len` of the 32-byte
field; 4 for crc32c; covers block after the csum field to `nodesize` end).
compression: `0=none,1=zlib,2=LZO,3=zstd`; `ram_bytes`=decompressed size.

## 2. Existing implementations (build-vs-reuse)

| Name | URL | Kind | Maturity/license | Use |
|---|---|---|---|---|
| **`btrfs-diskformat`** (GodTamIt) | github.com/GodTamIt/btrfs-diskformat, crates.io 0.5.1 | Read, on-disk structs, no_std zerocopy | 25★, **BSD-2** | **Best Rust struct cross-check** (permissive); struct layer, not a logical-address reader. |
| **`danobi/btrfs-walk`** | github.com/danobi/btrfs-walk | Read-only demo: SB→chunk bootstrap→root→fs walk | GPL-2 | **Closest reference for the exact bootstrap chain** — read, don't vendor. |
| **`danobi/btrd`** | github.com/danobi/btrd | Interactive read-only debugger | 22★, GPL-2 | Navigation reference + scriptable cross-check oracle — GPL, reference only. |
| `btrfs`/`btrfs2` | crates.io | **ioctl wrappers** (live mounted FS) | MIT-ish | Not on-disk parsing. |

**No mature, maintained, read-only, permissively-licensed Rust btrfs navigator exists.**

**Non-Rust references + oracles:**
- **`btrfs inspect-internal dump-super [-f]`** — SB + system chunk array + backup roots (structural oracle).
- **`btrfs inspect-internal dump-tree [-t <tree>]`** — every tree/item/key — **the canonical structural ground-truth oracle**.
- **`btrfs-debugfs`** (Python) — per-file extent mapping.
- **Kernel driver (mount -o ro,loop + sha256)** — content oracle (independent
  second implementation; on a *self-minted* image this is still Tier-2 — see §3).
- **TSK: btrfs is NOT stable.** Added in TSK **4.13.0** (Mar 2025) then **reverted as
  experimental in 4.14.0** (Apr 2025). Official stable list excludes btrfs; pytsk3
  inherits this. Academic add-ons: Juchli's TSK-btrfs (`ajuch/sleuthkit-btrfs-testsuite`),
  the 2024 "File System Add-ons" paper. **TSK is not a usable btrfs oracle; btrfs-progs
  is** → a real forensic gap (no production forensic-suite btrfs reader) = the differentiator.

**Recommendation: BUILD.** Reuse ecosystem for leaf primitives only —
`crc32c`/`xxhash-rust`/`sha2`/`blake2` (csums), `flate2`(zlib)/`zstd`/an LZO decoder
(compression). `btrfs-diskformat` (BSD-2) = struct cross-check; `btrfs-walk`/`btrd`
(GPL) = algorithm references (read, don't vendor). Validate vs
`btrfs inspect-internal dump-tree` (structure) + mount-ro/sha256 (content).

## 3. Real sample data + oracle (Tier-2 self-mint backstop; Tier-1 real corpus wired via Fedora)

```bash
# Parallels Ubuntu VM: sudo apt install btrfs-progs
cd /tmp && truncate -s 512M btrfs-oracle.img
mkfs.btrfs -f -L BTRFS_ORACLE --csum crc32c btrfs-oracle.img
#   variants: --csum xxhash ; -m single -d single ; -n 4096
sudo mkdir -p /mnt/btrfs-oracle && sudo mount -o loop btrfs-oracle.img /mnt/btrfs-oracle
cd /mnt/btrfs-oracle
echo "hello inline btrfs" | sudo tee small.txt >/dev/null
sudo dd if=/dev/urandom of=big.bin bs=1M count=8 status=none
sudo bash -c 'yes ABCDEFGH | head -c 4194304 > comp.txt'
sudo mount -o remount,compress-force=zlib /mnt/btrfs-oracle
sudo bash -c 'yes ABCDEFGH | head -c 4194304 > comp_zlib.txt'
sudo mkdir -p dir/sub && echo nested | sudo tee dir/sub/leaf.txt >/dev/null
sudo ln small.txt small_hardlink.txt ; sudo ln -s big.bin big_symlink
sudo btrfs subvolume create subv1
echo "in subvolume" | sudo tee subv1/svfile.txt >/dev/null
sudo btrfs subvolume snapshot subv1 snap1
sudo btrfs subvolume snapshot -r subv1 snap1_ro
sync
sudo find . -type f -exec sha256sum {} \; | sudo tee /tmp/btrfs-oracle.sha256   # content check (Tier-2: self-minted content)
sudo umount /mnt/btrfs-oracle
# structural oracles (Tier-2)
btrfs inspect-internal dump-super -f btrfs-oracle.img  > /tmp/oracle.dump-super.txt
btrfs inspect-internal dump-tree      btrfs-oracle.img > /tmp/oracle.dump-tree.txt
btrfs inspect-internal dump-tree -t chunk btrfs-oracle.img > /tmp/oracle.chunk-tree.txt
btrfs inspect-internal dump-tree -t root  btrfs-oracle.img > /tmp/oracle.root-tree.txt
```

**Tiering (corrected — self-minted ≠ Tier-1).** A non-ours *oracle*
(`btrfs inspect-internal dump-super/dump-tree`, the kernel mount, sha256) does not
lift a self-authored *artifact* to Tier-1. Our `btrfs.img` is **REAL-self = Tier-2**:
real `mkfs.btrfs` output, confirmed byte-for-byte by independent tools, but **we chose
the scenario** — so both structure (dump-tree/dump-super) and content (mount-ro +
sha256) are validated at **Tier-2**. Tier-2 is the correct, useful tier for these
committed fixtures: fast, deterministic P0/P1 regression backstops under an independent
decoder oracle. But it inherits our blind spots — a single-device `mkfs.btrfs -d single`
image only ever exercises the geometry we asked for.

Genuine **Tier-1** requires a *third-party-authored or real-world* artifact whose
answer key we did not write. **btrfs has no ground-truth forensic corpus** — no
`libfsbtrfs` in libyal, no dfvfs btrfs test image, no NIST CFReDS btrfs answer key,
and TSK's btrfs support was reverted as experimental (§2). The best available Tier-1
is therefore a **real Fedora Cloud btrfs image** (the Fedora Project authored the
filesystem, not us), validated against the independent `btrfs inspect-internal`
decoder. Honest framing: this is **"real distro image + independent decoder oracle,"
not a ground-truth answer-key corpus** — see [`validation.md`](validation.md) and
`tests/data/README.md` for the wired Fedora oracle (`BTRFS_FEDORA_ORACLE`, gitignored).
Document every minted/downloaded image's commands per the fleet provenance standard
(`tests/data/README.md` + `issen/docs/corpus-catalog.md`).

## 4. Scope/difficulty + phased build order

**MVP:** superblock → `sys_chunk_array` bootstrap → chunk-tree full logical→physical
map → root tree → FS tree (5) walk (inode → DIR_INDEX/DIR_ITEM → EXTENT_DATA) → read
file by path (inline + regular/uncompressed) → inode metadata + 4 timestamps.

**Hard (ranked):**
1. **Chunk-tree logical addressing — bootstrap-before-you-can-read (HIGHEST RISK).** A
   subtle single-device offset error (`stripe.offset + (logical − chunk_key.offset)`)
   yields plausible-but-wrong reads → LZNT1-trap zone; mandatory oracle from day one.
2. **`btrfs_key (objectid,type,offset)` tuple ordering (HIGH, subtle)** — wrong
   comparison mis-navigates while looking fine on small images; cross-check vs `dump-tree`.
3. CoW/generation/committed-root selection (highest valid generation; per-block
   generation distinguishes live vs stale — the forensic basis).
4. Compression (zlib/LZO/zstd) — reuse audited crates; LZO has btrfs-specific per-page
   framing (validate vs a compressed oracle file).
5. Subvolume/snapshot enumeration + cross-subvolume roots.
6. RAID profiles — defer entirely; single/DUP first.

**Difficulty:** **harder than XFS, much harder than ext4** — btrfs adds a whole
logical-address indirection layer (chunk tree) on top of an everything-is-CoW-B-tree
design; you parse two trees just to bootstrap addressing before any content is reachable.

**`btrfs-core` phases:** P0 Superblock (magic, csum, highest-generation copy; oracle
`dump-super -f`) → P1 Bootstrap chunk map (sys_chunk_array, single/DUP; oracle
`dump-tree -t chunk`) → P2 Tree-block reader (header + key_ptr + item; key search
honoring `(objectid,type,offset)`; csum per block; oracle `dump-tree`) → P3 Full chunk
tree → P4 Root tree + FS tree (ROOT_ITEMs → FS tree 5 → inodes) → P5 File read
(EXTENT_DATA inline + regular uncompressed → **content sha256 gate** — Tier-2 on the
self-mint, Tier-1 once run against the real Fedora image) → P6 Compression
(zlib→zstd→LZO) + sparse holes + timestamps → P7 Subvolumes/snapshots (multi-device/
RAID deferred).

**`btrfs-forensic` (over the raw tree/block layer — needs stale blocks/slack the
reader normalizes):** old-root/generation recovery (backup roots + stale tree blocks
with older generation → **point-in-time reconstruction via CoW**, no ext4 equivalent);
deleted-file recovery (freed-but-unoverwritten tree blocks by generation/owner
mismatch; ORPHAN_ITEM type 48); snapshot diffing (FS trees across roots); integrity
findings (EXTENT_CSUM mismatch, SB-mirror divergence, generation inconsistency, orphans)
→ `forensicnomicon::report::Finding` (`BTRFS-CSUM-MISMATCH`, `BTRFS-STALE-ROOT`,
`BTRFS-GEN-INCONSISTENT`).

**Highest-risk items to gate hardest:** (1) chunk-tree logical→physical mapping and
(2) `btrfs_key` tuple ordering — both silently-wrong-not-loud; pin both to the
`dump-tree` oracle on real minted data before trusting anything else.

**Gaps/caveats:** torvalds kernel raw header 429'd → struct facts from btrfs-progs
`master` UAPI (functionally identical ABI) + readthedocs tables; verify final byte
offsets vs a live `dump-super`/`dump-tree` when implementing. Confirm zstd enum (3) +
LZO framing on a minted `compress=zstd` file.
