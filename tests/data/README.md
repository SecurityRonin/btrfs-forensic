# btrfs Forensic Test Data — Provenance

Two evidentiary tiers (see [`docs/validation.md`](../../docs/validation.md)):

- **Tier-1 (REAL-ext):** a genuine third-party btrfs filesystem — the **Fedora
  Cloud Base 41** root partition — validated against the independent
  `btrfs inspect-internal` decoder. Neither the image nor its answer key was
  authored by us. Gitignored + downloaded on demand (`BTRFS_FEDORA_ORACLE`).
  btrfs has **no ground-truth forensic corpus** (no libfsbtrfs, no dfvfs btrfs,
  no NIST answer key), so this is "real distro image + independent decoder
  oracle," not an answer-key corpus — but it is real, third-party geometry the
  self-mint never produced (see the Fedora entry below).
- **Tier-2 (REAL-self):** minted on a controlled Linux VM with `mkfs.btrfs`
  (btrfs-progs) and cross-checked against the independent `btrfs inspect-internal`
  oracle (a different implementation from this reader). Real `mkfs.btrfs` output,
  independently checked — **but we chose the scenario**, so it is Tier-2, not
  Tier-1: a fast, deterministic P0/P1 regression backstop, not the independent
  answer key.

See the fleet catalog at
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

## Tier-1 real-world corpus — Fedora Cloud Base 41 (REAL-ext, gitignored)

The genuine Tier-1 artifact: a **real Fedora Cloud Base 41** disk image whose
btrfs root filesystem was authored by the Fedora Project, not us. Consumed by
`core/tests/tier1_fedora.rs` (env-gated on `BTRFS_FEDORA_ORACLE`; skips when
absent). Not committed — large and freely re-downloadable.

<!-- TODO: mirror this entry into issen/docs/corpus-catalog.md (the single fleet
     machine index) — classify REAL-ext / Tier-1, gitignored. Do not duplicate;
     that catalog cross-references this README. -->

#### Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2 → fedora-btrfs.raw

- **Source:** Fedora Project, Fedora Linux 41 Cloud Base (Generic) image.
- **Original download URL** (moved to the archive host once F41 was superseded):
  <https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2>
  (the `download.fedoraproject.org` redirector now 404s for F41 — use the archive
  host directly).
- **qcow2 identity:** 491 716 608 bytes, published SHA256
  `6205ae0c524b4d1816dbd3573ce29b5c44ed26c9fbc874fbe48c41c89dd0bac2`
  (from `Fedora-Cloud-41-1.4-x86_64-CHECKSUM`; verified after download).
- **License / redistribution:** Fedora Cloud images are freely redistributable
  (Fedora Project). We do **not** commit them — downloaded on demand.
- **Extracted btrfs partition** (`fedora-btrfs.raw`, gitignored):
  md5 `2e91a6d3b627ecf759779a1d2f54066d`, 4 212 112 896 bytes (GPT partition 4,
  `p.lxroot`, at byte offset 1 156 579 328 of the 5 GiB raw disk).
- **Independent oracle ground truth** (`btrfs inspect-internal`, btrfs-progs
  v6.6.3), asserted by the test:

  | field | value |
  |---|---|
  | `magic` | `_BHRfS_M` `[match]` |
  | `csum_type` | `0 (crc32c)` |
  | `fsid` | `815e66c2-6a8a-4984-a890-1a3c710bf933` |
  | `label` | `fedora` |
  | `generation` | `13` |
  | `root` (logical) | `71991296` → physical `80379904` (METADATA\|DUP chunk) |
  | `chunk_root` (logical) | `22069248` → physical `22069248` (SYSTEM\|DUP, identity) |
  | `log_root` | `0` |
  | `total_bytes` | `4212109312` |
  | `sectorsize` / `nodesize` / `stripesize` | `4096` / `16384` / `4096` |
  | `num_devices` | `1` |
  | `incompat_flags` | `0x371` (MIXED_BACKREF \| **COMPRESS_ZSTD** \| BIG_METADATA \| EXTENDED_IREF \| SKINNY_METADATA \| NO_HOLES) |

  The chunk tree is a single leaf at `22069248` (7 items): SYSTEM\|DUP,
  METADATA\|DUP `[30408704, +268435456)` (first stripe physical `38797312`), and
  several DATA\|single chunks. `COMPRESS_ZSTD` and the 256 MiB METADATA chunk are
  real-world features the self-mint (`0x361`, 33 MiB METADATA) never produced.

### Verbatim download + extraction commands (reproduce the Tier-1 corpus)

```bash
# 1. Download the Fedora Cloud qcow2 (archive host; verify SHA256).
mkdir -p /tmp/btrfs_fedora && cd /tmp/btrfs_fedora
curl -sSL -O \
  https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2
shasum -a 256 Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2   # 6205ae0c...0bac2

# 2. Convert qcow2 -> raw (qemu-img; host or VM).
qemu-img convert -O raw Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2 fedora.raw

# 3. Find the btrfs partition and extract it standalone (on the Linux VM;
#    parted reports partition 4 = btrfs at byte 1156579328, size 4212112896).
parted -s fedora.raw unit B print
dd if=fedora.raw of=fedora-btrfs.raw bs=512 skip=2258944 count=8226783 status=none

# 4. Confirm it is btrfs + record md5.
btrfs inspect-internal dump-super -f fedora-btrfs.raw   # magic _BHRfS_M [match]
md5sum fedora-btrfs.raw                                 # 2e91a6d3...066d

# 5. Run the env-gated Tier-1 test.
BTRFS_FEDORA_ORACLE=/tmp/btrfs_fedora/fedora-btrfs.raw cargo test -p btrfs-core --test tier1_fedora
```

## Committed files (index)

| file | oracle | anchors |
|---|---|---|
| `btrfs_superblock.bin` (md5 `812c99bb8ddd898a011abcd3ac5c3bbe`, 4096 B) | `dd skip=65536 count=4096` | **P0 always-on superblock test** |
| `btrfs_chunk_root.bin` (md5 `316c875aa24188c9b252fa09f78f8147`, 16384 B) | `dd skip=22036480 count=16384` | **P1 always-on node/chunk test** (raw chunk-tree leaf) |
| `btrfs.dump-super.txt` | `dump-super -f` | P0 superblock field ground truth |
| `btrfs.fs-show.txt` | `btrfs filesystem show` | human geometry cross-check |
| `btrfs.chunk-tree.txt` | `dump-tree -b 22036480` | **P1** full chunk-tree walk oracle (DATA/SYSTEM/METADATA chunks) |
| `btrfs.chunk-node.txt` | `dump-tree -b 22036480` | **P1** node ground truth for `btrfs_chunk_root.bin` |
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
