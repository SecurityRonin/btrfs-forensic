# Validation

How `btrfs-core` (and the `btrfs-forensic` auditor over it) is proven correct,
and at what evidentiary tier. The axis is **who authored the artifact and its
answer key** — not whether the data is "synthetic" — following the fleet's
Evidence-Based Rigor discipline.

## Summary

- **Tier-1 (real distro image + independent decoder oracle, env-gated):** the
  reader is validated against a genuine third-party btrfs filesystem — the
  **Fedora Cloud Base 41** root partition — whose ground truth comes from
  `btrfs inspect-internal dump-super -f` / `dump-tree` (btrfs-progs v6.6.3), a
  wholly separate implementation. Neither the image nor the field values were
  authored by us. Gitignored and downloaded on demand (`BTRFS_FEDORA_ORACLE`);
  skips cleanly when absent so CI stays green.
- **Tier-2 (self-minted regression backstops):** our own `mkfs.btrfs` image
  (`btrfs.img`, and the committed `btrfs_superblock.bin` / `btrfs_chunk_root.bin`
  fixtures extracted from it) exercises the P0 superblock + `sys_chunk_array`
  bootstrap and the P1 B-tree node / chunk-tree map. These are **not Tier-1**: we
  authored both the fixture and the expected answer, so they inherit our blind
  spots. They sit *beneath* the Tier-1 image as fast, deterministic regression
  scaffolding, cross-checked at mint time against `btrfs inspect-internal` but not
  authored by an independent party.

**btrfs has no ground-truth forensic corpus.** There is no `libfsbtrfs` in
libyal, no dfvfs btrfs test image, and no NIST CFReDS btrfs answer key; TSK's
btrfs support was added in 4.13.0 then reverted as experimental in 4.14.0, so it
is not a usable oracle either. The genuine Tier-1 here is therefore best
described as **"a real distribution image decoded against an independent decoder
oracle,"** not an answer-key corpus. That is a real and useful Tier-1 — the image
and its geometry are authentic and third-party — but it is honestly weaker than a
NIST-style corpus where an independent party publishes the expected answers.

Self-minted ≠ Tier-1. The distinction is load-bearing here: our single
`mkfs.btrfs -d single` self-mint only ever produced `incompat_flags = 0x361`, a
33 MiB METADATA chunk, and a 3-item chunk tree. The real Fedora image sets
`incompat_flags = 0x371` (**COMPRESS_ZSTD** on by default), carries a 256 MiB
METADATA chunk, and a 7-item chunk tree with several DATA chunks — real-world
geometry no self-mint here reproduced, and exactly the kind of case a Tier-1
image exists to catch.

## Tier-1 — Fedora Cloud Base 41 (third-party, freely redistributable)

**Source.** `Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2` from the Fedora
Project archive
([archives.fedoraproject.org](https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2)),
published SHA256 `6205ae0c524b4d1816dbd3573ce29b5c44ed26c9fbc874fbe48c41c89dd0bac2`
(verified after download). Converted qcow2 → raw with `qemu-img`, then the btrfs
root partition (GPT partition 4, `p.lxroot`) extracted to a standalone image
(`fedora-btrfs.raw`, md5 `2e91a6d3b627ecf759779a1d2f54066d`, 4 212 112 896 bytes).
The image and its raw partition are **gitignored** — large and freely
re-downloadable; provenance and the verbatim extraction commands live in
[`tests/data/README.md`](https://github.com/SecurityRonin/btrfs-forensic/blob/main/tests/data/README.md).

**Oracle (independent of our reader).**

| Oracle | What it establishes |
|---|---|
| `btrfs inspect-internal dump-super -f` (btrfs-progs v6.6.3) | superblock geometry — magic, csum_type, fsid, label, generation, root/chunk_root logical addrs, total_bytes, sectorsize, nodesize, num_devices, incompat_flags |
| `btrfs inspect-internal dump-tree -t chunk` | the chunk tree's logical→physical placements (7 CHUNK_ITEMs: SYSTEM\|DUP, METADATA\|DUP, several DATA\|single) |
| `btrfs inspect-internal dump-tree -t root` | the root tree's own logical addr, owner, and item count |

**Ground truth captured** (verbatim in `tests/data/README.md`):

- Superblock: magic `_BHRfS_M [match]`, csum_type `0 (crc32c)`, fsid
  `815e66c2-6a8a-4984-a890-1a3c710bf933`, label `fedora`, generation 13, root
  logical `71991296`, chunk_root logical `22069248`, log_root 0, total_bytes
  `4212109312`, sectorsize 4096, nodesize 16384, num_devices 1, incompat_flags
  `0x371` (MIXED_BACKREF | **COMPRESS_ZSTD** | BIG_METADATA | EXTENDED_IREF |
  SKINNY_METADATA | NO_HOLES).
- Chunk map: root logical `71991296` sits in the METADATA\|DUP chunk
  `[30408704, +268435456)` (first stripe physical `38797312`), so root physical =
  `38797312 + (71991296 − 30408704) = 80379904`; chunk_root logical `22069248`
  maps identically to physical `22069248`. Both were cross-checked against the raw
  bytes (the node headers at those physical offsets self-reference the expected
  `bytenr`/`owner`).

**Test** — `core/tests/tier1_fedora.rs` (env-gated on `BTRFS_FEDORA_ORACLE`). It
asserts:

1. `Superblock::parse` fields == the `dump-super -f` values (incl. the
   `COMPRESS_ZSTD` incompat bit our self-mint lacked, and the primary superblock's
   crc32c verifying).
2. `ChunkMap::walk` over Fedora's 7-item chunk tree resolves `chunk_root` and
   `root` to the physical offsets `dump-tree` implies.
3. `read_node` reads the root tree (owner ROOT_TREE, crc verifies) and the chunk
   root (owner CHUNK_TREE, crc verifies) by logical address.

**Run command** (after preparing `fedora-btrfs.raw` per `tests/data/README.md`):

```bash
BTRFS_FEDORA_ORACLE=/abs/path/to/fedora-btrfs.raw \
  cargo test -p btrfs-core --test tier1_fedora
```

**Result.** All assertions pass: `btrfs-core` reads the real third-party Fedora
image correctly on the first pass. The larger METADATA chunk, the multi-DATA-chunk
layout, and the `COMPRESS_ZSTD` flag — none of which the self-mint produced —
decode correctly, so no reader change was required. This is a
"validates existing code" result, not a bug fix.

## Tier-2 — self-minted regression backstops

Minted on a controlled Linux VM (Parallels `Ubuntu 24.04`, `mkfs.btrfs`
btrfs-progs v6.6.3) and cross-checked at mint time against
`btrfs inspect-internal dump-super -f` / `dump-tree`. Provenance and the verbatim
mint commands are in [`tests/data/README.md`](https://github.com/SecurityRonin/btrfs-forensic/blob/main/tests/data/README.md). The 512
MiB `btrfs.img` is gitignored; the small extracted fixtures are committed:

- `btrfs_superblock.bin` (4096 B) — the P0 always-on superblock test: magic,
  csum, fsid, geometry, root/chunk_root logical addrs, and the `sys_chunk_array`
  bootstrap SYSTEM\|DUP entry.
- `btrfs_chunk_root.bin` (16384 B) — the P1 always-on node/chunk test: the raw
  chunk-tree leaf (header, 4 items, the DATA/SYSTEM/METADATA CHUNK_ITEMs and their
  stripes) with a verifying node crc32c, plus the `ChunkMap` logical→physical
  mapping for the known addresses.

They remain valuable as fast, deterministic CI regression scaffolding, but their
correctness is defined by fixtures we authored, so they never stand alone as the
sole proof for a value-producing path — the Fedora Tier-1 image is the independent
oracle above them.

## Tier-2 — deletion oracle (self-minted, for F-CARVE)

The `btrfs-forensic` **F-CARVE** deleted-file recovery needs an image with an
actual deletion, which the Fedora Tier-1 image does not have. A **self-minted**
`del.img` (256 MiB) supplies it: `mkfs.btrfs` on a controlled Linux VM, a known
file written + committed (gen 7) then `rm`'d + synced (gen 8), leaving the
pre-delete `FS_TREE` root in a backup slot. This is **Tier-2, not Tier-1** — real
`mkfs.btrfs`/kernel output independently decoded by `btrfs inspect-internal`, but
*we chose the deletion scenario*, so a re-mint reproduces a Tier-2 fixture and can
never reconstitute a Tier-1 validation.

- **Env var:** `BTRFS_DEL_ORACLE` (absolute path to the 256 MiB `del.img`; the
  image is gitignored, provenance-only). The small extracted leaf fixtures
  (`btrfs_del_old_fs_tree_leaf.bin` / `btrfs_del_current_fs_tree_leaf.bin`) are
  committed and drive the always-on F-CARVE gate with no env var.
- **Verbatim mint command + md5s + ground truth:** `tests/data/README.md`
  ("Deletion oracle" section) — `del.img` md5 `a324b52d8e73df339f584859c6491ed4`;
  pre-delete gate sha256
  `4fce0707f6dbddc3e37931fd76044862979ddca3d80b97e338197f8995e8d312`.
- **Run command** (whole-image F-CARVE path):
  ```bash
  BTRFS_DEL_ORACLE=/abs/path/to/del.img \
    cargo test -p btrfs-forensic --test f_carve full_image_recovers_deleted_file
  ```
  The same image also drives the `btrfs-core` VFS-adapter cross-check (needs the
  `vfs` feature):
  ```bash
  BTRFS_DEL_ORACLE=/abs/path/to/del.img \
    cargo test -p btrfs-core --features vfs --test vfs_oracle
  ```

## Reproduce Tier-1 from a clean clone

btrfs has **no downloadable answer-key corpus** (no `libfsbtrfs`, no dfvfs btrfs
image, no NIST CFReDS btrfs), so the single Tier-1 path is the real Fedora image
decoded against an independent decoder oracle. From a fresh clone:

1. **Download + verify the Fedora image** (Fedora Project archive, freely
   redistributable):
   ```bash
   curl -L -o /tmp/fedora.qcow2 \
     https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/41/Cloud/x86_64/images/Fedora-Cloud-Base-Generic-41-1.4.x86_64.qcow2
   sha256sum /tmp/fedora.qcow2   # == 6205ae0c524b4d1816dbd3573ce29b5c44ed26c9fbc874fbe48c41c89dd0bac2
   ```
2. **Convert + extract the btrfs root partition** (verbatim commands in
   `tests/data/README.md`) to `fedora-btrfs.raw` (md5
   `2e91a6d3b627ecf759779a1d2f54066d`).
3. **Set the env var + run:**
   ```bash
   BTRFS_FEDORA_ORACLE=/tmp/fedora-btrfs.raw \
     cargo test -p btrfs-core --test tier1_fedora
   ```

The Tier-2 deletion oracle above is *not* Tier-1 and is not part of this block —
it is self-minted (mint command in `tests/data/README.md`), not downloaded.
