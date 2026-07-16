# btrfs-forensic

**A from-scratch btrfs reader and a graded anomaly auditor — walk the chunk tree, B-trees, and FS-tree of a btrfs image over any byte source, then turn its copy-on-write history into evidence: stale backup roots, csum-mismatched tree blocks, orphaned inodes, and deleted files still carvable from an older generation's FS-tree.**

Two crates, one workspace:

- **[`btrfs-core`](https://crates.io/crates/btrfs-core)** — the reader: superblock + `sys_chunk_array` bootstrap, chunk-tree logical→physical mapping, B-tree node navigation, FS-tree inode / directory / path resolution, and `EXTENT_DATA` → file content with always-compiled zlib / LZO / zstd decompression, over any byte slice. No `unsafe`, no C bindings.
- **[`btrfs-forensic`](https://crates.io/crates/btrfs-forensic)** — the auditor: turns parsed btrfs structures into severity-graded [`forensicnomicon::report::Finding`](https://crates.io/crates/forensicnomicon)s, and recovers CoW-deleted files, so a btrfs volume's anomalies aggregate uniformly with the partition and container layers.

## Audit a btrfs image in 30 seconds

```toml
[dependencies]
btrfs-forensic = "0.1"   # pulls in btrfs-core
```

```rust
use btrfs_forensic::audit_findings;

// Feed it the raw image bytes; get back graded findings.
for finding in audit_findings(&image_bytes, "btrfs") {
    println!("[{:?}] {} — {}", finding.severity, finding.code, finding.note);
    // e.g. [Some(High)] BTRFS-BACKUP-ROOT-DIVERGENCE — backup root gen 42 > committed 41 …
}
```

`audit_findings` parses the superblock, chunk tree, and FS-tree in place and grades what it finds. A structurally invalid image yields no findings (corruption is surfaced as its own finding or by the carver, never a panic).

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | What it observes |
|---|---|---|
| `BTRFS-SUPERBLOCK-CRC-MISMATCH` | High | The superblock's own crc32c does not verify — corruption or post-write tampering |
| `BTRFS-CRC-MISMATCH` | High | A metadata node/leaf whose stored crc32c does not verify |
| `BTRFS-BACKUP-ROOT-DIVERGENCE` | High | A `btrfs_root_backup` entry inconsistent with the committed generation — consistent with rollback / tampered backup roots |
| `BTRFS-IMPOSSIBLE-GEOMETRY` | High | A root/geometry field beyond what the image can hold — an allocation-bomb / corruption guard |
| `BTRFS-ORPHANED-INODE` | Medium | An `ORPHAN_ITEM` in the `FS_TREE` — an inode unlinked while open / pending cleanup, a recovery lead |

Deleted-file recovery is separate: `recover_deleted(&image)` walks an older generation's `FS_TREE` (reached through a `btrfs_root_backup` entry), diffs it against the current `FS_TREE`, and returns each carved `RecoveredFile` (name, inode, generation, size, content, and the content's sha256 recovery gate).

## The reader: navigate an image

`btrfs-core` reads a btrfs image over any byte slice:

```rust
use btrfs_core::{Superblock, ChunkMap, read_by_path_content};

let sb = Superblock::parse(&image[65536..65536 + 4096])?;
let map = ChunkMap::walk(&image, &sb)?;
let bytes = read_by_path_content(&image, &sb, &map, "etc/hostname")?;
# Ok::<(), btrfs_core::BtrfsError>(())
```

The bare crate name `btrfs` on crates.io is an unrelated live-FS ioctl wrapper, so this on-disk reader publishes as `btrfs-core` and imports as `btrfs_core`.

## Trust but verify

- **`#![forbid(unsafe_code)]`** in both crates — no `unsafe`, no C bindings.
- **Panic-free** — every integer/length/offset field is read through bounds-checked helpers; a malformed image degrades to an empty/typed result, never a panic.
- **Fuzzed** — one `cargo-fuzz` target per parsed structure (superblock, node, chunk, fstree, extent, crc) plus a `fuzz_forensic` target driving the full `audit_image` / `recover_deleted` pipeline. See [Validation](validation.md).
- **Tier-1 validated** — the reader is checked against a real **Fedora Cloud** btrfs filesystem whose ground truth comes from btrfs-progs' own `dump-super -f` / `dump-tree`, a wholly separate implementation. See [Validation](validation.md).

---

[Privacy Policy](privacy.md) · [Terms of Service](terms.md) · © 2026 Security Ronin Ltd.
