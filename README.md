# btrfs-forensic

[![btrfs-core](https://img.shields.io/crates/v/btrfs-core.svg?label=btrfs-core)](https://crates.io/crates/btrfs-core)
[![btrfs-forensic](https://img.shields.io/crates/v/btrfs-forensic.svg?label=btrfs-forensic)](https://crates.io/crates/btrfs-forensic)
[![Docs.rs](https://img.shields.io/docsrs/btrfs-forensic?label=docs.rs)](https://docs.rs/btrfs-forensic)
[![Rust 1.87+](https://img.shields.io/badge/rust-1.87%2B-blue.svg)](https://www.rust-lang.org)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

[![CI](https://github.com/SecurityRonin/btrfs-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/btrfs-forensic/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-100%25%20lines-brightgreen.svg)](https://securityronin.github.io/btrfs-forensic/validation/)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![Security audit](https://img.shields.io/badge/security-cargo--deny-brightgreen.svg)](deny.toml)
[![Docs](https://img.shields.io/badge/docs-mkdocs-blue.svg)](https://securityronin.github.io/btrfs-forensic/)

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

`audit_findings` parses the superblock, chunk tree, and FS-tree in place and grades what it finds. A structurally invalid image yields no findings (corruption is surfaced as its own finding or by the carver, never a panic). For the typed form, `audit_image(&image)` returns `Vec<Anomaly>` — each `anomaly.to_finding(source)` converts to a `report::Finding`.

## The anomaly codes

Each finding is an **observation** ("consistent with …"); the examiner draws the conclusions. Codes are a stable, published contract.

| Code | Severity | What it observes |
|---|---|---|
| `BTRFS-SUPERBLOCK-CRC-MISMATCH` | High | The superblock's own crc32c does not verify — corruption or post-write tampering |
| `BTRFS-CRC-MISMATCH` | High | A metadata node/leaf whose stored crc32c does not verify |
| `BTRFS-BACKUP-ROOT-DIVERGENCE` | High | A `btrfs_root_backup` entry inconsistent with the committed generation — consistent with rollback / tampered backup roots |
| `BTRFS-IMPOSSIBLE-GEOMETRY` | High | A root/geometry field beyond what the image can hold — an allocation-bomb / corruption guard |
| `BTRFS-ORPHANED-INODE` | Medium | An `ORPHAN_ITEM` in the `FS_TREE` — an inode unlinked while open / pending cleanup, a recovery lead |

Deleted-file recovery is separate: `recover_deleted(&image)` walks an older generation's `FS_TREE` (reached through a `btrfs_root_backup` entry), diffs it against the current `FS_TREE`, and returns each carved `RecoveredFile` — name, inode, generation, size, content, and the content's sha256 recovery gate.

## The reader: navigate an image

`btrfs-core` (imported as `btrfs_core`) reads a btrfs image over any byte slice:

```rust
use btrfs_core::{Superblock, ChunkMap, read_by_path_content};

// The superblock lives at physical offset 65536; the chunk map is walked from
// the sys_chunk_array bootstrap it carries.
let sb = Superblock::parse(&image[65536..65536 + 4096])?;
let map = ChunkMap::walk(&image, &sb)?;

// Resolve a slash-separated path from the FS_TREE root to its file bytes,
// decompressing zlib / LZO / zstd extents transparently.
let bytes = read_by_path_content(&image, &sb, &map, "etc/hostname")?;
# Ok::<(), btrfs_core::BtrfsError>(())
```

The bare crate name `btrfs` on crates.io is an unrelated live-FS ioctl wrapper, so this on-disk reader publishes as `btrfs-core` and imports as `btrfs_core`.

## What makes this different from a general-purpose btrfs crate

Most btrfs crates answer one question: "what files are on this volume?" This workspace answers the questions a digital forensics examiner actually needs:

| Capability | General-purpose btrfs crate | this workspace |
|---|---|---|
| Superblock + `sys_chunk_array` bootstrap | ✅ | ✅ |
| Chunk-tree logical→physical mapping | ✅ | ✅ |
| B-tree node / leaf navigation | ✅ | ✅ |
| FS-tree inode / directory / path resolution | ✅ | ✅ |
| `EXTENT_DATA` → file content (inline / regular / prealloc / hole) | ✅ | ✅ |
| zlib / LZO / zstd extent decompression | partial | ✅ |
| crc32c metadata-node verification (per block) | — | ✅ |
| Superblock csum tamper check | — | ✅ |
| `btrfs_root_backup` divergence detection (rollback tell) | — | ✅ |
| Orphaned-inode (`ORPHAN_ITEM`) enumeration | — | ✅ |
| CoW deleted-file recovery from an older generation's FS-tree | — | ✅ |
| Impossible-geometry / allocation-bomb guards | — | ✅ |
| Severity-graded `report::Finding` output | — | ✅ |
| `#![forbid(unsafe_code)]` | — | ✅ |

## Trust but verify

- **`#![forbid(unsafe_code)]`** in both crates — no `unsafe`, no C bindings.
- **Panic-free** — every integer / length / offset field is read through bounds-checked helpers; a malformed image degrades to an empty or typed result, never a panic.
- **Fuzzed** — one `cargo-fuzz` target per parsed structure (`superblock`, `node`, `chunk`, `fstree`, `extent`, `crc`) plus a `fuzz_forensic` target driving the full `audit_image` / `recover_deleted` pipeline. `fuzz.yml` builds every target on each push and deep-fuzzes each for 10 minutes weekly.
- **Tier-1 validated** — the reader is checked against a real **Fedora Cloud** btrfs filesystem whose ground truth comes from btrfs-progs' own `btrfs inspect-internal dump-super -f` / `dump-tree`, a wholly separate implementation. See [`docs/validation.md`](https://securityronin.github.io/btrfs-forensic/validation/).

## Reader API (`btrfs-core`)

| Item | Purpose |
|---|---|
| `Superblock::parse` | Superblock geometry, tree roots, csum descriptor, `sys_chunk_array` |
| `ChunkMap::walk` / `logical_to_physical` | Full chunk-tree logical→physical map |
| `read_node` / `Node::parse` | Read / decode any `nodesize` B-tree block (header + items or key-ptrs) |
| `fs_tree_root` / `read_inode` / `list_dir` / `read_by_path` | FS-tree `ROOT_ITEM`, inode metadata, directory entries, path resolution |
| `read_file` / `read_by_path_content` | `EXTENT_DATA` → file bytes (inline / regular / prealloc / hole), truncated to size |
| `decompress_extent` | zlib / LZO / zstd extent decompression (always compiled in) |
| `superblock_crc_status` / `verify_superblock_crc32c` | crc32c superblock verification |

---

[Privacy Policy](https://securityronin.github.io/btrfs-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/btrfs-forensic/terms/) · © 2026 Security Ronin Ltd
