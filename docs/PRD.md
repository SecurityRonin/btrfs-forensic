# btrfs-forensic — Design, Purpose & Scope

This is a **library** design note (not a PRD): `btrfs-forensic` ships no binary
an examiner runs. It is two linked crates — a reader and an auditor — consumed by
fleet orchestration (Issen / disk4n6) and by third-party Rust tools. For the
per-decision rationale see [`docs/decisions/`](decisions/); for the evidentiary
tiers see [`docs/validation.md`](validation.md); for the format survey see
[`docs/RESEARCH.md`](RESEARCH.md).

## Purpose

Give the fleet a pure-Rust, from-scratch btrfs on-disk reader and a graded
anomaly auditor over it, so a btrfs volume's structure and its
copy-on-write history become evidence that aggregates uniformly with the
partition and container layers. The forensic ecosystem has no usable btrfs
reader — TSK reverted btrfs to experimental in 4.14.0, libyal has no
`libfsbtrfs`, and there is no NIST CFReDS btrfs answer key (RESEARCH.md §2) — so
this repo fills a genuine gap rather than reimplementing an existing wheel
(ADR 0002).

## Users

- **Fleet orchestration** (`btrfs-core` → `forensic-vfs` mount via the `vfs`
  feature; `btrfs-forensic` → `forensicnomicon::report::Finding` aggregated into
  one `Report`).
- **Rust developers** who want an on-disk btrfs navigator over any `&[u8]`
  without a live mount, C bindings, or GPL contamination.
- **Forensic examiners**, indirectly, through the front ends that consume the
  findings — this crate emits *observations* ("consistent with …"); the examiner
  draws the conclusions.

## What it does

**`btrfs-core`** (the reader — imported as `btrfs_core`, ADR 0003):

- superblock parse at physical offset 65536 + `sys_chunk_array` bootstrap;
- chunk-tree logical→physical mapping (`ChunkMap`), single-device single/DUP;
- B-tree node/leaf navigation honoring `(objectid, type, offset)` key ordering
  (ADR 0006);
- root-tree → FS-tree inode / directory / path resolution (`read_by_path`);
- `EXTENT_DATA` → file content (inline / regular / prealloc / hole), decompressing
  zlib / LZO / zstd extents always-on (ADR 0008);
- crc32c superblock and metadata-node verification.

**`btrfs-forensic`** (the auditor):

- **F-INTEGRITY** (`audit_image` / `audit_findings`) — graded findings for
  structural anomalies. Published anomaly codes (a stable contract):
  `BTRFS-SUPERBLOCK-CRC-MISMATCH`, `BTRFS-CRC-MISMATCH`,
  `BTRFS-BACKUP-ROOT-DIVERGENCE`, `BTRFS-ORPHANED-INODE`,
  `BTRFS-IMPOSSIBLE-GEOMETRY`.
- **F-CARVE** (`recover_deleted`) — walks an older generation's `FS_TREE` reached
  through a `btrfs_root_backup` entry, diffs it against the current `FS_TREE`, and
  returns each carved `RecoveredFile` with a sha256 recovery gate
  (`BTRFS-DELETED-FILE-CARVED`).

## Scope

Single-device btrfs images (single / DUP block-group geometry), read-only, over an
in-memory byte source. crc32c checksums; zlib / LZO / zstd compression. The CoW
model — per-block generations and `btrfs_root_backup` point-in-time root sets — is
the forensic lever for rollback detection and deleted-file recovery.

## Non-goals

- **No RAID profiles** (RAID0/1/10/5/6/1c3/1c4) and no multi-device images —
  deferred (RESEARCH.md §4); a multi-stripe logical address is out of scope until
  a later phase.
- **No writing** — read-only; the carver emits recovered content to the caller,
  never back to the source.
- **No live-filesystem ioctls** — that is the unrelated `btrfs` crate's job
  (ADR 0003); this reader is strictly on-disk.
- **No streaming reader yet** — traversal buffers the whole image
  (`vfs.rs` documents this); a streaming path is future `btrfs-core` work.
- **No non-crc32c csum verification path** and **no interior root-tree descent
  beyond the FS-tree root leaf yet** — documented current limits, surfaced as
  empty/typed results, never panics.
- **No CLI / GUI / MCP binary** — front ends live in orchestration
  (disk4n6 / Issen); this is a library.

## Validation approach

Evidence is tiered by *who authored the artifact and its answer key*
(`docs/validation.md`):

- **Tier-1** — the reader is validated against a real third-party **Fedora Cloud
  Base 41** btrfs filesystem, ground-truthed by btrfs-progs'
  `btrfs inspect-internal dump-super -f` / `dump-tree` (a wholly separate
  implementation). Env-gated (`BTRFS_FEDORA_ORACLE`), gitignored, skips cleanly
  when absent.
- **Tier-2** — self-minted `mkfs.btrfs` fixtures as fast deterministic regression
  backstops, cross-checked at mint time against the same independent decoder.
- **Panic-free posture** — `forbid(unsafe)` (ADR 0005), bounds-checked readers
  (ADR 0006/0007), the workspace `unwrap_used`/`expect_used = deny` lints (active
  on `btrfs-forensic`, which opts in via `[lints] workspace = true`; `btrfs-core`
  does not opt in, so its panic-freedom rests on `forbid(unsafe)` + the
  bounds-checked readers + fuzzing — see ADR 0007), and one `cargo-fuzz` target
  per parsed structure (`superblock`, `node`, `chunk`, `fstree`, `extent`, `crc`)
  plus a `fuzz_forensic` target over the full `audit_image` / `recover_deleted`
  pipeline.
