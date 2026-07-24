# 1. Reader / analyzer two-crate split (`core/` + `forensic/`)

Date: 2026-07-24
Status: Accepted

## Context

btrfs work divides into two concerns with different audiences and different
robustness postures. One is *reading* a valid btrfs image — superblock and
`sys_chunk_array` bootstrap, chunk-tree logical→physical mapping, B-tree
navigation, FS-tree inode/directory/path resolution, and `EXTENT_DATA` → file
content with decompression. The other is *auditing* — turning the parsed
structures (and the raw bytes a happy-path reader normalizes away) into
severity-graded forensic findings and recovering CoW-deleted files.

The SecurityRonin fleet Crate-structure standard (`ronin-issen/CLAUDE.md`,
"Crate-structure standard — reader/analyzer split") makes this split binding for
every format: one workspace repo named `<x>-forensic`, a `core/` crate that is
the raw reader (no findings) and a `forensic/` crate that is the anomaly
auditor emitting `forensicnomicon::report::Finding`. `ntfs-forensic` /
`vmdk-forensic` are the reference implementations.

## Decision

Ship one workspace (`Cargo.toml` `members = ["core", "forensic"]`) with two
independently-versioned members:

- **`btrfs-core`** (`core/`, version `0.1.x`) — the pure reader: `Superblock`,
  `ChunkMap`, `Node`, FS-tree navigation, `read_by_path_content`,
  `decompress_extent`. No findings, no severity vocabulary.
- **`btrfs-forensic`** (`forensic/`, version `0.1.x`) — the auditor:
  `AnomalyKind`/`Anomaly` + `audit_image`/`audit_findings`/`recover_deleted`,
  each anomaly converting to a `report::Finding` via `impl Observation`
  (`forensic/src/lib.rs:267`).

`btrfs-forensic` depends on `btrfs-core` (workspace path dep pinned to a
registry version — `[workspace.dependencies] btrfs-core = { path = "core",
version = "0.1.3" }`), but also parses some raw superblock bytes directly where
the reader does not surface them (the `btrfs_root_backup` array — see the
`forensic/src/lib.rs` `parse_backup_roots` path and ADR 0006). This follows the
fleet principle that `-forensic` *prefers* `-core` yet may go lower when the
reader's normalized view hides the very anomaly the audit hunts.

## Consequences

A Rust consumer that only needs to read a btrfs volume depends on `btrfs-core`
alone and never compiles the finding/severity machinery. The auditor evolves its
anomaly catalogue without touching the reader's API. The two crates version
independently, so a reader bug-fix and an auditor feature cut separate releases.
The cost is the standard two-crate overhead (two manifests, two changelogs,
inter-crate version bookkeeping), accepted fleet-wide.
