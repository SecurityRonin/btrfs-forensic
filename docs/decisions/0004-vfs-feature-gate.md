# 4. `forensic-vfs` FileSystem adapter behind an optional `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet VFS standard (`ronin-issen/CLAUDE.md`, "VFS & Universal Container
Abstraction") wants every filesystem reader to implement the `forensic-vfs`
`FileSystem` contract so a whole stack (`E01 → GPT → … → btrfs`) reads as one
`Arc<dyn ImageSource>` that consumers share without knowing one filesystem from
another. `btrfs-core` gained that adapter (`core/src/vfs.rs`, `BtrfsFs`;
`63388ca test(vfs): RED` → `4ce3683 feat(vfs): GREEN`).

But `forensic-vfs` pulls a non-trivial dependency graph. `btrfs-core` is also a
bare on-disk *parser* that many consumers want without any VFS/mount machinery
(ADR 0001's "reader alone" audience). Forcing every `btrfs-core` dependent to
compile `forensic-vfs` would violate the reader's minimal-surface intent.

## Decision

Gate the `forensic-vfs` adapter behind an **optional, non-default `vfs`
feature** (`core/Cargo.toml`: `vfs = ["dep:forensic-vfs"]`, and
`forensic-vfs = { version = "0.7", optional = true }`). The bare parser builds
with no VFS dependency; a consumer that wants to mount a btrfs image opts in with
`features = ["vfs"]`. `core/src/lib.rs` gates the module with
`#[cfg(feature = "vfs")] pub mod vfs;`.

This is the deliberate, narrow batteries-included exception: the fleet default is
to compile capability *in*, but a genuinely optional, rarely-wanted *mount
integration* whose whole point is the extra dependency graph is exactly the
sanctioned "named non-default feature for outside consumers" case. The
*decode/analysis* capability (decompression) stays always-on (ADR 0008); only the
VFS mount surface is gated.

## Consequences

`btrfs-core` stays lean for the parser-only audience while still satisfying the
fleet VFS contract for mount consumers (identifying as `FsKind::BTRFS` after the
`forensic-vfs 0.3+` migration — `47352f7`, `f718ad6 fix(deps): bump forensic-vfs
to 0.7`). Known limits are documented in `vfs.rs` (whole-image buffering; only
the FS-tree root leaf is currently reachable; empty extent map) rather than
hidden. The cost is a feature-matrix axis CI must cover (`--all-features`) and the
periodic `forensic-vfs` version bumps the git log shows.
