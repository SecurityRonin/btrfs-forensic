# 8. Batteries-included decompression and the 1.87 MSRV floor it dictates

Date: 2026-07-24
Status: Accepted

## Context

btrfs stores file content zlib-, LZO-, or zstd-compressed per extent
(`compression` byte `1`/`2`/`3` in `btrfs_file_extent_item`, RESEARCH.md §1(f)).
An examiner reading a compressed file must get the decoded bytes from the
zero-config path — the fleet Batteries-Included policy bans `default-features =
false` slimming and any capability behind a feature the analyst must know to
enable.

Two forces meet here:

- **Pure-Rust, no C FFI** — required to keep `forbid(unsafe)` (ADR 0005). So the
  decoders are `flate2` with the miniz_oxide backend (zlib), `ruzstd` (zstd), and
  `lzo` (a safe bounds-checked LZO1X), with btrfs's per-sector LZO framing applied
  on top in `core/src/extent.rs`.
- **MSRV** — the fleet library floor is normally `1.75`/`1.80`, but `ruzstd 0.8`
  declares `rust-version = 1.87`. The batteries-included pure-Rust zstd decoder,
  not our own code, dictates the floor.

## Decision

Compile all three decoders in **always** (never feature-gated) —
`core/Cargo.toml` declares `flate2`, `ruzstd`, `lzo` as unconditional
dependencies; `decompress_extent` (`extent.rs`) dispatches on the compression
byte; the RED/GREEN pair `6ca2360`/`f8e85e2` ("EXTENT_DATA file-content +
batteries-in decoders") landed them. Per "MSRV yields to capability," **take the
`1.87` floor** rather than feature-gate zstd to advertise a lower one. The floor
is declared once at `Cargo.toml [workspace.package] rust-version = "1.87"` with an
inline comment recording that `ruzstd 0.8` is the cause, and is CI-verified by the
`msrv` job.

## Consequences

A single static build decodes any btrfs extent an examiner encounters, with no C
toolchain and no feature flags — consistent with `forbid(unsafe)` and the
zero-config-capability rule. The trade-off is a higher MSRV (`1.87`) than the
usual fleet library floor, narrowing the crate's compiler audience; this is the
accepted price of the always-on zstd path, and the decision to raise it is tied to
a specific dependency so it is revisited only if that dependency's floor moves.
