# 2. Build a from-scratch on-disk reader; reuse only leaf primitives

Date: 2026-07-24
Status: Accepted

## Context

The Research-First survey (`docs/RESEARCH.md` §2, committed in
`78aae99 docs(research): Research-First report`) evaluated the Rust and
non-Rust btrfs ecosystem before any code was written, as the fleet
Research-First discipline requires:

- `btrfs` / `btrfs2` on crates.io are **ioctl wrappers** over a *live mounted*
  filesystem — not on-disk parsers.
- `GodTamIt/btrfs-diskformat` (BSD-2) is a clean struct catalogue but only a
  struct layer, not a logical-address reader.
- `danobi/btrfs-walk` and `danobi/btrd` are the closest read-only navigators,
  but both are **GPL-2** — usable as algorithm references, not vendorable into an
  Apache-2.0 crate.
- Forensic suites offer nothing usable: TSK added btrfs in 4.13.0 (Mar 2025) then
  **reverted it as experimental in 4.14.0** (Apr 2025); there is no `libfsbtrfs`
  in libyal and no NIST CFReDS btrfs answer key.

The report's conclusion: *"No mature, maintained, read-only, permissively-licensed
Rust btrfs navigator exists. Recommendation: BUILD."* The absence of a forensic
btrfs reader is itself the differentiator this repo exists to fill.

## Decision

Implement the reader from scratch in `btrfs-core`, transcribing struct layouts
byte-exact from the btrfs-progs UAPI headers (`btrfs_tree.h`, `ctree.h`) and the
on-disk-format docs (RESEARCH.md §1). Reuse the ecosystem **only for audited
leaf primitives** where a correct crate already exists (Research-First
build-vs-reuse, and the fleet "prefer our own / reuse-audited-crypto" rules):

- checksums: the `crc` crate for crc32c (Castagnoli) — `core/src/crc.rs`;
- decompression: `flate2` (zlib, pure-Rust miniz_oxide backend), `ruzstd`
  (pure-Rust zstd), `lzo` (bounds-checked pure-Rust LZO1X) — see ADR 0008.

GPL references (`btrfs-walk`, `btrd`) were read, never vendored; `btrfs-progs`
`btrfs inspect-internal dump-super`/`dump-tree` serves as the independent
structural oracle (ADR unnumbered — see `docs/validation.md`).

## Consequences

The repo owns a complete logical-address btrfs navigator with no C bindings and
no copyleft contamination, publishable under Apache-2.0. The cost is carrying the
hardest part of the format ourselves — the chunk-tree logical→physical bootstrap
and `(objectid,type,offset)` key ordering (RESEARCH.md §4 ranks both as the
highest-risk, silently-wrong-not-loud items), which ADR 0006 and the Tier-1
Fedora oracle exist to gate. Single-device (single/DUP) geometry is implemented;
RAID profiles are deferred (RESEARCH.md §4).
