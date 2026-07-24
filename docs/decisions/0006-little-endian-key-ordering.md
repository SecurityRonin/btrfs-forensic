# 6. Little-endian on-disk decoding and `(objectid, type, offset)` key ordering

Date: 2026-07-24
Status: Accepted

## Context

btrfs is little-endian on disk throughout, and every B-tree — the chunk tree, the
root tree, and each FS tree — sorts its items by the `btrfs_key` **tuple**
`(objectid, type, offset)`, compared on host-integer values (fields stored LE,
compared as `u64`/`u8`). RESEARCH.md §1(d) and §4 flag two silently-wrong-not-loud
correctness hazards that the *structure* of the format forces, not a matter of
taste:

1. the chunk-tree logical→physical mapping
   `physical = stripe.offset + (logical − chunk_key.offset)` — a subtle offset
   error yields plausible-but-wrong reads (the "LZNT1-trap" zone);
2. key comparison — *"comparing raw LE bytes, or reordering type/offset, silently
   mis-navigates"* while looking fine on small images.

Both must be pinned to an independent oracle from day one, and both are decisions
about *how bytes are interpreted*, so they belong in the record.

## Decision

Decode all on-disk integers as little-endian and compare keys strictly as the
integer tuple `(objectid, type, offset)`, never as raw byte slices. Fixed-width
field reads go through the bounds-checked LE helpers in `core/src/bytes.rs`
(`le_u16`/`le_u32`/`le_u64`/`u8_at`, which yield `0` out of range) — see ADR 0007
for the reader implementation choice. Interior descent and leaf binary search in
`core/src/node.rs` order on the decoded tuple. Struct field offsets are
transcribed byte-exact from the btrfs-progs UAPI headers (RESEARCH.md §1).

Correctness is gated against `btrfs inspect-internal dump-tree`/`dump-super`
(btrfs-progs, a wholly separate implementation) on a real Fedora Cloud 41 image
(Tier-1, env-gated) plus self-minted Tier-2 backstops — `docs/validation.md`,
and the RED/GREEN commit pairs `542f4d6`/`ee35fcf` (P1 chunk map) and
`bde0e9d`/`5e47880` (P2 root/FS-tree navigation).

## Consequences

Navigation matches the reference decoder on real data, closing the two
highest-risk failure modes the research identified before they could ship green.
The mapping is deliberately scoped to single-device single/DUP geometry; RAID
striping is deferred (RESEARCH.md §4), so a multi-stripe logical address is out of
scope until a later phase. The correctness claim rests on the Tier-1 oracle, not
on self-authored fixtures alone.
