# 7. Hand-rolled bounds-checked readers instead of the fleet `safe-read` crate

Date: 2026-07-24
Status: Accepted

## Context

The fleet Paranoid Gatekeeper standard (`ronin-issen/CLAUDE.md`, "Security &
Robustness Standard") is explicit: every integer field read should route through
the published **`safe-read`** crate — the fleet's single audited, `no_std`,
`forbid(unsafe)`, fuzzed implementation — and crates must **NEVER hand-roll a
per-crate `bytes.rs`**, because hand-rolled copies drift and some
`data.get(off..off+N)` variants can overflow `usize` where `safe-read`'s
`checked_add` cannot.

`btrfs-core` does **not** use `safe-read`. It carries its own
`core/src/bytes.rs` with `le_u16`/`le_u32`/`le_u64`/`u8_at`, each returning `0`
when the requested range lies outside the buffer. There is no reference to
`safe-read` anywhere in the repo (`Cargo.toml`, `Cargo.lock`, sources), and the
git history contains no commit discussing the choice — the module is present from
the first `020b55c`/`79cb38c` P0 superblock commits onward.

## Decision

Record the *as-built* state: `btrfs-core` reads fixed-width fields through the
local `core/src/bytes.rs` helpers rather than the fleet `safe-read` crate. The
helpers are bounds-checked via `slice::get(off..off+N)` and yield `0` out of
range, so they satisfy the *robustness intent* of the Paranoid Gatekeeper
standard (no panic on truncated/malformed input, backed by `#![forbid(unsafe_code)]`
and the per-structure fuzz targets).

Note the workspace `unwrap_used`/`expect_used = deny` lints do **not** apply to
`btrfs-core`: unlike `forensic/Cargo.toml`, `core/Cargo.toml` omits
`[lints] workspace = true`, so those denies gate only `btrfs-forensic`.
`btrfs-core`'s panic-freedom therefore rests on `#![forbid(unsafe_code)]`
(`core/src/lib.rs`), the bounds-checked `bytes.rs` readers, and the fuzz
targets — not on the deny lints.

**Rationale reconstructed from structure; original intent not recovered in
available history.** Why this crate hand-rolled `bytes.rs` instead of adopting
`safe-read` — whether `safe-read` predated it, was overlooked, or was
deliberately declined — is not recoverable from the commit log. This ADR does not
invent one.

## Consequences

The reader is panic-free and fuzzed, so the *safety* goal is met. But the crate
sits outside the fleet's single-audited-implementation guarantee and carries the
exact drift/`usize`-overflow risk the standard exists to prevent: the local
`off + N` expressions are not `checked_add`, so a caller passing an
attacker-derived near-`usize::MAX` offset could wrap (the fuzz targets and the
Tier-1 oracle are the current backstop). **Follow-up:** evaluate migrating
`core/src/bytes.rs` to `safe-read` (a `forensic-vfs` transitive re-export is
already available) to bring the crate onto the audited path and close the
overflow gap; this is flagged, not yet done.
