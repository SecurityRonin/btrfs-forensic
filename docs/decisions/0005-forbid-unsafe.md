# 5. `#![forbid(unsafe_code)]` fleet-wide, no C bindings

Date: 2026-07-24
Status: Accepted

## Context

Both crates parse untrusted, attacker-controllable disk images — the exact
threat surface the fleet Paranoid Gatekeeper standard and the global unsafe-code
law address. The unsafe law makes `forbid(unsafe)` the default *and* the goal: a
provable "zero places a crafted input can corrupt memory," downgraded to
`deny` + a bounded per-site `#[allow]` only when a real benefit (e.g. an mmap
scanner, as in `ewf`/`memf`) justifies surrendering the compiler's guarantee.

`btrfs-core`'s traversal API operates on an in-memory `&[u8]` (`vfs.rs` notes
`open` reads the whole source into memory once), so there is **no mmap or FFI
requirement** to justify any downgrade. Every dependency chosen for leaf
primitives is pure-Rust (ADR 0002/0008): `crc`, `flate2`+miniz_oxide, `ruzstd`,
`lzo` — none pulls a C `-sys` crate.

## Decision

Set `unsafe_code = "forbid"` at the workspace level
(`Cargo.toml [workspace.lints.rust]`) and repeat `#![forbid(unsafe_code)]` at the
crate root of both `core/src/lib.rs` and `forensic/src/lib.rs`. There are no
`#[allow(unsafe_code)]` sites anywhere; `rg 'allow(unsafe_code)'` is empty. The
crates therefore legitimately wear the README `unsafe forbidden` badge (unlike
the mmap crates, which the fleet README standard says must *skip* it).

## Consequences

A malformed image cannot reintroduce the C/C++ memory-corruption / RCE class that
safe Rust deletes by construction; the guarantee is compiler-proved, not
asserted. The panic-free posture is the runtime complement (ADR 0006 +
`unwrap_used`/`expect_used = deny` + one fuzz target per parsed structure). The
constraint is that any future need touching mmap or a C decoder would require a
deliberate `forbid`→`deny`+bounded-`allow` downgrade with a written cost-benefit
justification, not a silent edit — which is the intended friction.
