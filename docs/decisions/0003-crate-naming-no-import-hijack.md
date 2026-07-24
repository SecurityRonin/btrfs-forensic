# 3. Crate names `btrfs-core` / `btrfs-forensic`, no import-path hijack of `btrfs`

Date: 2026-07-24
Status: Accepted

## Context

The bare crate name `btrfs` on crates.io is already taken by a *maintained
third-party* ioctl wrapper (`btrfs` 1.2.2, "Interface for BTRFS ioctls etc" —
RESEARCH.md §2, and the comment at `core/Cargo.toml`). The fleet Crate-naming
grammar (`ronin-issen/CLAUDE.md`) governs this collision:

- a single-format reader/analyzer repo is Pattern A: exactly `<x>-core` +
  `<x>-forensic`;
- when the bare `<x>` name is a *popular / maintained* crate, do **not** hijack
  the import path with a `[lib] name = "<x>"` override — keep `<x>_core`
  (the reference case is `ntfs-core` importing as `ntfs_core`, deliberately not
  shadowing Colin Finck's `ntfs`).

## Decision

Publish the reader as **`btrfs-core`** and the analyzer as **`btrfs-forensic`**,
with **no `[lib] name` override** — consumers write `use btrfs_core::…`
(`core/src/lib.rs` documents this; `core/Cargo.toml` carries the rationale
comment and omits any `[lib]` stanza). The on-disk reader is therefore never
confused on crates.io with the live-FS `btrfs` ioctl crate, and that crate's
import path is left untouched.

The repo also follows the fleet release grammar downstream of this name: the
`v[0-9]*` binary-release trigger is avoided for library tags, and
`release-plz.toml` sets `git_tag_name = "<crate>-vX.Y.Z"`
(`8f0df9a ci(release-plz): set git_tag_name to <crate>-vX.Y.Z form (avoid v*
binary-tag collision)`), keeping per-crate library tags off the binary-tag glob.

## Consequences

Both crates self-describe on crates.io without claiming a namespace that belongs
to an unrelated maintained crate, and existing users of the `btrfs` ioctl crate
are unaffected. Documentation and examples must consistently use the `btrfs_core`
import path (the README and `lib.rs` do). The mild cost is the slightly longer
import name versus a bare `btrfs`, accepted to avoid the hijack.
