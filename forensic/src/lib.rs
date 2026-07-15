//! `btrfs-forensic` — anomaly auditor for btrfs filesystems.
//!
//! Scaffold only (Phase 0). btrfs is an everything-is-CoW-B-tree design, so the
//! forensic layer's differentiators — stale-root / older-generation tree-block
//! recovery (point-in-time reconstruction via CoW), deleted-file carving from
//! freed-but-unoverwritten tree blocks, snapshot diffing, and integrity findings
//! (`EXTENT_CSUM` mismatch, superblock-mirror divergence, generation
//! inconsistency) — arrive in later phases, once the core reader can navigate
//! the chunk tree and B-tree nodes.
//!
//! Each finding will be an **observation** ("consistent with …"), emitted as a
//! [`forensicnomicon::report::Finding`] via the fleet producer pattern
//! (typed `AnomalyKind` + `impl Observation`), mirroring `xfs-forensic` /
//! `ntfs-forensic`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub use forensicnomicon::report::Severity;
