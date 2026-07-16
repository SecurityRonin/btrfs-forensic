# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning is
[SemVer](https://semver.org/spec/v2.0.0.html). `btrfs-core` and `btrfs-forensic`
are versioned independently.

## btrfs-core 0.1.1 — 2026-07-16

### Changed

- Migrate to `forensic-vfs` 0.3 (from 0.1). The re-exported `FsKind` is now
  forensicnomicon's newtype, so the vfs adapter identifies btrfs as
  `FsKind::BTRFS` (was the `FsKind::Other` placeholder — the newtype has no
  `Other`).

## btrfs-forensic 0.1.1 — 2026-07-16

### Changed

- Bump `btrfs-core` dependency to 0.1.1 (forensic-vfs 0.3 migration).
