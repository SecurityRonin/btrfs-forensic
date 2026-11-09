# Changelog

All notable changes to `btrfs-core` (the reader) are documented here. The format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0](https://github.com/SecurityRonin/btrfs-forensic/compare/btrfs-core-v0.1.5...btrfs-core-v0.2.0) - 2026-11-09

### Added

- *(vfs)* enumerate btrfs hard links from INODE_REF back-references
- *(xattr)* GREEN - decode Btrfs XATTR_ITEM

### Build

- *(deps)* [**breaking**] record that forensic-vfs 0.10 breaks btrfs-core's vfs feature

### Fixed

- *(extent)* bound a file's assembled bytes by its size, not per extent
- *(vfs)* read a btrfs symlink under the kernel's rules, not as a file
- *(security)* state ruzstd >= 0.9.1 in btrfs-core's own manifest

### Other

- require forensic-vfs 0.9

## [0.1.5](https://github.com/SecurityRonin/btrfs-forensic/compare/btrfs-core-v0.1.4...btrfs-core-v0.1.5) - 2026-08-20

### Fixed

- *(lints)* make btrfs-core actually enforce unsafe_code ([#6](https://github.com/SecurityRonin/btrfs-forensic/pull/6))

## [0.1.3](https://github.com/SecurityRonin/btrfs-forensic/compare/btrfs-core-v0.1.2...btrfs-core-v0.1.3) - 2026-07-19

### Fixed

- *(deps)* bump forensic-vfs 0.4 -> 0.5

## [0.1.1]

- Current published reader: pure-Rust, `forbid(unsafe)`, panic-free-by-lint,
  input-fuzzed btrfs parser — superblock, B-tree nodes, chunk mapping, fs-tree,
  extents, CRC32c verification, and batteries-included zlib/zstd/LZO extent
  decompression.

<!-- release-plz appends new versions above this line, newest first. -->
