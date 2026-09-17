

#### btrfs_xattr_leaf.bin — raw FS_TREE leaf, 16384 bytes

- **Source / Identity:** the FS_TREE leaf (logical `30457856`, `owner 5`,
  `level 0`, 16 items) lifted out of a self-minted 120 MiB Btrfs filesystem
  created with `mkfs.btrfs` and populated through a real Linux mount.
- **Why only the leaf:** matches the existing `btrfs_fs_tree_leaf.bin`
  convention — 16 KiB instead of a 120 MiB image, and the leaf is the entire
  structure under test.
- **Generator (verbatim)** — run inside the podman machine VM, which has a real
  kernel and loop devices; a container cannot `mount -o loop` even with
  `--privileged`.

  ```sh
  dd if=/dev/zero of=btrfs_xattr.img bs=1M count=120
  mkfs.btrfs -q -f -L XATTRTEST btrfs_xattr.img
  mount -o loop btrfs_xattr.img /mnt/btr
  echo 'hello btrfs' > /mnt/btr/file.txt
  setfattr -n user.small   -v 'tiny-value'         /mnt/btr/file.txt
  setfattr -n user.comment -v 'a second attribute' /mnt/btr/file.txt
  setfattr -n trusted.t    -v 'trusted-value'      /mnt/btr/file.txt
  setfattr -n user.big -v "$(python3 -c 'import sys;sys.stdout.write("B"*2000)')" /mnt/btr/file.txt
  mkdir /mnt/btr/adir
  setfattr -n user.ondir -v 'on-a-directory' /mnt/btr/adir
  sync; umount /mnt/btr
  # leaf located by finding a known attribute name and rounding down to the
  # 16384-byte nodesize boundary, then verified via its own header
  # (owner == 5, level == 0) before extraction.
  ```

- **`SELinux` was enforcing on the build host**, so the kernel added its own
  `security.selinux` label to both nodes. Kept deliberately: it is exactly the
  attribute a forensic reader must not lose, and it supplies a second real
  namespace.
- **Contents** — 7 `XATTR_ITEM`s across two inodes, INTERLEAVED in the leaf,
  which is what makes the per-inode scoping test meaningful:

  | objectid | attribute | `data_len` |
  |---|---|---|
  | 257 (`file.txt`) | `user.small` | 10 |
  | 257 | `user.comment` | 18 |
  | 257 | `trusted.t` | 13 |
  | 257 | `user.big` | 2000 |
  | 257 | `security.selinux` | 37 |
  | 258 (`adir`) | `user.ondir` | 14 |
  | 258 | `security.selinux` | 37 |

- **Ground truth:** `btrfs inspect-internal dump-tree -t 5` printed every item
  with its `itemsize`, `data_len`, `name_len` and name; `getfattr -d -m '-'`
  read the values back through the kernel while mounted. The oracle is
  btrfs-progs and the Linux driver, not this crate.
- **The 30-byte `btrfs_dir_item` prefix is confirmed by arithmetic**, not
  assumed: `itemsize == 30 + name_len + data_len` holds for every item above
  (50 = 30+10+10, 2038 = 30+8+2000, 83 = 30+16+37).
- **Redistribution:** none — self-minted, no third-party data.
- **MD5:** `97c9d4bff8c1d2aa6fa196fb8b4bf69d`
- **Used by:** `core/tests/xattr.rs`
