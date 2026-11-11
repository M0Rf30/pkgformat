# Package installed by pacman in a container

`shapes-1.0-1-any.pkg.tar.zst` is written by this module (`shapesSpec` in
`container_test.go`): a hard link, a symbolic link, a pipe, a setuid file, a
file with `security.capability`, a file with a `user.shape` xattr, files owned
by 1234:5678 and a sticky directory with that owner. `generate.sh` installs it
with `pacman -U` in an `archlinux:latest` container (pacman 7.1.0, rootless
podman, so the container's root and the owners 1234:5678 exist in its user
namespace), alters some files, and keeps what came out.

| File | Content |
| --- | --- |
| `shapes-1.0-1-any.pkg.tar.zst` | the package |
| `local/shapes-1.0-1/` | the `desc`, `files` and `mtree` pacman wrote for it |
| `qkk-clean.expected` | `pacman -Qkk` right after the install: 0 altered files |
| `files.expected` | `stat` and `getfattr` of the installed files: owners, link count, modes, the capability |
| `qkk-tampered.expected` | `pacman -Qkk` after a content change, a chown, a chmod, a removal and an edit of the backup file |

`TestPacmanInstallsSpecialFilesInContainer` also builds the test binary and
runs it inside the container, where `LocalDB.VerifyInstalled` reads the
database pacman just wrote, and has to report the same paths as `pacman -Qkk`.
