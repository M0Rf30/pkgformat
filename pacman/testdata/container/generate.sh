#!/bin/sh
# Regenerates this directory. Needs podman, the go toolchain and the image
# docker.io/library/archlinux:latest already pulled.
#
#   ./generate.sh
#
# The package is written by this module (shapesSpec in container_test.go) and
# installed with the pacman of the container (pacman -U, as root of a user
# namespace, so that owners, hard links, pipes, xattrs and file capabilities
# take effect). What came out is kept here:
#
#   shapes-1.0-1-any.pkg.tar.zst  the package this module wrote
#   local/shapes-1.0-1/           desc, files and mtree that pacman wrote for it
#   qkk-clean.expected            pacman -Qkk right after the install
#   files.expected                stat and getfattr of the installed files
#   qkk-tampered.expected         pacman -Qkk after the files were altered
set -eu

cd "$(dirname "$0")/../.."
PKGFORMAT_UPDATE_FIXTURES=1 go test -count=1 -run '^TestPacmanInstallsSpecialFilesInContainer$' .
