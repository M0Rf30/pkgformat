#!/bin/bash
# Regenerates expected.tsv: the file names that a real `apt-get update` gives
# the files of repositories reached through many kinds of URIs. It needs
# podman or docker and network access (to install python3, gnupg and apt-utils
# into the container); nothing is fetched from the internet by apt itself, the
# repositories are served from inside the container. Run from anywhere:
#
#   deb/apt/testdata/sources/listnames/generate.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
engine=${CONTAINER_ENGINE:-$(command -v podman || command -v docker)}
image=${IMAGE:-docker.io/library/debian:stable-slim}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$engine" run --rm \
	-v "$work:/out:Z" \
	-v "$here/container.sh:/container.sh:Z,ro" \
	"$image" bash /container.sh

cp "$work/expected.tsv" "$here/expected.tsv"
cp "$work/MANIFEST" "$here/MANIFEST"
echo "image-reference: $image" >>"$here/MANIFEST"
