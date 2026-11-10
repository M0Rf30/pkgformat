#!/bin/bash
# Regenerates the fixture of the differential test against apt:
#
#   lists/      the Packages indexes of a debian container, trimmed to the
#               closure of targets.txt (see trim/main.go)
#   status      its dpkg status database, verbatim
#   expected.tsv  what `apt-get install -s --no-install-recommends <target>`
#               plans for every target: target, Inst|Remv, package, version
#   MANIFEST    which image and apt produced them
#
# Needs podman or docker, and network access. Run from anywhere:
#
#   deb/apt/testdata/diff/generate.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
engine=${CONTAINER_ENGINE:-$(command -v podman || command -v docker)}
image=${IMAGE:-docker.io/library/debian:stable-slim}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

"$engine" run --rm \
	-v "$work:/out:Z" \
	-v "$here/container.sh:/container.sh:Z,ro" \
	-v "$here/targets.txt:/targets.txt:Z,ro" \
	"$image" bash /container.sh

rm -rf "$here/lists"
mkdir -p "$here/lists"

(cd "$root" && go run ./deb/apt/testdata/diff/trim \
	-lists "$work/lists" -status "$work/status" -targets "$here/targets.txt" -out "$here/lists")

cp "$work/status" "$here/status"
cp "$work/expected.tsv" "$here/expected.tsv"
cp "$work/MANIFEST" "$here/MANIFEST"
echo "image-reference: $image" >>"$here/MANIFEST"
