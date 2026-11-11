#!/bin/bash
# Regenerates the fixtures of the differential tests against apt:
#
#   lists/        the Packages indexes of a debian container, trimmed to the
#                 closure of every package the scenarios below name (see
#                 trim/main.go)
#   status        its dpkg status database, verbatim
#   expected.tsv  what `apt-get -s install --no-install-recommends <target>`
#                 plans for every line of targets.txt (record.sh documents the
#                 format)
#   installed/    the same container after installing installed/preinstall.txt:
#                 its status and what apt plans for installed/scenarios.txt,
#                 which has to remove or replace packages
#   worlds/       synthetic package universes (Packages, status, optionally
#                 preferences and holds, scenarios.txt) and what apt plans for
#                 their scenarios, in worlds/<name>/expected.tsv
#   MANIFEST      which image and apt produced them
#
# The first two come from the live archive and change from day to day; the
# worlds are fixed input and only expected.tsv is regenerated, so a different
# apt shows up as a diff of it. Needs podman or docker, and network access for
# the archive part (SKIP_ARCHIVE=1 regenerates only the worlds). Run from
# anywhere:
#
#   deb/apt/testdata/diff/generate.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
engine=${CONTAINER_ENGINE:-$(command -v podman || command -v docker)}
image=${IMAGE:-docker.io/library/debian:stable-slim}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

if [ -z "${SKIP_ARCHIVE:-}" ]; then
	"$engine" run --rm \
		-v "$work:/out:Z" \
		-v "$here/container.sh:/container.sh:Z,ro" \
		-v "$here/record.sh:/record.sh:Z,ro" \
		-v "$here/targets.txt:/targets.txt:Z,ro" \
		-v "$here/installed:/installed:Z,ro" \
		"$image" bash /container.sh

	# Everything the scenarios name is a root of the trimmed closure.
	{
		cat "$here/targets.txt" "$here/installed/preinstall.txt"
		awk -F'\t' '!/^#/ && NF > 1 { n = split($2, w, " "); for (i = 2; i <= n; i++) if (w[i] !~ /^-/) print w[i] }' \
			"$here/installed/scenarios.txt"
	} >"$work/roots.txt"

	rm -rf "$here/lists"
	mkdir -p "$here/lists"

	(cd "$root" && go run ./deb/apt/testdata/diff/trim \
		-lists "$work/lists" -status "$work/installed/status" -targets "$work/roots.txt" -out "$here/lists")

	cp "$work/status" "$here/status"
	cp "$work/expected.tsv" "$here/expected.tsv"
	cp "$work/installed/status" "$here/installed/status"
	cp "$work/installed/expected.tsv" "$here/installed/expected.tsv"
	cp "$work/MANIFEST" "$here/MANIFEST"
	echo "image-reference: $image" >>"$here/MANIFEST"
fi

"$engine" run --rm \
	-v "$work:/out:Z" \
	-v "$here/worlds:/worlds:Z,ro" \
	-v "$here/record.sh:/record.sh:Z,ro" \
	-v "$here/container-worlds.sh:/container-worlds.sh:Z,ro" \
	"$image" bash /container-worlds.sh

for world in "$here"/worlds/*/; do
	cp "$work/worlds/$(basename "$world")/expected.tsv" "$world/expected.tsv"
done
