#!/bin/bash
# Regenerates results/<label>.tar.gz : what real apt makes of every scenario in
# scenarios/ over the repository in lists/ and the dpkg states in status/.
#
# Needs podman or docker and network access to pull the image. Run from
# anywhere:
#
#   deb/apt/testdata/policy/generate.sh
#
# IMAGES selects "label=image" pairs (default: bookworm, trixie and unstable
# Debian). SCENARIOS limits the run to some scenario names.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
engine=${CONTAINER_ENGINE:-$(command -v podman || command -v docker)}

images=${IMAGES:-"bookworm=docker.io/library/debian:bookworm trixie=docker.io/library/debian:stable-slim unstable=docker.io/library/debian:unstable-slim"}

for entry in $images; do
	label=${entry%%=*}
	image=${entry#*=}
	work=$(mktemp -d)
	mkdir -p "$work/scenarios"
	"$engine" run --rm \
		-e "SCENARIOS=${SCENARIOS:-}" \
		-v "$work:/out:Z" \
		-v "$here/container.sh:/container.sh:Z,ro" \
		-v "$here/lists:/repo/lists:Z,ro" \
		-v "$here/status:/repo/status:Z,ro" \
		-v "$here/sources.list:/repo/sources.list:Z,ro" \
		-v "$here/scenarios:/scenarios:Z,ro" \
		"$image" bash /container.sh
	echo "image-reference: $image" >>"$work/MANIFEST"
	mkdir -p "$here/results"
	# One reproducible archive per image keeps the tree small: results/<label>.tar.gz
	# holds MANIFEST and scenarios/<name>/<file>.
	rm -rf "$here/results/$label" "$here/results/$label.tar.gz"
	tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$work" -cf - MANIFEST scenarios |
		gzip -n -9 >"$here/results/$label.tar.gz"
	rm -rf "$work"
done
