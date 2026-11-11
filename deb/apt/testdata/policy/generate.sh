#!/bin/bash
# Regenerates results/<label>/ : what real apt makes of every scenario in
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
	rm -rf "$here/results/$label"
	mkdir -p "$here/results"
	mv "$work" "$here/results/$label"
	echo "image-reference: $image" >>"$here/results/$label/MANIFEST"
done
