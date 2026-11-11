#!/bin/bash
# Regenerates results/<label>/ : what real apt does with the repository in
# repo/ for the machine identifiers of machine-ids.txt, once per Debian release
# (apt 2.6 in bookworm, 3.0 in trixie, 3.3 in unstable).
#
# Needs podman or docker and network access to pull the images. Run from
# anywhere:
#
#   deb/apt/testdata/phased/generate.sh
#
# The draw vectors (draw.tsv) come from draw.cc and the host's g++:
#
#   g++ -O1 -o /tmp/draw deb/apt/testdata/phased/draw.cc
#   /tmp/draw <deb/apt/testdata/phased/inputs.txt >deb/apt/testdata/phased/draw.tsv
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
engine=${CONTAINER_ENGINE:-$(command -v podman || command -v docker)}

images=${IMAGES:-"bookworm=docker.io/library/debian:bookworm trixie=docker.io/library/debian:stable-slim unstable=docker.io/library/debian:unstable-slim"}

for entry in $images; do
	label=${entry%%=*}
	image=${entry#*=}
	work=$(mktemp -d)
	"$engine" run --rm \
		-v "$work:/out:Z" \
		-v "$here/container.sh:/container.sh:Z,ro" \
		-v "$here/repo:/repo:Z,ro" \
		-v "$here/machine-ids.txt:/machine-ids.txt:Z,ro" \
		"$image" bash /container.sh
	rm -rf "$here/results/$label"
	mkdir -p "$here/results/$label"
	cp "$work"/* "$here/results/$label/"
	echo "image-reference: $image" >>"$here/results/$label/MANIFEST"
	rm -rf "$work"
done
