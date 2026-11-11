#!/bin/sh
# Regenerates the fixtures of this directory with the reference tools
# (debsigs, dpkg-sig, debsig-verify, dpkg-deb) inside a Debian bookworm
# container. Needs podman and network access for the first image build.
set -eu
cd "$(dirname "$0")"
IMAGE=localhost/pkgformat-debtools:bookworm

podman image exists "$IMAGE" || podman build -t "$IMAGE" -f Containerfile .
podman run --rm -v "$PWD:/w:Z" "$IMAGE" sh /w/inner.sh
