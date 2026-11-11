#!/bin/sh
# Regenerates testdata/changes: the .changes and .buildinfo files that
# dpkg-genchanges and dpkg-genbuildinfo write for a real build of the hello
# fixture in a Debian bookworm container.
#
# Needs podman and network access.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
cp "$here"/packages/hello/* "$work"/

cat >"$work/build.sh" <<'INNER'
set -e
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq --no-install-recommends build-essential debhelper texinfo dpkg-dev fakeroot >/dev/null 2>&1
dpkg-source --no-check -x hello_2.10-5.dsc src >/dev/null
cd src
export SOURCE_DATE_EPOCH=1700000000
dpkg-buildpackage -us -uc -sa >/dev/null 2>&1
mkdir -p ../out/full ../out/binary
cp ../hello_2.10-5_amd64.changes ../hello_2.10-5_amd64.buildinfo ../out/full/
dpkg-buildpackage -us -uc -b >/dev/null 2>&1
cp ../hello_2.10-5_amd64.changes ../hello_2.10-5_amd64.buildinfo ../out/binary/
INNER

podman run --rm -v "$work:/work:Z" -w /work docker.io/library/debian:bookworm sh build.sh

rm -rf "$here/changes"
mkdir -p "$here/changes"
cp -r "$work/out/full" "$work/out/binary" "$here/changes/"
rm -rf "$work"
