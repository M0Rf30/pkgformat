#!/bin/sh
# Regenerates testdata/sources: the Sources indexes that apt-ftparchive and
# dpkg-scansources write for the packages in testdata/packages.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$here/sources"
cd "$here"

cat >"$here/sources/ftparchive.conf" <<'CONF'
APT::FTPArchive::Sources::Packages "";
CONF

apt-ftparchive -c sources/ftparchive.conf sources packages >sources/Sources.apt-ftparchive 2>/dev/null
dpkg-scansources packages >sources/Sources.dpkg-scansources 2>/dev/null
rm sources/ftparchive.conf
