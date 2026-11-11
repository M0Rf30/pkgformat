#!/bin/sh
# Regenerates ftparchive/ and ftparchive.Release with the real apt-ftparchive:
# a small dists/<suite> tree (Packages and Contents in three compressions, a
# Translation file and its i18n/Index, a Sources index) and the Release
# `apt-ftparchive release` writes for it with every Release option it knows.
# Run from anywhere: sh generate.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
dist="$here/ftparchive/dists/x"

rm -rf "$here/ftparchive"
mkdir -p "$dist/main/binary-amd64" "$dist/main/i18n" "$dist/main/source"

pk() {
	printf 'Package: hello\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/main/h/hello/hello_1.0_amd64.deb\nSize: 1\nSHA256: aa\nDescription: hi\n\n' >"$1"
}

pk "$dist/main/binary-amd64/Packages"
gzip -9nk "$dist/main/binary-amd64/Packages"
xz -9ek "$dist/main/binary-amd64/Packages"

printf 'usr/bin/hello\t\t\t\t\t\t    utils/hello\n' >"$dist/Contents-amd64"
gzip -9nk "$dist/Contents-amd64"

printf 'Package: hello\nDescription-md5: 0123456789abcdef0123456789abcdef\nDescription-en: hi\n long\n' >"$dist/main/i18n/Translation-en"
bzip2 -9k "$dist/main/i18n/Translation-en"

printf 'Package: hello\nVersion: 1.0\n\n' >"$dist/main/source/Sources"
gzip -9nk "$dist/main/source/Sources"

cd "$dist"
apt-ftparchive \
	-o APT::FTPArchive::Release::Origin=Test \
	-o APT::FTPArchive::Release::Label=Test \
	-o APT::FTPArchive::Release::Suite=testing \
	-o APT::FTPArchive::Release::Version=1.5 \
	-o APT::FTPArchive::Release::Codename=x \
	-o APT::FTPArchive::Release::NotAutomatic=yes \
	-o APT::FTPArchive::Release::ButAutomaticUpgrades=yes \
	-o APT::FTPArchive::Release::Acquire-By-Hash=yes \
	-o APT::FTPArchive::Release::Architectures=amd64 \
	-o APT::FTPArchive::Release::Components=main \
	-o APT::FTPArchive::Release::Description="A test archive" \
	-o APT::FTPArchive::Release::ValidTime=2592000 \
	release . >"$here/ftparchive.Release"
