#!/bin/sh
# Regenerates this directory from an Arch Linux container. Needs podman or
# docker and network access.
#
#   ./generate.sh
#
# The container is archlinux:latest with one extra package (tree, installed
# explicitly, the rest of the image being dependencies and base packages).
# local/ holds a few of the package directories of /var/lib/pacman/local
# verbatim, and its ALPM_DB_VERSION. What pacman prints for that directory,
# with LC_ALL=C and TZ=UTC, is next to it:
#
#   local/           the database: ALPM_DB_VERSION and <name>-<version>/{desc,files,mtree}
#   Q.expected       pacman -Q
#   Qi.expected      pacman -Qi
#   Ql.expected      pacman -Ql
#   info.txt         pacman and the image
set -eu

cd "$(dirname "$0")"
engine=${ENGINE:-$(command -v podman || command -v docker)}
pkgs="filesystem acl attr pacman-mirrorlist bash pacman binutils ca-certificates-utils tree"

out=$(mktemp -d)
"$engine" run --rm -v "$out:/out:Z" docker.io/library/archlinux:latest sh -ec "
	pacman -Sy --noconfirm tree >/dev/null 2>&1
	src=/var/lib/pacman/local
	mkdir /out/db /out/db/local
	cp \$src/ALPM_DB_VERSION /out/db/local/
	for p in $pkgs; do
		cp -a \$src/\$(pacman -Q \$p | tr ' ' '-') /out/db/local/
	done
	export LC_ALL=C TZ=UTC
	pacman --dbpath /out/db -Q > /out/Q.expected 2>/dev/null
	pacman --dbpath /out/db -Qi > /out/Qi.expected
	pacman --dbpath /out/db -Ql > /out/Ql.expected
	{ pacman --version | grep -o 'Pacman v[0-9.a-z]*'; grep PRETTY_NAME /etc/os-release; } > /out/info.txt
"
rm -rf local Q.expected Qi.expected Ql.expected info.txt
mv "$out/db/local" local
mv "$out"/Q.expected "$out"/Qi.expected "$out"/Ql.expected "$out"/info.txt .
rm -rf "$out"
