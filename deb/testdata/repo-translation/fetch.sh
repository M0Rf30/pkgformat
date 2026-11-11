#!/bin/sh
# Refreshes the real-archive fixtures of this directory (network needed): the
# first paragraphs of Debian stable's English and German Translation files and
# of its amd64 Packages index, whose Description-md5 fields key them.
# Run from anywhere: sh fetch.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
DEBIAN=${DEBIAN:-http://deb.debian.org/debian}

# paras N: the first N paragraphs of the input.
paras() { awk -v n="$1" 'BEGIN { RS = ""; ORS = "\n\n" } NR <= n { print }'; }

curl -sf "$DEBIAN/dists/stable/main/i18n/Translation-en.xz" | xz -dc 2>/dev/null | paras 12 \
	>"$here/debian-Translation-en" || true
curl -sf "$DEBIAN/dists/stable/main/i18n/Translation-de.bz2" | bzcat 2>/dev/null | paras 12 \
	>"$here/debian-Translation-de" || true
curl -sf -r 0-60000 "$DEBIAN/dists/stable/main/binary-amd64/Packages.xz" | xz -dc 2>/dev/null | paras 8 \
	>"$here/debian-Packages.head" || true
