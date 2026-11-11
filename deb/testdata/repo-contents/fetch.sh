#!/bin/sh
# Refreshes the real-archive Contents fixtures (network needed): the head of
# three Contents indexes written by two different archive tools. Run from
# anywhere: sh fetch.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
DEBIAN=${DEBIAN:-http://deb.debian.org/debian}
UBUNTU=${UBUNTU:-http://archive.ubuntu.com/ubuntu}

# dak (Debian): paths padded with blanks to column 56, no header; the whole
# udeb index is small, 150 lines of it are kept, gzip compressed as published.
curl -sf "$DEBIAN/dists/stable/main/Contents-udeb-amd64.gz" | gunzip | head -n 150 | gzip -9n \
	>"$here/debian-contents-udeb-amd64.head.gz"

# dak, Contents-amd64: the first 120 lines of a truncated download (files with
# several packages and long names).
curl -sf -r 0-30000 "$DEBIAN/dists/stable/main/Contents-amd64.gz" | gunzip 2>/dev/null | head -n 120 \
	>"$here/debian-contents-amd64.head" || true

# apt-ftparchive (Ubuntu): paths padded with tabs, no header.
curl -sf -r 0-20000 "$UBUNTU/dists/jammy/Contents-amd64.gz" | gunzip 2>/dev/null | head -n 80 \
	>"$here/ubuntu-contents-amd64.head" || true
