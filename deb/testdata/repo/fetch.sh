#!/bin/sh
# Refreshes the real-archive fixtures of this directory from the public
# archives (network needed). The trimmed files keep every header field and the
# checksum lines of a few indexes, so they stay parseable and byte-stable.
# Run from anywhere: sh fetch.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
DEBIAN=${DEBIAN:-http://deb.debian.org/debian}
UBUNTU=${UBUNTU:-http://archive.ubuntu.com/ubuntu}

# trim keeps the header of a Release and, in each checksum section, only the
# lines whose path matches the pattern ($1).
trim() {
	awk -v keep="$1" '
		/^[A-Za-z]/ { section = ($0 ~ /^(MD5Sum|SHA1|SHA256|SHA512):$/); print; next }
		section && $3 ~ keep { print }
	'
}

# Debian stable: dak layout (fields in dak order, sizes in 8 columns).
curl -sf "$DEBIAN/dists/stable/Release" |
	trim '^(main/(binary-amd64/Packages|Contents-amd64|Contents-udeb-amd64|i18n/Translation-(en|de)[.]|source/Sources)|contrib/Contents-all[.]gz$)' \
		>"$here/debian-stable.Release"

# Debian bookworm-backports: NotAutomatic, ButAutomaticUpgrades, Valid-Until.
curl -sf "$DEBIAN/dists/bookworm-backports/Release" | trim '^main/binary-amd64/Packages' \
	>"$here/debian-backports.Release"

# Ubuntu jammy: apt-ftparchive layout (sizes in 16 columns), no Acquire-By-Hash.
curl -sf "$UBUNTU/dists/jammy/Release" | trim '^(main/binary-amd64/Packages|main/Contents-amd64|main/i18n/(Index|Translation-(en|de)([.]|$)))' \
	>"$here/ubuntu-jammy.Release"

# Ubuntu jammy-backports: a blank-padded hour in the date.
curl -sf "$UBUNTU/dists/jammy-backports/Release" | trim '^main/binary-amd64/Packages' \
	>"$here/ubuntu-backports.Release"

# Ubuntu jammy i18n/Index (SHA1 only), the Asturian, German and English entries.
curl -sf "$UBUNTU/dists/jammy/main/i18n/Index" |
	awk '/^[A-Za-z]/ { print; next } $3 ~ /^Translation-(de|en|ast)([.]|$)/ { print }' \
		>"$here/ubuntu-jammy.i18n.Index"
