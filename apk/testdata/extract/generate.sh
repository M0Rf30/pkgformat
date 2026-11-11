#!/bin/sh
# Regenerates listings/<package>.listing: the tree `apk extract` produces for
# every *.apk here, run as root in an Alpine container (the packages are
# Alpine 3.20 builds, fetched with `apk fetch`; see README.md). One line per
# path, sorted:
#   path|type|mode|uid|gid|size|link target|sha256|links|security.capability
# devices-*.apk are only listed by GNU tar (device nodes need root outside a user
# namespace): listings/devices-*.tarlist.
# type is d, f, l, c (char device), b (block device) or p (fifo); mode is octal with the setuid/setgid/sticky bits; the
# sha256 is of regular files; links is the hard link count; the capability
# is the hex xattr value or empty.
set -eu

cd "$(dirname "$0")"

# interop-*.apk and signed-*.apk are written by this library; rewrite them
# (and the test key) first.
(cd ../.. && PKGFORMAT_UPDATE=1 go test -run '^TestInterop_fixtures$' . >/dev/null)
engine=${ENGINE:-$(command -v podman || command -v docker)}
image=${IMAGE:-docker.io/library/alpine:3.24}

rm -rf listings
mkdir listings

"$engine" run --rm -v "$PWD:/in:ro" -v "$PWD/listings:/out:rw" "$image" sh -eu -c '
	apk add --no-cache attr tar >/dev/null 2>&1
	for pkg in /in/*.apk; do
		name=$(basename "$pkg" .apk)
		case "$name" in devices-*) tar --numeric-owner -tvzf "$pkg" > /out/$name.tarlist; continue ;; esac
		rm -rf /x; mkdir /x
		apk extract --allow-untrusted --destination /x "$pkg" >/dev/null 2>&1
		cd /x
		find . -mindepth 1 | sort | while read -r p; do
			rel=${p#./}
			if [ -L "$p" ]; then t=l; elif [ -d "$p" ]; then t=d; elif [ -c "$p" ]; then t=c; elif [ -b "$p" ]; then t=b; elif [ -p "$p" ]; then t=p; else t=f; fi
			meta=$(stat -c "%a|%u|%g|%s" "$p")
			link=""; sum=""
			[ "$t" = l ] && link=$(readlink "$p")
			[ "$t" = f ] && sum=$(sha256sum "$p" | cut -d" " -f1)
			links=$(stat -c %h "$p")
			cap=$(getfattr -h -n security.capability -e hex "$p" 2>/dev/null | sed -n "s/^security.capability=0x//p")
			echo "$rel|$t|$meta|$link|$sum|$links|$cap"
		done > /out/$name.listing
		cd /
	done
	# What apk makes of the packages the writer produced: the signed one
	# verifies against the committed key, the unsigned one does not.
	{
		apk --keys-dir /in/keys --no-network verify /in/signed-1.2.3-r4.apk && echo "signed: ok" || echo "signed: failed"
		apk --keys-dir /in/keys --no-network verify /in/interop-1.2.3-r4.apk >/dev/null 2>&1 && echo "unsigned: ok" || echo "unsigned: failed"
		rm -rf /r; mkdir -p /r/etc/apk
		mkdir -p /r/etc/apk/keys; cp /in/keys/*.pub /r/etc/apk/keys/
		apk --root /r --initdb --no-network --no-cache --no-scripts add /in/signed-1.2.3-r4.apk >/dev/null 2>&1 && echo "add signed: ok" || echo "add signed: failed"
	} > /out/apk.verdicts
'
