#!/bin/sh
# Regenerates the installed-database fixtures in this directory from Alpine
# containers. Needs podman or docker and network access.
#
#   ./generate.sh [alpine-3.24|alpine-3.20]...      (default: both)
#
# Each fixture directory holds the file /lib/apk/db/installed of a container
# after a few packages were added, and what the container's own apk prints for
# it, in the text format of "apk info":
#
#   installed        /lib/apk/db/installed, as apk left it
#   list.expected    apk list -I          (name-version, architecture, origin, license)
#   files.expected   apk info -L <pkg>    for every package
#   provides.expected  apk info -P <pkg>  for every package
#   depends.expected   apk info -R <pkg>  for every package
#   info.txt         the Alpine release and the apk version
#
#   alpine-3.24   alpine:latest (apk-tools 3), plus the virtual package
#                 .build-deps that pulls zlib-dev
#   alpine-3.20   alpine:3.20 (apk-tools 2), plus curl and what it needs
set -eu

cd "$(dirname "$0")"
engine=${ENGINE:-$(command -v podman || command -v docker)}
[ "$#" -gt 0 ] || set -- alpine-3.24 alpine-3.20

fixture() {
	name=$1 image=$2 add=$3
	out=$(mktemp -d)
	"$engine" run --rm -v "$out:/out:Z" "$image" sh -ec "
		$add
		cp /lib/apk/db/installed /out/installed
		{ cat /etc/alpine-release; apk --version; } > /out/info.txt
		# --no-network: answer from the installed database only, not from the
		# index the add above just fetched (which may hold newer versions).
		apk --no-network list -I 2>/dev/null > /out/list.expected
		names=\$(apk --no-network info 2>/dev/null)
		apk --no-network info -L \$names 2>/dev/null > /out/files.expected
		apk --no-network info -P \$names 2>/dev/null > /out/provides.expected
		apk --no-network info -R \$names 2>/dev/null > /out/depends.expected
	"
	rm -rf "$name"
	mkdir "$name"
	mv "$out"/* "$name"/
	rmdir "$out"
}

for f in "$@"; do
	case $f in
	alpine-3.24)
		fixture "$f" docker.io/library/alpine:latest "apk add --no-cache --virtual .build-deps zlib-dev >/dev/null"
		;;
	alpine-3.20)
		fixture "$f" docker.io/library/alpine:3.20 "apk add --no-cache curl >/dev/null"
		;;
	esac
done
