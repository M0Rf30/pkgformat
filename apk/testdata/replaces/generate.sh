#!/bin/sh
# Regenerates expected: for each case the owner package is installed in an empty
# root with apk (Alpine container, apk-tools 3.0.8), then the incoming package.
# Both ship the file "shared" (content "owner" or "incoming"). The outcome is
#   yes       the file now holds "incoming"
#   no        the file still holds "owner"
#   conflict  apk refused the incoming package
# The packages are written by this library (PKGFORMAT_UPDATE=1 go test -run
# TestReplacesFile, run here first).
set -eu

cd "$(dirname "$0")"
engine=${ENGINE:-$(command -v podman || command -v docker)}
image=${IMAGE:-docker.io/library/alpine:3.24}

(cd ../.. && PKGFORMAT_UPDATE=1 go test -run '^TestReplacesFile$' . >/dev/null)

"$engine" run --rm -v "$PWD:/in:ro" -v "$PWD:/out:rw" "$image" sh -eu -c '
	: > /out/expected
	for o in /in/*-owner.apk; do
		name=$(basename "$o" -owner.apk)
		rm -rf /r; mkdir -p /r
		apk --root /r --initdb --allow-untrusted --no-network --no-cache --no-scripts add "$o" >/dev/null 2>&1
		if apk --root /r --allow-untrusted --no-network --no-cache --no-scripts add /in/$name-incoming.apk >/dev/null 2>&1; then
			if [ "$(cat /r/shared)" = incoming ]; then r=yes; else r=no; fi
		else
			r=conflict
		fi
		echo "$name $r" >> /out/expected
	done
'
