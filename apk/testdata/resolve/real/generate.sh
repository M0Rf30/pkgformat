#!/bin/sh
# Regenerates the real-universe fixtures from an Alpine container (needs
# network): the full APKINDEX of the main and community repositories is
# reduced to the packages that the simulated `apk add` of every target in
# targets.txt installs, together with the container's installed database
# and world, and the answers apk gives against the reduced index are
# stored in expected/.
#
#   APKINDEX    reduced index (main and community concatenated, repository
#               order kept by the file order: main first)
#   installed   /lib/apk/db/installed of the image
#   world       /etc/apk/world of the image
#   expected/   one file per target, sorted lines "install name-version"
set -eu

cd "$(dirname "$0")"
engine=${ENGINE:-$(command -v podman || command -v docker)}
image=${IMAGE:-docker.io/library/alpine:3.24}

rm -rf out
mkdir out

"$engine" run --rm -v "$PWD:/in:ro" -v "$PWD/out:/out:rw" "$image" sh -eu -c '
	apk update >/dev/null
	mkdir -p /full
	n=0
	for f in /var/cache/apk/APKINDEX.*.tar.gz; do
		n=$((n + 1))
		tar -xzOf "$f" APKINDEX > /full/$n.index
	done
	cat /full/*.index > /full/all.index

	# Which packages do the targets pull in?
	: > /need
	while read -r t; do
		apk add --simulate "$t" 2>/dev/null | sed -n "s/^( *[0-9]*\/[0-9]*) Installing \([^ ]*\) (\(.*\))\$/\1 \2/p" >> /need
	done < /in/targets.txt
	sort -u /need > /need.u

	awk -v need=/need.u "BEGIN { while ((getline l < need) > 0) { split(l, a, \" \"); want[a[1] \" \" a[2]] = 1 } RS=\"\"; ORS=\"\n\n\" }
		{ p=\"\"; v=\"\"; n=split(\$0, ls, \"\n\"); for (i=1;i<=n;i++) { if (substr(ls[i],1,2)==\"P:\") p=substr(ls[i],3); if (substr(ls[i],1,2)==\"V:\") v=substr(ls[i],3) } if ((p \" \" v) in want) print }" /full/all.index > /out/APKINDEX

	cp /lib/apk/db/installed /out/installed
	cp /etc/apk/world /out/world

	# Replay against the reduced index only.
	mkdir -p /u/main/$(apk --print-arch) /out/expected
	work=$(mktemp -d); cp /out/APKINDEX $work/APKINDEX
	tar -C $work -czf /u/main/$(apk --print-arch)/APKINDEX.tar.gz APKINDEX
	echo /u/main > /etc/apk/repositories
	while read -r t; do
		if out=$(apk --allow-untrusted --no-network --no-cache add --simulate "$t" 2>/dev/null </dev/null); then
			echo "$out" | sed -n "s/^( *[0-9]*\/[0-9]*) Installing \([^ ]*\) (\(.*\))\$/install \1-\2/p" | sort > /out/expected/$t
		else
			echo error > /out/expected/$t
		fi
	done < /in/targets.txt
'

rm -rf expected
mv out/expected expected
mv out/APKINDEX out/installed out/world .
rmdir out
