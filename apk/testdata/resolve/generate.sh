#!/bin/sh
# Regenerates expected/ from cases.txt with the apk of an Alpine container:
# every case is replayed with `apk add --simulate` (or `apk upgrade
# --simulate`) against the repositories main.index and edge.index and a root
# whose installed database and world file are the case's. Needs podman or
# docker and the alpine image; no network once the image is local.
#
#   ./generate.sh [name-prefix]      (default: every case)
#
# main.index and edge.index are APKINDEX texts made by mkidx.py from
# main.universe and edge.universe (one line per package); the checksums are
# SHA-1 of name and version in the canonical base64 form apk requires.
#
# expected/<case> holds one line per change, sorted:
#   install name-version | upgrade name-newversion | downgrade name-newversion
#   remove name-version | reinstall name-version
# or the single line "error" when apk cannot select the packages.
set -eu

cd "$(dirname "$0")"
engine=${ENGINE:-$(command -v podman || command -v docker)}
image=${IMAGE:-docker.io/library/alpine:3.24}
prefix=${1:-}

python3 mkidx.py main.universe > main.index
python3 mkidx.py edge.universe > edge.index

rm -rf expected.tmp
mkdir expected.tmp

"$engine" run --rm -v "$PWD:/in:ro" -v "$PWD/expected.tmp:/out:rw" -e PREFIX="$prefix" "$image" sh -eu -c '
	# The repositories: index text -> APKINDEX.tar.gz.
	for r in main edge; do
		mkdir -p /u/$r/x86_64
		work=$(mktemp -d)
		cp /in/$r.index "$work/APKINDEX"
		tar -C "$work" -czf /u/$r/x86_64/APKINDEX.tar.gz APKINDEX
		rm -rf "$work"
	done

	stanza() { # name version -> the index record, from either index
		awk -v p="$1" -v v="$2" "BEGIN { RS=\"\"; ORS=\"\n\n\" } \$0 ~ \"(^|\\n)P:\" p \"(\\n|\$)\" && \$0 ~ \"(^|\\n)V:\" v \"(\\n|\$)\"" /in/main.index /in/edge.index
	}

	trim() { echo "$1" | sed -e "s/^[ \t]*//" -e "s/[ \t]*\$//"; }

	grep -v "^#" /in/cases.txt | while IFS="|" read -r name installed world cmd; do
		name=$(trim "$name")
		[ -n "$name" ] || continue
		case "$name" in "$PREFIX"*) ;; *) continue ;; esac
		installed=$(trim "$installed"); world=$(trim "$world"); cmd=$(trim "$cmd")

		rm -rf /r
		mkdir -p /r/etc/apk /r/lib/apk/db
		printf "%s\n" /u/main "@edge /u/edge" > /r/etc/apk/repositories
		: > /r/lib/apk/db/installed
		for nv in $installed; do
			n=${nv%%-[0-9]*}
			ver=${nv#"$n"-}
			stanza "$n" "$ver" >> /r/lib/apk/db/installed
		done
		: > /r/etc/apk/world
		for w in $world; do echo "$w" >> /r/etc/apk/world; done

		set -- $cmd
		verb=$1; shift
		if out=$(apk --root /r --arch x86_64 --allow-untrusted --no-network --no-cache $verb --simulate "$@" 2>/dev/null </dev/null); then
			echo "$out" | sed -n \
				-e "s/^( *[0-9]*\/[0-9]*) Installing \([^ ]*\) (\(.*\))\$/install \1-\2/p" \
				-e "s/^( *[0-9]*\/[0-9]*) Upgrading \([^ ]*\) (.* -> \(.*\))\$/upgrade \1-\2/p" \
				-e "s/^( *[0-9]*\/[0-9]*) Downgrading \([^ ]*\) (.* -> \(.*\))\$/downgrade \1-\2/p" \
				-e "s/^( *[0-9]*\/[0-9]*) Purging \([^ ]*\) (\(.*\))\$/remove \1-\2/p" \
				-e "s/^( *[0-9]*\/[0-9]*) Reinstalling \([^ ]*\) (\(.*\))\$/reinstall \1-\2/p" \
				| sed "s/@[a-z]*-\([0-9]\)/-\1/" | sort > /out/$name
			[ -e /out/$name ] || : > /out/$name
		else
			echo error > /out/$name
		fi
	done
'

if [ -z "$prefix" ]; then rm -rf expected; mkdir expected; fi
mv expected.tmp/* expected/
rmdir expected.tmp
