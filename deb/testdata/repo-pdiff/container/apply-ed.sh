#!/bin/sh
# Runs inside a Debian container with network access (ed is installed when
# missing). Same input and output as apply-rred.sh, but the patches are applied
# by GNU ed, the program the format was made for: the patch, then w and q.
set -eu

command -v ed >/dev/null 2>&1 || {
	apt-get update -qq >/dev/null
	apt-get install -y -qq ed >/dev/null
}

while read -r id; do
	cp "/w/$id.old" /tmp/work
	{
		cat "/w/$id.patch"
		printf 'w\nq\n'
	} | ed -s /tmp/work
	printf '%s %s\n' "$id" "$(sha256sum </tmp/work | cut -d' ' -f1)"
done </w/ids
