#!/bin/sh
# Runs inside a Debian container (apt provides rred). /w holds the file "ids"
# and, for every id, <id>.old and <id>.patch. Prints "<id> <sha256 of the
# patched file>" with rred of apt, the program apt itself applies pdiffs with.
set -eu

rred=/usr/lib/apt/methods/rred

while read -r id; do
	sum=$("$rred" -f "/w/$id.patch" <"/w/$id.old" | sha256sum | cut -d' ' -f1)
	printf '%s %s\n' "$id" "$sum"
done </w/ids
