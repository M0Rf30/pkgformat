#!/bin/sh
# Runs inside a Debian container (apt provides rred). /w/matrix/pp holds
# patches (*.ed) and /w/matrix the base files (base-*.txt). Prints
# "<patch> <base> <sha256 of rred's output | error>" for every pair; "error"
# when rred exits non-zero.
set -u

rred=/usr/lib/apt/methods/rred

for p in /w/matrix/pp/*.ed; do
	for b in /w/matrix/base-*.txt; do
		if "$rred" -f "$p" <"$b" >/tmp/out 2>/dev/null; then
			res=$(sha256sum </tmp/out | cut -d' ' -f1)
		else
			res=error
		fi
		printf '%s %s %s\n' "$(basename "$p" .ed)" "$(basename "$b")" "$res"
	done
done
