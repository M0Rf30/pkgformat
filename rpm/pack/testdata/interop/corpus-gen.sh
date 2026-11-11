#!/bin/bash
# Prints "ok" or "bad", a tab and the dependency, for every line of richdeps.txt,
# as the spec parser of the installed rpm judges "Requires: <line>".
set -u
d=$(mktemp -d)
while IFS= read -r e; do
	printf 'Name: t\nVersion: 1\nRelease: 1\nSummary: x\nLicense: MIT\nRequires: %s\n%%description\nx\n' "$e" > "$d/t.spec"
	if out=$(rpmspec -q --requires "$d/t.spec" 2>&1) && ! grep -q "^error" <<<"$out"; then
		# a dependency that rpm splits into several names is not a boolean one
		if [ "$(wc -l <<<"$out")" = 1 ] && [[ "$(tr -d ' ' <<<"$out")" == "$(tr -d ' ' <<<"$e")" ]]; then echo -e "ok\t$e"; else echo -e "bad\t$e"; fi
	else
		echo -e "bad\t$e"
	fi
done < "${1:-richdeps.txt}"
rm -rf "$d"
