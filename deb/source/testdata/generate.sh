#!/bin/sh
# Regenerates the source package fixtures and the expected trees.
#
# Packages are fetched from deb.debian.org (the Sources index of stable);
# the expected tree of each is what `dpkg-source -x` produces, recorded as a
# manifest of "mode type path digest-or-target" lines.
#
# Usage: ./generate.sh [workdir]
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=${1:-$(mktemp -d)}
mirror=${MIRROR:-https://deb.debian.org/debian}

# package names, in the order of the Sources index they come from
packages="hello sl rust-getch node-boolbase node-is-node r-cran-bh icingaweb2-module-metapackages meta-exwm cl-pipes libtemplate-plugin-utf8decode-perl vacation valgrind-if-available"

manifest() {
	(cd "$1" && find . -mindepth 1 | LC_ALL=C sort | while read -r p; do
		if [ -L "$p" ]; then
			printf '%s l %s %s\n' "$(stat -c %a "$p")" "$p" "$(readlink "$p")"
		elif [ -d "$p" ]; then
			printf '%s d %s -\n' "$(stat -c %a "$p")" "$p"
		else
			printf '%s f %s %s\n' "$(stat -c %a "$p")" "$p" "$(sha256sum <"$p" | cut -d' ' -f1)"
		fi
	done)
}

mkdir -p "$work" "$here/packages" "$here/expected"
curl -fsSL "$mirror/dists/stable/main/source/Sources.xz" | xz -dc >"$work/Sources"

for name in $packages; do
	dir=$(awk -v RS= -v n="$name" '$0 ~ "(^|\n)Package: " n "\n" { for (i = 1; i <= NF; i++) if ($i == "Directory:") print $(i+1) }' "$work/Sources" | head -n1)
	[ -n "$dir" ] || { echo "no $name in Sources" >&2; exit 1; }
	mkdir -p "$here/packages/$name"
	dsc=$(awk -v RS= -v n="$name" '$0 ~ "(^|\n)Package: " n "\n"' "$work/Sources" | awk '/^Files:/{f=1;next} f&&/\.dsc$/{print $3}' | head -n1)
	if [ -z "$dsc" ]; then
		# Sources stanzas do not list the .dsc: derive it from the version.
		ver=$(awk -v RS= -v n="$name" '$0 ~ "(^|\n)Package: " n "\n"' "$work/Sources" | awk '/^Version:/{print $2}' | sed 's/^[0-9]*://')
		dsc=${name}_${ver}.dsc
	fi
	curl -fsSL -o "$here/packages/$name/$dsc" "$mirror/$dir/$dsc"
	for f in $(awk '/^Files:/{f=1;next} f&&/^ /{print $3;next} {f=0}' "$here/packages/$name/$dsc"); do
		curl -fsSL -o "$here/packages/$name/$f" "$mirror/$dir/$f"
	done
	rm -rf "$work/x-$name"
	(cd "$here/packages/$name" && dpkg-source --no-check -x "$dsc" "$work/x-$name" >/dev/null)
	manifest "$work/x-$name" >"$here/expected/$name.manifest"
done
