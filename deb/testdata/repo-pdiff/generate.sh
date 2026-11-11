#!/usr/bin/env bash
# Regenerates the interop fixtures of this directory.
#
#   ./generate.sh fetch    download the real Debian files (network)
#   ./generate.sh record   apply every patch with rred and GNU ed in containers
#                          and record the results (podman; network for ed)
#
# "record" rewrites interop/, interop-expected.txt and rred-matrix.txt. The Go
# tests TestPDiffInteropAgainstRredAndEd and TestPDiffRredMatrix then check
# this package against them without any tool; TestPDiffRredLive repeats the
# rred part live when podman is there.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
rred_image=${RRED_IMAGE:-localhost/debtools:bookworm}
ed_image=${ED_IMAGE:-docker.io/library/debian:bookworm}

fetch() {
	local snap=https://snapshot.debian.org/archive/debian
	local live=https://deb.debian.org/debian/dists/stable-updates/main/binary-amd64

	# buster-updates/main/binary-amd64 on 2020-01-01: an index with unmerged
	# patches, starting from an empty file.
	local b=$snap/20200101T000000Z/dists/buster-updates/main/binary-amd64
	mkdir -p "$here/buster-updates"
	curl -fsSL "$b/Packages.diff/Index" -o "$here/buster-updates/Index"
	curl -fsSL "$b/Packages.xz" -o "$here/buster-updates/Packages.xz"
	for name in 2019-08-14-2019.27 2019-09-18-2012.01 2019-09-23-0812.44; do
		curl -fsSL "$b/Packages.diff/$name.gz" -o "$here/buster-updates/$name.gz"
	done

	# stable-updates (trixie) as served by deb.debian.org when the fixtures were
	# made: an index with merged patches. Fetch the Index first and the files it
	# names after; the archive moves on, so these may no longer exist.
	local t=$here/trixie-updates
	mkdir -p "$t"
	curl -fsSL "$live/Packages.diff/Index" -o "$t/Index"
	curl -fsSL "$live/Packages.xz" -o "$t/Packages.xz"
	for name in $(awk '/^SHA256-Download:/{f=1;next} /^[^ ]/{f=0} f&&/\.gz$/{print $3}' "$t/Index"); do
		curl -fsSL "$live/Packages.diff/$name" -o "$t/$name"
	done

	# The Packages file as it stood at each moment of the History (the file a
	# patch applies to), from the snapshot archive; one per timestamp.
	for ts in 20250809T210000Z 20250910T210000Z 20260714T150000Z 20260718T090000Z 20261022T210000Z 20261101T000000Z; do
		curl -fsSL "$snap/$ts/dists/trixie-updates/main/binary-amd64/Packages.xz" -o "$t/base-$ts.xz"
	done
}

record() {
	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT

	(cd "$root" && PKGFORMAT_PDIFF_OUT="$tmp" go test ./deb -run '^TestPDiffInteropDump$' -count=1)

	# One directory per container run: /w/ids lists the cases, /w/<id>.old and
	# /w/<id>.patch are the inputs.
	mkdir -p "$tmp/all"
	cp "$tmp"/interop/* "$tmp"/real/* "$tmp/all/"
	(cd "$tmp/all" && ls ./*.old | sed 's|^\./||; s|\.old$||' >ids)
	cp "$here"/container/*.sh "$tmp/all/"
	cp -r "$tmp/matrix" "$tmp/all/matrix"

	podman run --rm --network=none -v "$tmp/all:/w:ro" "$rred_image" sh /w/apply-rred.sh >"$tmp/rred.txt"
	podman run --rm -v "$tmp/all:/w:ro" "$ed_image" sh /w/apply-ed.sh >"$tmp/ed.txt"
	podman run --rm --network=none -v "$tmp/all:/w:ro" "$rred_image" sh /w/matrix-rred.sh >"$tmp/matrix.txt"

	{
		echo "# id sha256(new) sha256(patch) sha256(rred output) sha256(ed output)"
		echo "# written by generate.sh record; rred of apt in $rred_image, ed in $ed_image"
		while read -r id; do
			printf '%s %s %s %s %s\n' "$id" \
				"$(sha256sum <"$tmp/all/$id.new" | cut -d' ' -f1)" \
				"$(sha256sum <"$tmp/all/$id.patch" | cut -d' ' -f1)" \
				"$(awk -v id="$id" '$1==id{print $2}' "$tmp/rred.txt")" \
				"$(awk -v id="$id" '$1==id{print $2}' "$tmp/ed.txt")"
		done <"$tmp/all/ids"
	} >"$here/interop-expected.txt"

	{
		echo "# patch base sha256(rred output) | error; written by generate.sh record"
		cat "$tmp/matrix.txt"
	} >"$here/rred-matrix.txt"

	rm -rf "$here/interop"
	cp -r "$tmp/interop" "$here/interop"
}

case ${1:-} in
fetch) fetch ;;
record) record ;;
*)
	echo "usage: $0 fetch|record" >&2
	exit 2
	;;
esac
