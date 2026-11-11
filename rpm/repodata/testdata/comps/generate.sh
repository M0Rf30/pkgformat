#!/bin/sh
# Rebuilds fedora43.xml and fedora15.xml from the published comps files. The
# result is deterministic: running this script leaves the committed fixtures
# unchanged. features.xml is written by hand and is not touched.
#
# Needs: curl, zstd, python3, sha256sum.
set -eu

cd "$(dirname "$0")"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # url sha256 file
	curl -fsSL -o "$3" "$1"
	echo "$2  $3" | sha256sum -c - >/dev/null
}

# Fedora 43, Everything, x86_64: the comps-Everything.x86_64.xml.zst of the
# release repository (its file name starts with its own sha256).
f43=73a6103e51d00abd1abd50eb54f98a07b398a86972555b532af6acdb98565c3d
fetch "https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Everything/x86_64/os/repodata/$f43-comps-Everything.x86_64.xml.zst" \
	"$f43" "$work/f43.zst"
zstd -dq "$work/f43.zst" -o "$work/full43.xml"
echo "68827506abbd1ff7a0118e1a351883bffe8a0b88fe13eaf43d24448a0cf95a97  $work/full43.xml" | sha256sum -c - >/dev/null

python3 trim.py "$work/full43.xml" fedora43.xml \
	--groups core,guest-agents,networkmanager-submodules,standard,kde-mobile,kde-mobile-apps,firefox,design-suite,input-methods \
	--categories kde-mobile-environment,apps \
	--environments custom-environment,kde-mobile-environment \
	--langpacks tesseract,mythes,aspell

# Fedora 15, Everything, x86_64 (archived release): old-style comps with
# langonly, basearchonly, <blacklist> and <whiteout>.
f15=47fcb90b5119c93feaab864c3346f9abed0245fe407bf317e3f7c20c0bef62b8
fetch "https://archives.fedoraproject.org/pub/archive/fedora/linux/releases/15/Everything/x86_64/os/repodata/$f15-comps-f15.xml" \
	"$f15" "$work/f15.xml"

python3 trim.py "$work/f15.xml" fedora15.xml \
	--groups armenian-support,legacy-software-development,java-development,java,core \
	--categories language-support,development,base-system \
	--langpacks aspell,eclipse-platform,gcompris \
	--blacklist 8 --whiteout 8
