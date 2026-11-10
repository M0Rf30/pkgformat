#!/bin/sh
# Regenerates the dpkg status fixture in this directory from a Debian
# container. Needs podman or docker and network access.
#
#   ./generate.sh
#
# The container is debian:stable-slim. The script adds the i386 architecture,
# then installs and removes a few packages so that the status file holds every
# kind of stanza the reader meets:
#
#   - wget, installed and then removed (not purged): "deinstall ok config-files"
#   - hello, installed and put on hold: "hold ok installed"
#   - less, only unpacked: "install ok unpacked"
#   - libgcc-s1:i386 and its dependencies: a second architecture, and the
#     Multi-Arch: same list files "<name>:i386.list"
#   - tree, installed and purged: dpkg 1.22 drops the stanza, so the file
#     must not list it (older dpkg kept "purge ok not-installed")
#
# Files written next to this script:
#
#   status             /var/lib/dpkg/status, as dpkg left it
#   status.expected    what dpkg-query prints for it, see README.md
#   info/<pkg>.list    the file lists of a few packages (dpkg-query -L)
#   info/<pkg>.expected   dpkg-query -L <pkg>, one path per line
#   info.txt           the Debian release and dpkg version
set -eu

cd "$(dirname "$0")"
engine=${ENGINE:-$(command -v podman || command -v docker)}
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT

"$engine" run --rm -v "$out:/out:Z" docker.io/library/debian:stable-slim sh -ec '
	export DEBIAN_FRONTEND=noninteractive
	dpkg --add-architecture i386
	apt-get update -qq
	apt-get install -y -qq --no-install-recommends wget hello tree libgcc-s1:i386 >/dev/null
	apt-get download less
	dpkg --unpack less_*.deb >/dev/null
	dpkg --remove wget
	dpkg --purge tree
	echo "hello hold" | dpkg --set-selections

	cp /var/lib/dpkg/status /out/status
	{ cat /etc/debian_version; dpkg --version | head -n 1; } > /out/info.txt
	# Package, version, architecture, abbreviated status, status, provides.
	dpkg-query -W -f="\${Package}\t\${Version}\t\${Architecture}\t\${db:Status-Abbrev}\t\${Status}\t\${Provides}\n" > /out/status.expected
	mkdir -p /out/info
	for p in hello libgcc-s1:amd64 libgcc-s1:i386 libc6:i386 base-files wget; do
		dpkg-query -L "$p" > "/out/info/$p.expected"
		f=/var/lib/dpkg/info/$p.list
		[ -f "$f" ] || f=/var/lib/dpkg/info/${p%%:*}.list
		cp "$f" "/out/info/$p.list"
	done
'

rm -rf info status status.expected info.txt
mv "$out/status" "$out/status.expected" "$out/info.txt" "$out/info" .
