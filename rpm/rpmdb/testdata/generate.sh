#!/bin/sh
# Regenerates the fixture databases in this directory from distribution
# containers. Needs podman or docker and network access.
#
#   ./generate.sh [bdb|ndb|sqlite|rich]...      (default: all four)
#
# The rich fixture is different: rich/build.sh builds small packages from the
# specs in rich/ (scriptlets, triggers, file triggers, versioned and rich
# dependencies, several versions and architectures of one name) and registers
# them with a few distribution packages; rich.sqlite.scripts and
# rich.sqlite.queries hold what rpm prints for --scripts --triggers
# --filetriggers and for the -q, -qf, --whatprovides, --whatrequires,
# --whatconflicts ... queries listed in rich/queries.txt.
#
# Each fixture is the rpm database of a throw-away root into which a few small
# packages were registered with `rpm -i --justdb` (nothing is unpacked). Next
# to it, <fixture>.expected holds what the distribution's own rpm prints for
# the same database, in the tab-separated records the tests compare:
#
#   P name epoch version release arch installtime
#   D name provide-name provide-flags provide-version
#   Q name require-name require-flags require-version
#   F name path mode size digest linkto user group mtime flags
#
# <fixture>.info holds the rpm version and database backend that wrote it.
set -eu

cd "$(dirname "$0")"
engine=${ENGINE:-$(command -v podman || command -v docker)}
[ "$#" -gt 0 ] || set -- bdb ndb sqlite rich

QF='P\t%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{INSTALLTIME}\n'
QF=$QF'[D\t%{=NAME}\t%{PROVIDENAME}\t%{PROVIDEFLAGS}\t%{PROVIDEVERSION}\n]'
QF=$QF'[Q\t%{=NAME}\t%{REQUIRENAME}\t%{REQUIREFLAGS}\t%{REQUIREVERSION}\n]'
QF=$QF'[F\t%{=NAME}\t%{FILENAMES}\t%{FILEMODES}\t%{FILESIZES}\t%{FILEDIGESTS}\t%{FILELINKTOS}\t%{FILEUSERNAME}\t%{FILEGROUPNAME}\t%{FILEMTIMES}\t%{FILEFLAGS}\n]'

# fixture <name> <image> <backend> <db file name in the root> <script that
# leaves the rpm files to register in /tmp/rpms>
fixture() {
	name=$1 image=$2 backend=$3 dbfile=$4 fetch=$5
	out=$(mktemp -d)
	"$engine" run --rm -v "$out:/out:Z" -e QF="$QF" "$image" sh -ec "
		mkdir -p /tmp/rpms /tmp/r
		$fetch
		rpm --root /tmp/r --define '_db_backend $backend' --initdb
		rpm --root /tmp/r --define '_db_backend $backend' -i --justdb --nodeps --noscripts --nosignature --nodigest /tmp/rpms/*.rpm
		$IMPORT
		{ rpm --version; rpm --eval '%_db_backend (default); using $backend'; } > /out/info
		rpm --root /tmp/r --define '_db_backend $backend' -qa --qf \"\$QF\" > /out/expected
		cp \$(ls /tmp/r/var/lib/rpm/$dbfile /tmp/r/usr/lib/sysimage/rpm/$dbfile 2>/dev/null | head -n 1) /out/db
	"
	mv "$out/db" "$name" && mv "$out/expected" "$name.expected" && mv "$out/info" "$name.info"
	rmdir "$out"
}

for f in "$@"; do
	case $f in
	bdb)
		IMPORT='rpm --root /tmp/r --define "_db_backend bdb" --import /etc/pki/rpm-gpg/RPM-GPG-KEY-rockyofficial' \
		fixture Packages.bdb docker.io/library/rockylinux:8 bdb Packages \
			"dnf -y -q install 'dnf-command(download)' && dnf -y download --destdir /tmp/rpms --releasever=8 setup basesystem ncurses-base"
		;;
	ndb)
		IMPORT= fixture Packages.ndb docker.io/opensuse/tumbleweed:latest ndb Packages.db \
			"zypper -n --pkg-cache-dir /tmp/zc download filesystem system-user-root aaa_base && cp /tmp/zc/*/*/*.rpm /tmp/rpms/"
		;;
	sqlite)
		IMPORT= fixture rpmdb.sqlite docker.io/library/fedora:latest sqlite rpmdb.sqlite \
			"dnf -y download --destdir /tmp/rpms setup ncurses-base which"
		;;
	rich)
		out=$(mktemp -d)
		"$engine" run --rm -v "$PWD/rich:/rich:ro,Z" -v "$out:/out:Z" \
			registry.fedoraproject.org/fedora:43 sh /rich/build.sh
		for part in db:rich.sqlite expected:rich.sqlite.expected info:rich.sqlite.info \
			scripts:rich.sqlite.scripts queries:rich.sqlite.queries; do
			mv "$out/${part%%:*}" "${part#*:}"
		done
		rmdir "$out"
		;;
	esac
done
