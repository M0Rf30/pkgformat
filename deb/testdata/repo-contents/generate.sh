#!/bin/sh
# Regenerates the fixtures of this directory with the real tools (dpkg-deb and
# apt-ftparchive). Run from anywhere: sh generate.sh
#
# pool/*.deb        packages built with dpkg-deb
# contents.expected the output of `apt-ftparchive contents pool`
# generate.expected Contents-amd64 as written by `apt-ftparchive generate`
#                   for a tree with one component (LongDescription irrelevant)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export SOURCE_DATE_EPOCH=1700000000
umask 022

mkpkg() { # name version arch section extra-control
	root="$work/src-$1"
	mkdir -p "$root/DEBIAN"
	{
		echo "Package: $1"
		echo "Version: $2"
		echo "Architecture: $3"
		echo "Maintainer: Test <test@example.org>"
		[ -n "$4" ] && echo "Section: $4"
		echo "Priority: optional"
		echo "Description: $1 test package"
		echo " The long description of $1."
		echo " ."
		echo " Second paragraph."
	} >"$root/DEBIAN/control"
}

# alpha: section utils, a symlink, a path with blanks, a path shared with beta
mkpkg alpha 1.0-1 amd64 utils
a="$work/src-alpha"
mkdir -p "$a/usr/bin" "$a/usr/share/with space" "$a/usr/share/doc/alpha"
printf '#!/bin/sh\n' >"$a/usr/bin/alpha"
chmod 755 "$a/usr/bin/alpha"
ln -s alpha "$a/usr/bin/alpha-link"
printf 'x' >"$a/usr/share/with space/file one.txt"
printf 'c' >"$a/usr/share/doc/alpha/copyright"

# beta: no Section, a conffile, the same /usr/bin/alpha path
mkpkg beta 2.0 amd64 ""
b="$work/src-beta"
mkdir -p "$b/usr/bin" "$b/etc"
printf '#!/bin/sh\n' >"$b/usr/bin/beta"
chmod 755 "$b/usr/bin/beta"
printf 'v' >"$b/usr/bin/alpha"
printf 'cfg' >"$b/etc/beta.conf"

# gamma: section libs/sub-section name with a slash, architecture all, a hard link
mkpkg gamma 3.1 all libs/extra
g="$work/src-gamma"
mkdir -p "$g/usr/lib/gamma"
printf 'lib' >"$g/usr/lib/gamma/libgamma.so.1"
ln "$g/usr/lib/gamma/libgamma.so.1" "$g/usr/lib/gamma/libgamma.so.1.0"

rm -rf "$here/pool"
mkdir -p "$here/pool"
dpkg-deb -Zxz --root-owner-group -b "$a" "$here/pool/alpha_1.0-1_amd64.deb" >/dev/null
dpkg-deb -Zgzip --root-owner-group -b "$b" "$here/pool/beta_2.0_amd64.deb" >/dev/null
dpkg-deb -Zzstd --root-owner-group -b "$g" "$here/pool/gamma_3.1_all.deb" >/dev/null

(cd "$here" && apt-ftparchive contents pool >contents.expected)

# A tree run: the Contents of a component as apt-ftparchive generate writes it.
tree="$work/tree"
mkdir -p "$tree/pool/main" "$tree/dists/x/main/binary-amd64" "$tree/cache"
cp "$here"/pool/*.deb "$tree/pool/main/"
cat >"$work/ftp.conf" <<EOF
Dir { ArchiveDir "$tree"; CacheDir "$tree/cache"; };
Default { Packages::Compress "."; Contents::Compress "."; };
TreeDefault { Directory "pool/\$(SECTION)"; Contents "\$(DIST)/Contents-\$(ARCH)"; };
Tree "dists/x" { Sections "main"; Architectures "amd64"; };
EOF
(cd "$tree" && apt-ftparchive generate "$work/ftp.conf" >/dev/null)
cp "$tree/dists/x/Contents-amd64" "$here/generate.expected"
