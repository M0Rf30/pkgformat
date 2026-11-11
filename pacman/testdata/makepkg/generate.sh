#!/bin/sh
# Rebuilds this directory with the host's makepkg (run as a normal user;
# makepkg runs the package() function under fakeroot):
#
#   ./generate.sh
#
# PKGBUILD makes a tree with every kind of entry a package can hold. The
# files written next to it are what makepkg produced from it:
#
#   tree-shapes-1.0-1-any.pkg.tar.zst   the package
#   mtree.expected    the decompressed .MTREE
#   buildinfo.expected the .BUILDINFO, with the installed packages of ../localdb
#   tar.expected      bsdtar -tvf of the package, owners as numbers
#   pax.expected      the extended header records of the package members
#   md5.expected      the .MTREE line of a file the way makepkg wrote it before it
#                     dropped md5: bsdtar --options md5,sha256
#   info.txt          makepkg and bsdtar versions
set -eu

cd "$(dirname "$0")"
work=$(mktemp -d)
cp PKGBUILD shapes.install ChangeLog "$work/"

# .BUILDINFO lists the installed packages. makepkg asks the program in $PACMAN,
# so give it one that reads the small database of ../localdb instead of the
# host's.
cat >"$work/pacman" <<SHIM
#!/bin/sh
exec pacman --dbpath "$PWD/../localdb" "\$@"
SHIM
chmod +x "$work/pacman"

(
	cd "$work"
	PACMAN=$work/pacman SOURCE_DATE_EPOCH=1700000000 PKGDEST=$work makepkg -f --nodeps --skipinteg >/dev/null 2>&1
)

pkg=$work/tree-shapes-1.0-1-any.pkg.tar.zst
cp "$pkg" .
bsdtar -xOf "$pkg" .MTREE | zcat >mtree.expected
bsdtar -xOf "$pkg" .BUILDINFO >buildinfo.expected
LC_ALL=C TZ=UTC bsdtar --numeric-owner -tvf "$pkg" >tar.expected
zstd -dc "$pkg" | LC_ALL=C strings -n 8 | grep -a 'xattr' | sort >pax.expected || true
# What makepkg asked bsdtar for when .MTREE carried both digests.
mkdir "$work/md5"
printf 'hello\n' >"$work/md5/hello"
touch -d @1700000000 "$work/md5/hello"
(cd "$work/md5" && LANG=C bsdtar -cnf - --format=mtree \
	--options='!all,use-set,type,uid,gid,mode,time,size,md5,sha256,link' hello | gzip -cn) | zcat >md5.expected
{ makepkg --version | sed -n 1p; bsdtar --version; } >info.txt
rm -rf "$work"
