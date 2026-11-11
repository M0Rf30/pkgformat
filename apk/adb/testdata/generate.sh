#!/bin/sh
# Regenerates the fixtures of this directory with apk-tools 3.0.9 (apk mkpkg,
# apk mkndx, apk adbdump). The trees and the metadata below are mirrored by
# fixtureSpec in fixtures_test.go, which checks that the writer of this package
# reproduces the ADB block of every unsigned fixture byte for byte.
#
# Needs: apk (3.x), openssl, setfattr, podman. The tool runs in a user
# namespace that maps the invoking user to root, so that every file is owned by
# root:root as far as apk can tell, whoever runs this.
#
#   sh generate.sh
#
# The signed fixtures are signed with throwaway keys made here; only the public
# halves are kept. EC signatures are randomized, so those fixtures differ every
# time they are made.
set -eu

here=$(cd "$(dirname "$0")" && pwd)

if [ -z "${ADB_FIXTURES_IN_USERNS:-}" ]; then
	ADB_FIXTURES_IN_USERNS=1 exec podman unshare sh "$here/generate.sh"
fi

# apk takes the modification time of every file from SOURCE_DATE_EPOCH.
export SOURCE_DATE_EPOCH=1700000000
BUILD_TIME=1700000000

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

out=$here
keys=$work/keys
mkdir -p "$keys"

mkpkg() { # name, extra apk arguments...
	name=$1
	shift
	apk mkpkg --output "$out/$name.apk" "$@"
	apk adbdump "$out/$name.apk" >"$out/$name.dump" || true
}

# --- trees -----------------------------------------------------------------

tree=$work/tree
mkdir -p "$tree/usr/bin" "$tree/etc" "$tree/usr/share/doc/tree" "$tree/var/empty" "$tree/var/lib/app/state"
printf '#!/bin/sh\necho hello\n' >"$tree/usr/bin/hello"
chmod 755 "$tree/usr/bin/hello"
printf 'su\n' >"$tree/usr/bin/su"
chmod 4755 "$tree/usr/bin/su"
ln -s hello "$tree/usr/bin/hi"
printf 'conf\n' >"$tree/etc/app.conf"
chmod 644 "$tree/etc/app.conf"
ln "$tree/etc/app.conf" "$tree/etc/app.conf.hard"
printf '' >"$tree/etc/empty"
chmod 600 "$tree/etc/empty"
head -c 100000 /dev/zero | tr '\0' x >"$tree/usr/share/doc/tree/big"
chmod 644 "$tree/usr/share/doc/tree/big"
printf 'readme\n' >"$tree/README"
chmod 644 "$tree/README"
chmod 700 "$tree/var/empty"
setfattr -n user.fixture -v v1 "$tree/etc/app.conf"

mkdir -p "$work/one/usr/bin"
printf 'one\n' >"$work/one/usr/bin/one"
chmod 755 "$work/one/usr/bin/one"

# --- packages --------------------------------------------------------------

mkpkg minimal --info name:minimal --info version:1.0-r0 --info arch:x86_64 \
	--info build-time:$BUILD_TIME

mkpkg tree --files "$tree" --xattrs \
	--info name:tree --info version:1.0-r0 --info arch:x86_64 \
	--info build-time:$BUILD_TIME \
	--info 'description:Fixture with every kind of entry' --info license:MIT

for c in none deflate:9 zstd:3; do
	mkpkg "tree-$(echo "$c" | tr -d :)" --files "$tree" --xattrs --compression "$c" \
		--info name:tree --info version:1.0-r0 --info arch:x86_64 \
		--info build-time:$BUILD_TIME \
		--info 'description:Fixture with every kind of entry' --info license:MIT
done

for v in 3.0.0_pre3 3.0.0_rc9; do
	mkpkg "tree-compat-$(echo "$v" | tr -d _.)" --files "$tree" --xattrs --compat "$v" \
		--info name:tree --info version:1.0-r0 --info arch:x86_64 \
		--info build-time:$BUILD_TIME \
		--info 'description:Fixture with every kind of entry' --info license:MIT
done

printf '#!/bin/sh\necho trigger\n' >"$work/trigger.sh"
printf '#!/bin/sh\necho pre-install\n' >"$work/pre-install.sh"
printf '#!/bin/sh\necho post-install\n' >"$work/post-install.sh"
printf '#!/bin/sh\necho pre-deinstall\n' >"$work/pre-deinstall.sh"
printf '#!/bin/sh\necho post-deinstall\n' >"$work/post-deinstall.sh"
printf '#!/bin/sh\necho pre-upgrade\n' >"$work/pre-upgrade.sh"
printf '#!/bin/sh\necho post-upgrade\n' >"$work/post-upgrade.sh"

mkpkg full --files "$work/one" \
	--info name:full --info version:1.2.3_rc1-r4 --info arch:x86_64 \
	--info 'description:Full test' --info 'license:MIT BSD-2-Clause' \
	--info url:https://example.org --info origin:fullorigin \
	--info 'maintainer:A B <a@b.c>' --info build-time:$BUILD_TIME \
	--info repo-commit:0123456789abcdef0123456789abcdef01234567 \
	--info provider-priority:10 --info layer:1 --info replaces-priority:5 \
	--info 'depends:busybox>=1.0 !conflicting so:libc.musl-x86_64.so.1 foo~1.2 bar<2 baz<=3 qux>4 quux=5 foo~1.2' \
	--info 'provides:cmd:full=1.2.3-r4 virt' --info replaces:other \
	--info 'install-if:foo=1 bar' --info 'recommends:rec1 rec2' --info 'tags:b a' \
	--script trigger:"$work/trigger.sh" --script pre-install:"$work/pre-install.sh" \
	--script post-install:"$work/post-install.sh" --script pre-deinstall:"$work/pre-deinstall.sh" \
	--script post-deinstall:"$work/post-deinstall.sh" --script pre-upgrade:"$work/pre-upgrade.sh" \
	--script post-upgrade:"$work/post-upgrade.sh" \
	--trigger '/usr/share/*' --trigger /lib/x

# --- signed packages -------------------------------------------------------

openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$keys/rsa.priv" 2>/dev/null
openssl pkey -in "$keys/rsa.priv" -pubout -out "$out/rsa.pub"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$keys/ec.priv" 2>/dev/null
openssl pkey -in "$keys/ec.priv" -pubout -out "$out/ec.pub"

for k in rsa ec; do
	mkpkg "signed-$k" --files "$work/one" --sign-key "$keys/$k.priv" \
		--info name:signed --info version:1.0-r0 --info arch:x86_64 --info build-time:$BUILD_TIME
done

# --- indexes ---------------------------------------------------------------

mkdir "$work/repo"
for p in minimal tree full; do
	case $p in
	minimal) v=1.0-r0 ;;
	tree) v=1.0-r0 ;;
	full) v=1.2.3_rc1-r4 ;;
	esac
	cp "$out/$p.apk" "$work/repo/$p-$v.apk"
done

apk --allow-untrusted mkndx --description 'fixture index' \
	--pkgname-spec '${name}-${version}.apk' \
	--output "$out/index.adb" "$work"/repo/*.apk
apk --allow-untrusted adbdump "$out/index.adb" >"$out/index.dump" || true

apk --allow-untrusted mkndx --description 'fixture index' \
	--pkgname-spec '${name}-${version}.apk' --sign-key "$keys/rsa.priv" \
	--output "$out/index-signed.adb" "$work"/repo/*.apk
apk --allow-untrusted adbdump "$out/index-signed.adb" >"$out/index-signed.dump" || true
