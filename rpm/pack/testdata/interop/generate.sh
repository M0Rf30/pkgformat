#!/bin/bash
# Regenerates the reference packages in this directory.
#
#   rpmbuild (host)   ref-feat-v4.rpm ref-feat-v6.rpm ref-trig.rpm ref-bar.rpm
#   container         trigger-order.txt (execution order of scriptlets and triggers)
#                     signbase-signed.rpm (rpmsign --signfiles --signverity)
#   rpmspec (host)    richdeps.tsv
#
# The container needs rpm, rpm-sign, fsverity-utils and ima-evm-utils; name a
# Fedora based image with them in PKGFORMAT_RPM_IMAGE. The packages pack builds
# for the container come from `go test -run TestInteropEmit` with
# PKGFORMAT_EMIT set.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
: "${PKGFORMAT_RPM_IMAGE:?name a container image with rpm-sign, fsverity-utils and ima-evm-utils}"
epoch=1700000000
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

build() { # spec format payload
	local top="$work/top-$1-$2"
	mkdir -p "$top"
	SOURCE_DATE_EPOCH=$epoch rpmbuild -bb --quiet --define "_topdir $top" \
		--define "_rpmformat $2" --define "_binary_payload $3" \
		--define "clamp_mtime_to_source_date_epoch 1" \
		--define "use_source_date_epoch_as_buildtime 1" \
		--define "source_date_epoch_from_changelog 0" "$here/$1.spec" >&2
	cp "$top"/RPMS/*/*.rpm "$4"
}
build feat 4 w9.gzdio "$here/ref-feat-v4.rpm"
build feat 6 w9.gzdio "$here/ref-feat-v6.rpm"
build trig 4 w9.gzdio "$here/ref-trig.rpm"
build bar 4 w9.gzdio "$here/ref-bar.rpm"

(cd "$here" && ./corpus-gen.sh | awk -F'\t' '$2 ~ /^\(/ && $2 !~ / $/' > richdeps.tsv)

emit="$work/emit"
mkdir -p "$emit"
(cd "$repo" && PKGFORMAT_EMIT="$emit" go test -count=1 -run TestInteropEmit ./rpm/pack)

run() { podman run --rm -v "$1:/work:Z" -v "$here:/here:Z" -w /work "$PKGFORMAT_RPM_IMAGE" "${@:2}"; }
mkdir -p "$work/ref" "$work/pack"
cp "$here/ref-trig.rpm" "$work/ref/trig.rpm"; cp "$here/ref-bar.rpm" "$work/ref/bar.rpm"
cp "$emit/trig.rpm" "$emit/bar.rpm" "$work/pack/"
run "$work/ref" sh /here/scenario.sh trig.rpm bar.rpm > "$work/order-ref.txt"
run "$work/pack" sh /here/scenario.sh trig.rpm bar.rpm > "$work/order-pack.txt"
diff -u "$work/order-ref.txt" "$work/order-pack.txt"
cp "$work/order-ref.txt" "$here/trigger-order.txt"

# file signatures: the same unsigned package, signed by rpmsign
cp "$emit/signbase.rpm" "$work/signbase.rpm"
cp "$here/sign-key.pem" "$here/sign-cert.pem" "$work/"
run "$work" bash -c '
	export GNUPGHOME=/tmp/gh; mkdir -p -m700 $GNUPGHOME
	gpg --batch --passphrase "" --quick-gen-key sign@example.org rsa2048 sign never 2>/dev/null
	fpr=$(gpg --list-keys --with-colons | awk -F: "/^fpr/{print \$10; exit}")
	rpmsign -D "_openpgp_sign_id $fpr" --addsign --signfiles --signverity \
		--fskpath sign-key.pem --certpath sign-cert.pem signbase.rpm'
cp "$work/signbase.rpm" "$here/signbase-signed.rpm"
