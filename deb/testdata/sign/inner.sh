#!/bin/sh
# Runs inside the container with the fixture directory mounted at /w.
set -eu
export GNUPGHOME=/tmp/gnupg
mkdir -m 700 -p "$GNUPGHOME"
cd /w

# A throw-away signing key; the private half is committed on purpose.
gpg --batch --quiet --passphrase '' --quick-generate-key 'Pkgformat Test <test@example.org>' rsa3072 sign never
FPR=$(gpg --batch --with-colons --list-keys | awk -F: '/^fpr:/ {print $10; exit}')
KEYID=$(printf '%s' "$FPR" | tail -c 16)
gpg --batch --armor --export "$FPR" > pub.asc
gpg --batch --export "$FPR" > pub.gpg
gpg --batch --armor --export-secret-keys "$FPR" > key.asc
printf '%s\n' "$FPR" > fingerprint.txt

# An unsigned package built by dpkg-deb.
rm -rf /tmp/pkg && mkdir -p /tmp/pkg/DEBIAN /tmp/pkg/usr/share/hello
cat > /tmp/pkg/DEBIAN/control <<CTL
Package: hello-sign
Version: 1.0-1
Architecture: all
Maintainer: Test <test@example.org>
Description: signature fixture
 A package used to test package signatures.
CTL
echo hello > /tmp/pkg/usr/share/hello/hello.txt
SOURCE_DATE_EPOCH=1700000000 dpkg-deb --root-owner-group -Zgzip --build /tmp/pkg unsigned.deb

cp unsigned.deb real-debsigs.deb
# debsig-verify rejects SHA-1 signatures, which gpg 2.2 makes by default
# and debsigs gives no way to change but through gpg.conf.
echo "digest-algo SHA256" > "$GNUPGHOME/gpg.conf"
debsigs --sign=origin --default-key="$FPR" real-debsigs.deb
cp unsigned.deb real-dpkg-sig.deb
dpkg-sig -k "$FPR" -s builder real-dpkg-sig.deb

# debsig-verify needs a policy and a keyring under fixed paths.
mkdir -p "/etc/debsig/policies/$KEYID" "/usr/share/debsig/keyrings/$KEYID"
cp pub.gpg "/usr/share/debsig/keyrings/$KEYID/debsig.gpg"
sed "s/@KEYID@/$KEYID/g" policy.pol.in > "/etc/debsig/policies/$KEYID/pkgformat.pol"
cp "/etc/debsig/policies/$KEYID/pkgformat.pol" policy.pol

{
  echo '$ debsig-verify real-debsigs.deb'
  debsig-verify -v real-debsigs.deb 2>&1 || echo "exit status $?"
  echo '$ dpkg-sig --verify real-dpkg-sig.deb'
  dpkg-sig --verify real-dpkg-sig.deb 2>&1 || echo "exit status $?"
} > real-tools.txt
