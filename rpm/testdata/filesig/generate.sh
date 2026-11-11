#!/bin/sh
# Regenerates the fixtures of this directory in a Fedora 43 container:
#   ima-v4.rpm, ima-v6.rpm        ../meta/meta-v{4,6}.rpm with IMA file
#                                  signatures (rpmsign --signfiles)
#   verity-v4.rpm, verity-v6.rpm  ../hello.rpm and ../v6/ref-v6.rpm with
#                                  fs-verity signatures (rpmsign --signverity;
#                                  rpmsign 6.0.2 crashes on packages with FIFOs)
#   ima.der, verity.crt           the certificates of the throwaway keys
#   expected.txt                  fsverity digest of the files of the verity
#                                  packages, as computed by fsverity(1)
# Usage: ./generate.sh (needs podman); the private keys are not kept.
set -e
cd "$(dirname "$0")"
cp ../meta/meta-v4.rpm ../meta/meta-v6.rpm ../hello.rpm .
cp ../v6/ref-v6.rpm .
podman run --rm -v "$PWD:/w:Z" registry.fedoraproject.org/fedora:43 sh -ec '
cd /w
dnf -q -y install rpm-sign fsverity-utils openssl gnupg2 cpio >/dev/null 2>&1
export GNUPGHOME=$(mktemp -d)
gpg --batch --passphrase "" --quick-gen-key "filesig test <filesig@example.invalid>" rsa3072 sign never 2>/dev/null
k=$(mktemp -d)
openssl req -x509 -newkey rsa:2048 -nodes -keyout $k/ima.key -out $k/ima.crt -days 36500 -subj /CN=ima-test 2>/dev/null
openssl x509 -in $k/ima.crt -outform DER -out ima.der
openssl req -x509 -newkey rsa:2048 -nodes -keyout $k/verity.key -out verity.crt -days 36500 -subj /CN=verity-test 2>/dev/null
sign() { rpmsign --define "_gpg_name filesig test" --addsign "$@" >/dev/null; }
for v in 4 6; do cp meta-v$v.rpm ima-v$v.rpm; sign --signfiles --fskpath $k/ima.key --certpath ima.der ima-v$v.rpm; done
cp hello.rpm verity-v4.rpm; cp ref-v6.rpm verity-v6.rpm
for v in 4 6; do sign --signverity --fskpath $k/verity.key --certpath verity.crt verity-v$v.rpm; done
: > expected.txt
for v in 4 6; do
  x=$(mktemp -d); (cd $x && rpm2cpio /w/verity-v$v.rpm | cpio -idm 2>/dev/null && find . -type f | sort | while read f; do echo "verity-v$v.rpm $(fsverity digest "$f" | cut -d" " -f1) ${f#.}"; done) >> expected.txt
done
# fs-verity digests of files of N bytes, byte i being i % 251, for the
# Merkle tree sizes the test covers (empty, one block, several levels)
: > vectors.txt
for i in $(seq 0 250); do printf "\\$(printf %03o $i)"; done > /tmp/pat
for n in 0 1 4095 4096 4097 524288 528385; do
  for r in $(seq 0 $((n / 251))); do cat /tmp/pat; done | head -c $n > /tmp/v
  for a in sha256 sha512; do echo "$n $a $(fsverity digest --hash-alg=$a /tmp/v | cut -d" " -f1)" >> vectors.txt; done
done
'
rm -f meta-v4.rpm meta-v6.rpm hello.rpm ref-v6.rpm
