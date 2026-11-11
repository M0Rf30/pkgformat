#!/bin/bash
# Regenerates the keys and signed files of this directory with the gpg on the
# host (written against GnuPG 2.4). The keys are throw-away ed25519 keys that
# never expire; running the script again makes different keys, so the Go tests
# read every fingerprint from fingerprints.txt and nothing is hard-coded.
#
#   deb/apt/testdata/keyring/generate.sh
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
home=$(mktemp -d)
trap 'gpgconf --homedir "$home" --kill all 2>/dev/null || true; rm -rf "$home"' EXIT
chmod 700 "$home"
export GNUPGHOME=$home

gen() { gpg --batch --passphrase '' --quick-generate-key "$1" ed25519 "$2" never 2>/dev/null; }
primary_fpr() { gpg --batch --with-colons --list-keys "$1" | awk -F: '$1 == "fpr" { print $10; exit }'; }
sub_fpr() { gpg --batch --with-colons --list-keys "$1" | awk -F: '$1 == "sub" { s = 1 } s && $1 == "fpr" { print $10; exit }'; }

# A: a signing primary key. B: another one. C: a certify-only primary key whose
# signing subkey does the signing.
gen 'Key A <a@example.invalid>' sign
gen 'Key B <b@example.invalid>' sign
gen 'Key C <c@example.invalid>' cert

fa=$(primary_fpr a@example.invalid)
fb=$(primary_fpr b@example.invalid)
fc=$(primary_fpr c@example.invalid)
gpg --batch --passphrase '' --quick-add-key "$fc" ed25519 sign never 2>/dev/null
fcs=$(sub_fpr c@example.invalid)

rm -f "$here"/*.asc "$here"/*.gpg "$here"/*.txt
gpg --batch --armor --export "$fa" >"$here/a.asc"
gpg --batch --export "$fa" >"$here/a.gpg"
gpg --batch --armor --export "$fb" >"$here/b.asc"
gpg --batch --armor --export "$fc" >"$here/c.asc"
gpg --batch --export "$fb" "$fc" >"$here/bc.gpg"

printf 'A %s\nB %s\nC %s\nC-subkey %s\n' "$fa" "$fb" "$fc" "$fcs" >"$here/fingerprints.txt"

text=$'Origin: keyring-test\nSuite: stable\nCodename: stable\nDate: Sat, 01 Jan 2022 00:00:00 UTC\n'
printf '%s' "$text" | gpg --batch --local-user "$fa" --clearsign >"$here/signed-by-a.txt" 2>/dev/null
printf '%s' "$text" | gpg --batch --local-user "$fb" --clearsign >"$here/signed-by-b.txt" 2>/dev/null
printf '%s' "$text" | gpg --batch --local-user "$fcs!" --clearsign >"$here/signed-by-c-subkey.txt" 2>/dev/null
gpg --version | head -n 1 >"$here/gpg-version.txt"
