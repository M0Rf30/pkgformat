#!/bin/sh
# Regenerates this directory with the host's repo-add, gpg and pacman. The
# package is the one makepkg built in ../makepkg.
#
#   ./generate.sh
#
#   repo.db.tar.gz      repo-add --include-sigs: the sync database
#   repo.files.tar.gz   the files database repo-add writes next to it
#   package.sig         the detached signature (a throw-away ed25519 key) of
#                       ../makepkg/tree-shapes-1.0-1-any.pkg.tar.zst
#   Fl.expected         pacman -Fl tree-shapes, after pacman -Fy of the repo
#   F.expected          pacman -F usr/bin/shape-sym
#   info.txt            repo-add and pacman
set -eu

cd "$(dirname "$0")"
pkg=../makepkg/tree-shapes-1.0-1-any.pkg.tar.zst
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

mkdir "$work/repo" "$work/gnupg" "$work/root" "$work/root/db" "$work/root/db/sync" "$work/root/cache" "$work/root/gnupg"
chmod 700 "$work/gnupg"
cp "$pkg" "$work/repo/"
gpg --homedir "$work/gnupg" --batch --pinentry-mode loopback --passphrase '' \
	--quick-generate-key 'pkgformat fixture <fixture@example.org>' ed25519 sign never 2>/dev/null
gpg --homedir "$work/gnupg" --batch --pinentry-mode loopback --passphrase '' \
	--detach-sign --output "$work/repo/$(basename "$pkg").sig" "$work/repo/$(basename "$pkg")"
repo-add --include-sigs "$work/repo/repo.db.tar.gz" "$work/repo/$(basename "$pkg")" >/dev/null 2>&1

cat >"$work/pacman.conf" <<CONF
[options]
Architecture = x86_64
SigLevel = Never

[repo]
Server = file://$work/repo
CONF

p() {
	LC_ALL=C unshare -rm pacman --root "$work/root" --dbpath "$work/root/db" --cachedir "$work/root/cache" \
		--gpgdir "$work/root/gnupg" --config "$work/pacman.conf" "$@"
}
p -Fy >/dev/null 2>&1
p -Fl tree-shapes >Fl.expected
p -F usr/bin/shape-sym >F.expected

cp "$work/repo/repo.db.tar.gz" "$work/repo/repo.files.tar.gz" .
cp "$work/repo/$(basename "$pkg").sig" package.sig
{ repo-add --version | head -1; pacman --version | grep -o 'Pacman v[0-9.a-z]*'; gpg --version | head -1; } >info.txt
