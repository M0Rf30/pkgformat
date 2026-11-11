#!/usr/bin/env bash
# End-to-end proof that apt consumes the Packages.diff this package publishes.
#
# It publishes a repository with deb.PDiffIndexBuilder (mkrepo), serves it from
# the host, and lets "apt-get update" in a Debian container fetch it several
# times, keeping the container's /var/lib/apt/lists between runs. The server
# log shows what apt downloaded: the first run takes the whole Packages.xz,
# every later run only Packages.diff/Index and the patches.
#
# Needs: go, podman and a local Debian image with apt (default
# localhost/debtools:bookworm; IMAGE=docker.io/library/debian:bookworm works).
# No network access outside the host is used.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../.." && pwd)
image=${IMAGE:-localhost/debtools:bookworm}
work=$(mktemp -d)
trap 'kill "${server:-0}" 2>/dev/null || true; rm -rf "$work"' EXIT

(cd "$root" && go build -o "$work/mkrepo" ./deb/testdata/repo-pdiff-e2e/mkrepo)
mkdir -p "$work/repo" "$work/lists" "$work/w"
cp "$here/apt-update.sh" "$work/w/"

"$work/mkrepo" publish -repo "$work/repo" -step 1
"$work/mkrepo" serve -repo "$work/repo" -addr 127.0.0.1:0 -log "$work/access.log" >"$work/serve.out" &
server=$!
for _ in $(seq 50); do
	grep -q listening "$work/serve.out" && break
	sleep 0.1
done
port=$(sed 's/.*://' "$work/serve.out")

update() {
	: >"$work/access.log"
	podman run --rm --network=host \
		-v "$work/lists:/var/lib/apt/lists" -v "$work/w:/w:ro" "$image" sh /w/apt-update.sh "$port" | tee "$work/apt.out"
	echo "--- what the server was asked for:"
	cat "$work/access.log"
	got=$(sed -n 's/^LIST-SHA256 //p' "$work/apt.out")
	want=$(sha256sum <"$work/repo/dists/e2e/main/binary-amd64/Packages" | cut -d' ' -f1)
	[ "$got" = "$want" ] || { echo "FAIL: apt's Packages differs from the published one"; exit 1; }
}

expect() { grep -q "$1" "$work/access.log" || { echo "FAIL: expected a request for $1"; exit 1; }; }
reject() { ! grep -q "$1" "$work/access.log" || { echo "FAIL: unexpected request for $1"; exit 1; }; }

echo "== 1: first update, apt has nothing to patch"
update
expect 'Packages.xz'
reject 'Packages.diff'

echo "== 2: one publication behind"
"$work/mkrepo" publish -repo "$work/repo" -step 2
update
expect 'Packages.diff/Index'
expect 'Packages.diff/2026-06-01-0200.00.gz'
reject 'Packages.xz'

echo "== 3: three publications behind, unmerged patches: three downloads"
for s in 3 4 5; do "$work/mkrepo" publish -repo "$work/repo" -step $s; done
update
expect 'Packages.diff/Index'
[ "$(grep -c 'Packages.diff/2026.*\.gz' "$work/access.log")" = 3 ] || { echo "FAIL: expected three patches"; exit 1; }
reject 'Packages.xz'

echo "== 4: three publications behind, merged patches: one download"
for s in 6 7 8; do "$work/mkrepo" publish -repo "$work/repo" -step $s -merge; done
update
expect 'Packages.diff/Index'
[ "$(grep -c 'Packages.diff/T-.*\.gz' "$work/access.log")" = 1 ] || { echo "FAIL: expected one merged patch"; exit 1; }
reject 'Packages.xz'

echo "OK"
