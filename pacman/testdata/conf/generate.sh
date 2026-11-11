#!/bin/sh
# Regenerates expected/ from the fixtures with the real pacman-conf.
#
#   expected/<fixture>.txt     pacman-conf -c <fixture>        (stdout)
#   expected/<fixture>.warn    the same run's stderr (unknown-directive warnings)
#   expected/<fixture>.repos   pacman-conf -c <fixture> --repo-list
#   expected/invalid/<name>.err  stderr of the run on invalid/<name>.conf, which must fail
#   expected/VERSION           pacman and pacman-conf versions
#
# Run on an x86_64 Arch Linux host: pacman-conf resolves "Architecture = auto"
# with uname -m and RootDir, DBPath and GPGDir must exist (the fixtures use
# /usr, /usr/lib and /usr/bin). Include paths are relative to this directory,
# which is therefore the working directory of every run.
set -eu

cd "$(dirname "$0")"

rm -rf expected
mkdir -p expected/invalid

{
	pacman-conf --version
	pacman -V | sed -n 's/^.*\(Pacman v[^ ]* - libalpm v[^ ]*\).*$/\1/p'
	uname -m
} >expected/VERSION

for f in *.conf; do
	n=${f%.conf}
	pacman-conf -c "$f" >"expected/$n.txt" 2>"expected/$n.warn"
	pacman-conf -c "$f" --repo-list >"expected/$n.repos" 2>/dev/null
done

for f in invalid/*.conf; do
	n=$(basename "$f" .conf)
	if pacman-conf -c "$f" >/dev/null 2>"expected/invalid/$n.err"; then
		echo "$f: pacman-conf accepted it" >&2
		exit 1
	fi
done
