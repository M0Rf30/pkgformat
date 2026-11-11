#!/bin/bash
# Runs inside a debian container (see generate.sh): refreshes the package
# indexes, then records the dpkg status, the plain Packages indexes, what
# `apt-get -s install --no-install-recommends` plans for every target, and,
# after installing packages on top of the image, what it plans for the
# scenarios of installed/scenarios.txt.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive LC_ALL=C
out=/out
targets=/targets.txt

# shellcheck source=record.sh
. /record.sh

# Plain, uncompressed indexes, whatever the image's apt configuration says.
rm -f /etc/apt/apt.conf.d/docker-gzip-indexes /etc/apt/apt.conf.d/docker-clean
rm -rf /var/lib/apt/lists/*
apt-get -o Acquire::GzipIndexes=false update -qq

mkdir -p "$out/lists"
cp /var/lib/dpkg/status "$out/status"

for f in /var/lib/apt/lists/*_Packages; do
	cp "$f" "$out/lists/$(basename "$f")"
done

{
	echo "image: $(. /etc/os-release && echo "$PRETTY_NAME")"
	echo "apt: $(apt-get --version | head -n 1)"
	echo "dpkg: $(dpkg --version | head -n 1)"
	echo "architecture: $(dpkg --print-architecture)"
	echo "captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$out/MANIFEST"

: >"$out/expected.tsv"

while read -r target; do
	case "$target" in '' | '#'*) continue ;; esac

	record_plan "$target" install "$target" >>"$out/expected.tsv"
done <"$targets"

# Second state: packages installed on top of the image.
mkdir -p "$out/installed"
# shellcheck disable=SC2046 # one argument per line, none with spaces
apt-get install -y -qq --no-install-recommends $(grep -v '^#' /installed/preinstall.txt) >/dev/null
cp /var/lib/dpkg/status "$out/installed/status"

: >"$out/installed/expected.tsv"

while IFS=$'\t' read -r id args; do
	case "$id" in '' | '#'*) continue ;; esac

	# shellcheck disable=SC2086 # the arguments are split on purpose
	record_plan "$id" $args >>"$out/installed/expected.tsv"
done </installed/scenarios.txt
