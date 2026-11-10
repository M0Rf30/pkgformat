#!/bin/bash
# Runs inside a debian container (see generate.sh): refreshes the package
# indexes, then records the dpkg status, the plain Packages indexes and what
# `apt-get install -s --no-install-recommends` would do for every target.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
out=/out
targets=/targets.txt

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

	plan=$(apt-get -s install --no-install-recommends "$target")

	# Inst name [installed-version] (candidate-version origin [arch])
	# Inst name (candidate-version origin [arch])
	# Remv name [installed-version]
	echo "$plan" | awk -v t="$target" '
		$1 == "Inst" {
			ver = ($3 ~ /^\[/) ? $4 : $3
			sub(/^\(/, "", ver)
			print t "\tInst\t" $2 "\t" ver
		}
		$1 == "Remv" {
			print t "\tRemv\t" $2 "\t-"
		}' >>"$out/expected.tsv"
done <"$targets"
