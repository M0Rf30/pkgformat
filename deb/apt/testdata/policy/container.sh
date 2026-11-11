#!/bin/bash
# Runs inside a Debian container (see generate.sh). For every scenario it
# installs the preferences, the dpkg status and the default release, and records
# what apt makes of them: `apt-cache policy` (package files and per-package
# version tables), `apt-get -s install` of every package, and
# `apt-get -s upgrade`.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export LC_ALL=C
unset SOURCE_DATE_EPOCH

out=/out
only=${SCENARIOS:-}

aptversion=$(apt-get --version | sed -n 1p)
image=$(. /etc/os-release && echo "Debian GNU/Linux ${VERSION_ID:-unstable}")

dpkg --add-architecture i386
rm -rf /var/lib/apt/lists/*
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* /etc/apt/preferences /etc/apt/apt.conf.d/docker-*
mkdir -p /var/lib/apt/lists/partial
cp /repo/lists/* /var/lib/apt/lists/
cp /repo/sources.list /etc/apt/sources.list

# The packages of the repository: native ones by name, i386 ones with their
# architecture.
specs=$(
	for f in /repo/lists/*_Packages; do
		suffix=
		case $f in *_binary-i386_Packages) suffix=:i386 ;; esac
		awk -v s="$suffix" '/^Package: / { print $2 s }' "$f"
	done
	echo gone
)
specs=$(printf '%s\n' $specs | sort -u)

{
	echo "image: $image"
	echo "apt: $aptversion"
	echo "captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$out/MANIFEST"

# first_result NAME: the outcome of `apt-get -s install` for NAME on stdin.
first_result() {
	awk -v s="$1" '
		$1 == "Inst" && $2 == s && !done { v = ($3 ~ /^\[/) ? $4 : $3; sub(/^\(/, "", v); print "inst=" v; done = 1 }
		$0 ~ "^" s " is already the newest version" && !done { v = $0; sub(/^.*\(/, "", v); sub(/\)\.$/, "", v); print "same=" v; done = 1 }
		/^E: / && !err { err = $0 }
		END { if (!done) print (err != "" ? "error=" err : "none") }
	'
}

for dir in /scenarios/*/; do
	name=$(basename "$dir")
	if [ -n "$only" ] && ! printf '%s\n' $only | grep -qx "$name"; then
		continue
	fi

	rm -rf /etc/apt/preferences /etc/apt/preferences.d
	mkdir -p /etc/apt/preferences.d
	[ -f "$dir/preferences" ] && cp "$dir/preferences" /etc/apt/preferences
	if [ -d "$dir/preferences.d" ]; then
		cp -a "$dir/preferences.d/." /etc/apt/preferences.d/
		# A name with a trailing dot cannot be committed (module zips refuse it):
		# scenarios store it with a ".DOT" suffix in place of the dot.
		for f in /etc/apt/preferences.d/*.DOT; do
			if [ -e "$f" ]; then mv "$f" "${f%DOT}"; fi
		done
	fi

	status=$(sed -n 's/^status: //p' "$dir/scenario")
	cp "/repo/status/$status" /var/lib/dpkg/status

	opts=()
	target=$(sed -n 's/^default-release: //p' "$dir/scenario")
	if [ -n "$target" ]; then
		opts=(-o "APT::Default-Release=$target")
	fi

	res="$out/scenarios/$name"
	mkdir -p "$res"

	rc=0
	apt-cache "${opts[@]}" policy >"$res/files" 2>"$res/stderr" || rc=$?
	echo "$rc" >"$res/rc"

	# shellcheck disable=SC2086
	apt-cache "${opts[@]}" policy $specs >"$res/policy" 2>>"$res/stderr" || true

	: >"$res/install.tsv"
	for spec in $specs; do
		result=$({ apt-get -s "${opts[@]}" install "$spec" 2>&1 || true; } | first_result "$spec")
		printf '%s\t%s\n' "$spec" "$result" >>"$res/install.tsv"
	done

	{ apt-get -s "${opts[@]}" upgrade 2>&1 || true; } |
		awk '$1 == "Inst" { v = ($3 ~ /^\[/) ? $4 : $3; sub(/^\(/, "", v); print $2 "=" v }' | sort >"$res/upgrade.tsv"
done
