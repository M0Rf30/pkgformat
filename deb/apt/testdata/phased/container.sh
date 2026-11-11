#!/bin/bash
# Runs inside a Debian container (see generate.sh). Installs the fixture
# repository as apt lists and dpkg status, then records which upgrades
# `apt-get -s upgrade` offers for many machine identifiers.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
unset SOURCE_DATE_EPOCH
out=/out

# apt does not phase updates in a chroot; the container must not look like one.
rc=0
ischroot -t || rc=$?
if [ "$rc" -ne 1 ]; then
	echo "ischroot -t returned $rc: this container looks like a chroot, phasing would be off" >&2
	exit 1
fi

libstdcxx=$(dpkg-query -W -f '${Package} ${Version}' libstdc++6)
image=$(. /etc/os-release && echo "Debian GNU/Linux ${VERSION_ID:-unstable}")
aptversion=$(apt-get --version | sed -n 1p)

rm -rf /var/lib/apt/lists/*
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* /etc/apt/apt.conf.d/docker-*
mkdir -p /var/lib/apt/lists/partial
cp /repo/*_Release /repo/*_Packages /var/lib/apt/lists/
cp /repo/sources.list /etc/apt/sources.list
cp /repo/status /var/lib/dpkg/status

# offered OPTION... : the packages `apt-get -s upgrade` would upgrade, sorted.
offered() {
	{ apt-get -s "$@" upgrade 2>/dev/null || true; } | awk '$1 == "Inst" { print $2 }' | sort | tr '\n' ' ' | sed 's/ $//'
}

{
	echo "image: $image"
	echo "apt: $aptversion"
	echo "libstdc++: $libstdcxx"
	echo "ischroot: not a chroot"
	echo "captured: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$out/MANIFEST"

# One line per machine identifier: the packages that were offered.
: >"$out/sweep.tsv"
while read -r id; do
	printf '%s\t%s\n' "$id" "$(offered -o "APT::Machine-ID=$id")" >>"$out/sweep.tsv"
done </machine-ids.txt

# The same with Phase-Policy: phasing then lowers pin priorities instead.
: >"$out/sweep-phase-policy.tsv"
head -n 100 /machine-ids.txt | while read -r id; do
	printf '%s\t%s\n' "$id" "$(offered -o "APT::Machine-ID=$id" -o APT::Get::Phase-Policy=true)" >>"$out/sweep-phase-policy.tsv"
done

first=$(head -n 1 /machine-ids.txt)
{
	printf 'never\t%s\n' "$(offered -o "APT::Machine-ID=$first" -o APT::Get::Never-Include-Phased-Updates=true)"
	printf 'always\t%s\n' "$(offered -o "APT::Machine-ID=$first" -o APT::Get::Always-Include-Phased-Updates=true)"
	printf 'no-machine-id\t%s\n' "$(offered -o APT::Machine-ID= -o Dir::Etc::machine-id=/dev/null)"
	printf 'never-no-machine-id\t%s\n' "$(offered -o APT::Machine-ID= -o Dir::Etc::machine-id=/dev/null -o APT::Get::Never-Include-Phased-Updates=true)"
	printf 'always-and-never\t%s\n' "$(offered -o "APT::Machine-ID=$first" -o APT::Get::Always-Include-Phased-Updates=true -o APT::Get::Never-Include-Phased-Updates=true)"
} >"$out/options.tsv"

# `apt-get install` does not phase: what it installs for the first identifiers.
: >"$out/install.tsv"
packages=$(awk '/^Package: / { print $2 }' /repo/*_Packages | sort -u | tr '\n' ' ')
head -n 5 /machine-ids.txt | while read -r id; do
	# shellcheck disable=SC2086
	plan=$({ apt-get -s -o "APT::Machine-ID=$id" install $packages 2>/dev/null || true; } | awk '$1 == "Inst" { v = ($3 ~ /^\[/) ? $4 : $3; sub(/^\(/, "", v); print $2 "=" v }' | sort | tr '\n' ' ' | sed 's/ $//')
	printf '%s\t%s\n' "$id" "$plan" >>"$out/install.tsv"
done

# Pin priorities and candidates under Phase-Policy, for the first identifiers.
: >"$out/policy-phase-policy.txt"
head -n 3 /machine-ids.txt | while read -r id; do
	echo "### machine-id $id" >>"$out/policy-phase-policy.txt"
	# shellcheck disable=SC2086
	apt-cache -o "APT::Machine-ID=$id" -o APT::Get::Phase-Policy=true policy $packages >>"$out/policy-phase-policy.txt"
done
