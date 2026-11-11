#!/bin/bash
# Runs inside a debian container (see generate.sh): for every world under
# /worlds it builds a flat repository from the world's Packages file, installs
# the world's dpkg status and extended_states (the auto-installed marks),
# applies its preferences and holds, then records what
# `apt-get -s` plans for each line of the world's scenarios.txt
# (<id> TAB <apt-get arguments>) into /out/worlds/<world>/expected.tsv, in the
# format record.sh documents.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive LC_ALL=C

# shellcheck source=record.sh
. /record.sh

rm -f /etc/apt/apt.conf.d/docker-gzip-indexes /etc/apt/apt.conf.d/docker-clean
# The image ships a setting that makes autoremove ignore Suggests; apt's own
# default (APT::AutoRemove::SuggestsImportant true) is what the worlds record.
rm -f /etc/apt/apt.conf.d/docker-autoremove-suggests
rm -f /etc/apt/sources.list.d/* /etc/apt/sources.list
rm -rf /etc/apt/preferences.d /etc/apt/preferences

out=/out/worlds
mkdir -p "$out"

for world in /worlds/*/; do
	name=$(basename "$world")
	mkdir -p "$out/$name"

	# The flat repository: each stanza gets the Filename and Size apt wants.
	rm -rf /repo
	mkdir /repo
	awk '
		/^$/ { if (pkg != "") { print "Filename: ./" pkg "_" ver "_amd64.deb"; print "Size: 1000" } print ""; pkg = ""; next }
		/^Package: / { pkg = $2 }
		/^Version: / { ver = $2 }
		{ print }
	' "$world/Packages" >/repo/Packages

	echo "deb [trusted=yes allow-insecure=yes] file:/repo ./" >/etc/apt/sources.list
	rm -rf /var/lib/apt/lists/*
	apt-get -qq -o Acquire::GzipIndexes=false update

	cp "$world/status" /var/lib/dpkg/status
	: >/var/lib/dpkg/available
	# The auto-installed marks: the world's own, or none.
	if [ -f "$world/extended_states" ]; then
		cp "$world/extended_states" /var/lib/apt/extended_states
	else
		rm -f /var/lib/apt/extended_states
	fi
	if [ -f "$world/holds" ]; then
		while read -r pkg; do
			[ -n "$pkg" ] && echo "$pkg hold" | dpkg --set-selections
		done <"$world/holds"
	fi

	if [ -f "$world/preferences" ]; then
		cp "$world/preferences" /etc/apt/preferences
	else
		rm -f /etc/apt/preferences
	fi

	: >"$out/$name/expected.tsv"

	while IFS=$'\t' read -r id args; do
		case "$id" in '' | '#'*) continue ;; esac

		# shellcheck disable=SC2086 # the arguments are split on purpose
		record_plan "$id" $args >>"$out/$name/expected.tsv"
	done <"$world/scenarios.txt"
done
