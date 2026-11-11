#!/bin/sh
# Runs inside a Debian container on the host network (see TestUpdateAptE2E):
# one "apt-get update" against the repository served on 127.0.0.1:$1, signed by
# the key in /w/key.asc, with Packages, English translations and Contents
# enabled (the Contents target is the one apt-file configures), pdiffs on, and /var/lib/apt/lists kept between runs. It prints the
# SHA-256 of the decompressed index files apt ended up with.
set -eu

echo "deb [signed-by=/w/key.asc arch=amd64] http://127.0.0.1:$1/ e2e main" >/tmp/e2e.list

apt-get \
	-o Dir::Etc::sourcelist=/tmp/e2e.list \
	-o Dir::Etc::sourceparts=- \
	-o APT::Sandbox::User=root \
	-o Acquire::Languages=en \
	-o Acquire::PDiffs=true \
	-o 'Acquire::IndexTargets::deb::Contents-deb::MetaKey=$(COMPONENT)/Contents-$(ARCHITECTURE)' \
	-o 'Acquire::IndexTargets::deb::Contents-deb::flatMetaKey=Contents-$(ARCHITECTURE)' \
	-o 'Acquire::IndexTargets::deb::Contents-deb::ShortDescription=Contents-$(ARCHITECTURE)' \
	-o 'Acquire::IndexTargets::deb::Contents-deb::Description=$(RELEASE)/$(COMPONENT) $(ARCHITECTURE) Contents (deb)' \
	-o 'Acquire::IndexTargets::deb::Contents-deb::flatDescription=$(RELEASE) Contents (deb)' \
	-o Acquire::IndexTargets::deb::Contents-deb::Optional=true \
	-o Acquire::IndexTargets::deb::Contents-deb::DefaultEnabled=true \
	update

# apt keeps the lists compressed (lz4 on Debian); cat-file reads any format.
show() {
	kind=$1
	shift
	for f in /var/lib/apt/lists/*"$1"*; do
		case $f in *diff_Index | *.diff*) continue ;; esac
		echo "LIST-SHA256 $kind $(/usr/lib/apt/apt-helper cat-file "$f" | sha256sum | cut -d' ' -f1)"
	done
}

show packages _main_binary-amd64_Packages
show translation _main_i18n_Translation-en
show contents _main_Contents-amd64
