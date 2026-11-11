#!/bin/sh
# Rebuilds the fixtures of this directory. Needs curl, xz, gzip, python3 and the
# libmodulemd python bindings (python3-gobject, libmodulemd 2.15.x); the
# network is only needed here, the tests read the committed files.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # URL OUT
	curl -fsSL "$1" -o "$work/dl"
	case "$1" in
	*.xz) xz -dc "$work/dl" >"$2" ;;
	*.gz) gzip -dc "$work/dl" >"$2" ;;
	*) cp "$work/dl" "$2" ;;
	esac
}

# Real AppStream metadata, trimmed to a few modules by trim_modules.py (documents are
# copied byte for byte).
fetch https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/repodata/5bc2523233617a7e5a22db1c3df821be29deead4a2e6016392b4461c8f3237b7-modules.yaml.xz "$work/rocky9.yaml"
fetch https://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os/repodata/bc0c446faa2133f807dcb66088e0eba3b12bdf880cccae3a8207832ced11cae8-modules.yaml.xz "$work/rocky8.yaml"
fetch https://dl.fedoraproject.org/pub/archive/fedora/linux/updates/38/Modular/x86_64/repodata/94bf64c1dcb8a99560d1c57ae4814ea5a1736e822976ca3d8e11228c19a8be79-modules.yaml.gz "$work/fedora38u.yaml"

python3 "$here/trim_modules.py" "$work/rocky9.yaml" \
	defaults:nginx stream:nginx:1.22 stream:nginx:1.26 \
	defaults:mariadb stream:mariadb:10.11 \
	defaults:maven stream:maven:3.9 \
	>"$here/rocky9-appstream.yaml"

python3 "$here/trim_modules.py" "$work/rocky8.yaml" \
	defaults:go-toolset stream:go-toolset:rhel8 \
	defaults:llvm-toolset stream:llvm-toolset:rhel8 \
	defaults:ruby stream:ruby:2.5 \
	defaults:nodejs stream:nodejs:10 \
	>"$here/rocky8-appstream.yaml"

python3 "$here/trim_modules.py" "$work/fedora38u.yaml" \
	obsoletes:cri-o:1.10 obsoletes:perl:5.30 obsoletes:perl-IO-Socket-SSL:2.068 \
	>"$here/fedora38-obsoletes.yaml"

# The format examples libmodulemd ships (yaml_specs/), tag 2.15.4.
for f in stream_v2 defaults_v1 obsoletes_v1 translations_v1; do
	curl -fsSL "https://raw.githubusercontent.com/fedora-modularity/libmodulemd/2.15.4/yaml_specs/modulemd_$f.yaml" \
		-o "$here/spec-$(echo "$f" | tr _ -).yaml"
done

# What libmodulemd writes for each file: the reference of the Go writer.
cd "$here"
sources=$(ls ./*.yaml | grep -v '\.libmodulemd\.yaml$')
# shellcheck disable=SC2086
python3 libmodulemd_dump.py $sources

# Every file, and every reference, must be accepted by libmodulemd's validator.
for f in *.yaml; do modulemd-validator "$f"; done
