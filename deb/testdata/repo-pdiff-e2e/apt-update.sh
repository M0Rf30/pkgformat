#!/bin/sh
# Runs inside a Debian container with the host network (see run.sh): one
# "apt-get update" against the repository served on 127.0.0.1:$1, with pdiffs
# enabled and /var/lib/apt/lists kept between runs, then the SHA-256 of the
# Packages index apt ended up with.
set -eu

echo "deb [trusted=yes arch=amd64] http://127.0.0.1:$1/ e2e main" >/tmp/e2e.list

apt-get \
	-o Dir::Etc::sourcelist=/tmp/e2e.list \
	-o Dir::Etc::sourceparts=- \
	-o APT::Sandbox::User=root \
	-o Acquire::Languages=none \
	-o Acquire::PDiffs=true \
	update

# apt keeps the index compressed (lz4 on Debian); cat-file reads any format.
list=$(ls /var/lib/apt/lists/*_main_binary-amd64_Packages* | grep -v 'diff_Index$')
echo "LIST-SHA256 $(/usr/lib/apt/apt-helper cat-file "$list" | sha256sum | cut -d' ' -f1)"
