#!/bin/sh
# Runs inside a Debian container (see generate.sh and the Go end-to-end test):
# points apt at the repository mounted read-only at /repo, updates with the
# German translations enabled and prints what apt shows for the packages.
#
#   sh container.sh trusted   the repository is trusted without a signature
#   sh container.sh signed    InRelease is checked against /repo/key.asc
set -eu

mode=${1:-trusted}

rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*

case $mode in
trusted) opts='trusted=yes' ;;
signed) opts='signed-by=/repo/key.asc' ;;
*)
	echo "unknown mode $mode" >&2
	exit 2
	;;
esac

echo "deb [$opts] file:///repo bookworm main" >/etc/apt/sources.list.d/test.list

apt-get update -o Acquire::Languages=de >/tmp/update.log 2>&1 || {
	cat /tmp/update.log >&2
	exit 1
}

echo "== lists"
ls /var/lib/apt/lists | grep -v '^lock$\|^partial$' | sort

echo "== apt-cache show hello"
apt-cache -o Acquire::Languages=de show --no-all-versions hello

echo "== apt-cache show hello-doc"
apt-cache -o Acquire::Languages=de show --no-all-versions hello-doc

echo "== apt-cache policy hello"
apt-cache policy hello | sed -n '1,4p'
