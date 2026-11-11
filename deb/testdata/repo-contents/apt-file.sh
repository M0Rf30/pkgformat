#!/bin/sh
# Runs inside a Debian container (see TestContentsReadByAptFile): installs
# apt-file (network needed), points apt at the repository mounted read-only at
# /repo (suite x, component main), fetches its Contents index and searches it.
set -eu

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq apt-file >/dev/null 2>&1

rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
echo "deb [trusted=yes] file:///repo x main" >/etc/apt/sources.list.d/test.list

apt-get update >/dev/null 2>&1
apt-file update >/dev/null 2>&1

echo "== search usr/bin/alpha"
apt-file search usr/bin/alpha
echo "== list gamma"
apt-file list gamma
echo "== search blanks"
apt-file search "with space"
echo "== search etc/beta.conf"
apt-file search etc/beta.conf
