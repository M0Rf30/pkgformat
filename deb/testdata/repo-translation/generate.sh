#!/bin/sh
# Regenerates repo/ (the repository this package builds) and expected-trusted.txt
# and expected-signed.txt (what apt prints for it) by running the Go test
# builder and container.sh in podman.
# Run from anywhere: sh generate.sh [image]   (default localhost/debtools:bookworm,
# any Debian bookworm image with apt works, e.g. docker.io/library/debian:bookworm-slim)
set -eu

here=$(cd "$(dirname "$0")" && pwd)
module=$(cd "$here/../../.." && pwd)

PKGFORMAT_E2E_IMAGE=${1:-${PKGFORMAT_E2E_IMAGE:-localhost/debtools:bookworm}}
export PKGFORMAT_E2E_IMAGE

cd "$module"
PKGFORMAT_UPDATE=1 go test ./deb/ -count=1 -run '^TestTranslationRepoRecordExpected$'
PKGFORMAT_UPDATE=1 go test ./deb/ -count=1 -run '^TestTranslationRepoFixture$'
