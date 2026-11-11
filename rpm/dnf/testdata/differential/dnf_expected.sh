#!/bin/sh
# Runs inside the Fedora container of generate.sh: for every line "label: specs"
# of targets.txt, asks dnf which packages `dnf install` would add to an empty
# system from the snapshot, and writes expected/<label>.txt: one "name arch
# epoch:version-release" per line, sorted, or "error: ..." lines when dnf
# cannot solve it.
set -eu

out=/work/expected
rm -rf "$out"
mkdir -p "$out"

grep -v '^#' /work/targets.txt | grep . | while IFS= read -r line; do
    label=${line%%:*}
    specs=${line#*:}
    root=$(mktemp -d)
    log=$(mktemp)

    # shellcheck disable=SC2086
    if dnf5 --setopt=reposdir=/work/reposdir --setopt=cachedir=/tmp/cache --installroot="$root" \
        --releasever=43 install --assumeno --setopt=install_weak_deps=False $specs >"$log" 2>&1 \
        || grep -q '^Operation aborted by the user' "$log"; then
        awk '
            /^Package +Arch/ { table = 1; next }
            /^Transaction Summary/ { table = 0 }
            table && /^ [^ ]/ { print $1, $2, $3 }
        ' "$log" | sort >"$out/$label.txt"
    else
        { echo "error: dnf could not solve $specs"; grep -E '^( Problem|  - )' "$log" | sed 's/^ *//; s/^/error: /'; } >"$out/$label.txt"
    fi

    rm -rf "$root" "$log"
done
