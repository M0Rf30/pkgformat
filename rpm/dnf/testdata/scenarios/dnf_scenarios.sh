#!/bin/sh
# Runs inside the Fedora container of generate.sh. For every line of
# /work/scenarios.txt it installs the "installed first" packages into an empty
# root from the synthetic repositories of /work/repos, keeps that rpm database
# as /work/installed/<label>/, then asks dnf5 what installing the specs would do
# with the repositories (priority, cost) and the options of the line, and writes
# /work/expected/<label>.txt.
#
# Each expected line is "+ name arch epoch:version-release repo" for a package
# the transaction installs or upgrades to, and "- name arch epoch:version-release"
# for an installed package it removes or replaces; or "error: ..." lines when dnf
# cannot solve it.
set -eu

rm -rf /work/expected /work/installed /work/logs
mkdir -p /work/expected /work/installed /work/logs /tmp/pre

for r in /work/repos/*; do
    id=$(basename "$r")
    printf '[%s]\nname=%s\nbaseurl=file://%s\ngpgcheck=0\nenabled=1\n' "$id" "$id" "$r" >"/tmp/pre/$id.repo"
done

trim() { printf '%s' "$1" | sed 's/^ *//; s/ *$//'; }

grep -v '^#' /work/scenarios.txt | grep . | while IFS='|' read -r label repos pre opts specs; do
    label=$(trim "$label")
    repos=$(trim "$repos")
    pre=$(trim "$pre")
    opts=$(trim "$opts")
    specs=$(trim "$specs")

    root=$(mktemp -d)
    run=$(mktemp -d)
    log=/work/logs/$label.log
    : >"$log"

    common="--installroot=$root --releasever=43 --setopt=cachedir=/tmp/cache --setopt=logdir=/tmp/log"

    if [ "$pre" != "-" ]; then
        prerepo=${pre%%:*}
        prespecs=${pre#*:}
        # shellcheck disable=SC2086
        dnf5 --setopt=reposdir=/tmp/pre $common --repo="$prerepo" install -y \
            --setopt=install_weak_deps=False --setopt=installonly_limit=100 \
            --setopt=tsflags=justdb,noscripts $prespecs >>"$log" 2>&1 </dev/null
    fi

    mkdir -p "/work/installed/$label"
    cp -r "$root"/usr/lib/sysimage/rpm/. "/work/installed/$label/" 2>/dev/null || true

    for entry in $(echo "$repos" | tr ',' ' '); do
        id=${entry%%:*}
        rest=${entry#"$id"}
        prio=99
        cost=1000
        if [ -n "$rest" ]; then
            rest=${rest#:}
            prio=${rest%%:*}
            [ "$rest" != "${rest#*:}" ] && cost=${rest#*:}
        fi
        printf '[%s]\nname=%s\nbaseurl=file:///work/repos/%s\npriority=%s\ncost=%s\ngpgcheck=0\nenabled=1\n' \
            "$id" "$id" "$id" "$prio" "$cost" >"$run/$id.repo"
    done

    setopts=
    if [ "$opts" != "-" ]; then
        for o in $opts; do setopts="$setopts --setopt=$o"; done
    fi

    echo "=== transaction" >>"$log"
    # shellcheck disable=SC2086
    if dnf5 --setopt=reposdir="$run" $common $setopts install --assumeno $specs >>"$log" 2>&1 </dev/null \
        || tail -n 3 "$log" | grep -q '^Operation aborted by the user'; then
        sed -n '/^=== transaction/,$p' "$log" | awk '
            /^Package +Arch/ { table = 1; next }
            /^Transaction Summary/ { table = 0 }
            table && /^[A-Z].*:$/ { section = $0; next }
            table && $1 == "replacing" { print "- " $2, $3, $4; next }
            table && /^ [^ ]/ && section ~ /^Skipping/ { next }
            table && /^ [^ ]/ && section ~ /^Removing/ { print "- " $1, $2, $3; next }
            table && /^ [^ ]/ { print "+ " $1, $2, $3, $4 }
        ' | sort >"/work/expected/$label.txt"
    else
        { echo "error: dnf could not solve $specs"; sed -n '/^=== transaction/,$p' "$log" | grep -E '^( Problem|  - )' | sed 's/^ *//; s/^/error: /'; } >"/work/expected/$label.txt"
    fi

    rm -rf "$root" "$run"
done
