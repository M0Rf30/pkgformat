#!/bin/sh
# Regenerates the zchunk fixtures of this directory with the reference tools:
# createrepo_c --zck for the *.xml.zck files of a repository, and the zck tool
# for the others. Needs createrepo_c >= 1.2, zchunk >= 1.5 (zck, unzck,
# zck_gen_zdict) and zcat. The sources are the golden documents of
# ../createrepo, so every file decodes to a document a test can compare with.
# Usage: ./generate.sh
set -eu
cd "$(dirname "$0")"
corpus=../createrepo
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# --- createrepo_c --zck on the whole corpus, and on all but four packages ----
repo() { # repo <dir> <egrep pattern of the file names to leave out>
    mkdir -p "$1/Packages"
    for p in "$corpus"/Packages/*.rpm; do
        if basename "$p" | grep -Eq "$2"; then continue; fi
        cp "$p" "$1/Packages/"
    done
    find "$1/Packages" -name '*.rpm' -exec touch -d @1700000000 {} +
    createrepo_c -q --simple-md-filenames --zck --general-compress-type=gz \
        --revision 1700000000 --set-timestamp-to-revision "$1"
}
repo "$work/new" '^$'
repo "$work/old" '^(systemd|vim|setup|edge)-'
for f in primary filelists other; do
    cp "$work/new/repodata/$f.xml.zck" "createrepo-$f.xml.zck"
done
cp "$work/old/repodata/primary.xml.zck" createrepo-primary-old.xml.zck

# --- the reference zck tool on the golden documents --------------------------
for f in primary filelists other; do
    zcat "$corpus/golden/$f.xml.gz" > "$work/$f.xml"
done
# content-defined chunks (the default), 1.5 MB so that there are many
zck -o zck-filelists.zck "$work/filelists.xml"
# chunk checksum types, no compression, the uncompressed-source extension
zck -h sha256 -o zck-other-sha256.zck "$work/other.xml"
zck -h sha512 -o zck-other-sha512.zck "$work/other.xml"
zck --compression-format=none -o zck-other-none.zck "$work/other.xml"
zck -u -o zck-other-uncompressed-source.zck "$work/other.xml"
# split before each <package, as zck -s does
zck -s '<package' -o zck-other-split.zck "$work/other.xml"
# a dictionary trained on the chunks of the createrepo_c primary
mkdir "$work/chunks"
(cd "$work" && cp "$OLDPWD/createrepo-primary.xml.zck" primary.xml.zck &&
    zck_gen_zdict -d chunks primary.xml.zck >/dev/null 2>&1)
cp "$work/primary.xml.zdict" primary.zdict
zck -D primary.zdict -o zck-primary-dict.zck "$work/primary.xml"
# the detached header of that file
(cd "$work" && cp "$OLDPWD/zck-primary-dict.zck" . && unzck --header zck-primary-dict.zck >/dev/null)
cp "$work/zck-primary-dict.zhr" zck-primary-dict.zhr

# --- a file from a real repository ------------------------------------------
# Not regenerated: the Fedora 43 Server tree moves on. These are the files as
# fetched on 2025-11-11, kept so that the test stays valid offline:
#   B=https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Server/x86_64/os/repodata
#   curl -o fedora43-server-repomd.xml $B/repomd.xml
#   curl -o fedora43-server-comps.xml.zck \
#       $B/0cdbab628d1038fc2b0e433a6b999972d8b718392165e0f65a541d2ef02a9649-comps-Server.x86_64.xml.zck
