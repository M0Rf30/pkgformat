#!/bin/sh
# Regenerates the fixtures of this directory (see README.md):
#
#   real/*.xml   advisories trimmed, byte for byte, from the updateinfo.xml of
#                Rocky Linux 8 and 9 and Fedora 43 (needs network and zstd)
#   model.xml    ground truth written by createrepo_c's library
#   dnf.xml      likewise, for the dnf proof
#   repo/        a repository built by createrepo_c 1.2 with dnf.xml added by
#                modifyrepo_c
#   dnf-*.txt    what dnf5 prints for that repository (needs podman and the
#                localhost/s3tools image: Fedora with dnf5)
#
# Set OFFLINE=1 to skip the download and the container steps.
set -eu
cd "$(dirname "$0")"
here=$PWD
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# fetch URL_OF_REPO_ROOT OUTPUT: downloads the updateinfo.xml the repomd.xml of
# a repository names, decompressed.
fetch() {
    python3 - "$1" "$2" <<'EOF'
import re, subprocess, sys, urllib.request

root, out = sys.argv[1].rstrip("/") + "/", sys.argv[2]
repomd = urllib.request.urlopen(root + "repodata/repomd.xml").read().decode()
data = re.search(r'<data type="updateinfo">.*?</data>', repomd, re.S).group(0)
href = re.search(r'<location href="([^"]+)"', data).group(1)
blob = urllib.request.urlopen(root + href).read()
tool = {"gz": ["gzip", "-dc"], "zst": ["zstd", "-dc"], "xz": ["xz", "-dc"]}[href.rsplit(".", 1)[1]]
open(out, "wb").write(subprocess.run(tool, input=blob, check=True, capture_output=True).stdout)
EOF
}

if [ "${OFFLINE:-0}" != 1 ]; then
    fetch https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os "$work/rocky9.xml"
    fetch https://dl.rockylinux.org/pub/rocky/8/AppStream/x86_64/os "$work/rocky8.xml"
    fetch https://dl.fedoraproject.org/pub/fedora/linux/updates/43/Everything/x86_64 "$work/fedora43.xml"

    go run trim.go "$work/rocky9.xml" RLBA-2022:7404 RLSA-2022:6602 >real/rocky9-baseos.xml
    go run trim.go "$work/rocky8.xml" RLSA-2019:2512 RLBA-2019:3522 >real/rocky8-appstream.xml
    go run trim.go "$work/fedora43.xml" FEDORA-2026-727b73bfa0 FEDORA-2025-5efdb69e46 FEDORA-2026-eb2fc8e93d \
        >real/fedora43-updates.xml
fi

python3 ground_truth.py "$here"

# A repository with one package and the advisories of dnf.xml.
rm -rf repo
mkdir "$work/repo"
cp ../../../testdata/hello.rpm "$work/repo/"
createrepo_c -q --simple-md-filenames --revision 1700000000 --set-timestamp-to-revision "$work/repo"
cp dnf.xml "$work/updateinfo.xml"
modifyrepo_c --simple-md-filenames --mdtype updateinfo "$work/updateinfo.xml" "$work/repo/repodata"
mkdir repo
cp -r "$work/repo/repodata" repo/

if [ "${OFFLINE:-0}" != 1 ]; then
    # dnf5 lists the advisories that concern a newer version of an installed
    # package; dnf.xml is about bash, coreutils and filesystem at epoch 99.
    dnf() {
        podman run --rm --network=none -v "$here/repo:/repo:ro" localhost/s3tools:latest \
            dnf5 -q -y --setopt=cachedir=/tmp/c --repofrompath=t,file:///repo --repo=t --no-gpgchecks "$@"
    }
    dnf updateinfo list --available >dnf-updateinfo-list.txt
    dnf updateinfo info --available >dnf-updateinfo-info.txt
    podman run --rm localhost/s3tools:latest dnf5 --version | sed -n 1p >dnf-version.txt
fi
