#!/bin/sh
# Regenerates snapshot/ and expected/ from the Fedora 43 release repository.
#
#   1. downloads primary.xml and filelists.xml of the repository (content
#      addressed: the file names carry their sha256, which is checked),
#   2. trims them to the closure of targets.txt with snapshot.py,
#   3. asks real dnf (dnf5 in a Fedora 43 container, podman) what it would
#      install for every target from the snapshot, with weak dependencies off,
#      with dnf_expected.sh.
#
# Needs curl, zstd, python3 with the rpm module, podman and network access.
# Takes a few minutes and about 1.2 GB of scratch space in $WORK.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$(mktemp -d)}
base=https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Everything/x86_64/os/repodata
image=registry.fedoraproject.org/fedora:43

primary=fffa3e9f63fffd3d21b8ea5e9bb0fe349a7ed1d4e09777a618cec93a2bcc305f-primary.xml.zst
filelists=21403b03aa2ade01ea6b0caabbcb50e74c08bf58324ab4f0de7e9b5b01e4b089-filelists.xml.zst

mkdir -p "$WORK/dl"
for f in "$primary" "$filelists"; do
    [ -s "$WORK/dl/$f" ] || curl -fsSL -o "$WORK/dl/$f" "$base/$f"
    echo "${f%%-*}  $WORK/dl/$f" | sha256sum -c -
done

zstd -dqf "$WORK/dl/$primary" -o "$WORK/primary.xml"
zstd -dqf "$WORK/dl/$filelists" -o "$WORK/filelists.xml"

rm -rf "$WORK/snapshot"
python3 "$here/snapshot.py" "$WORK/primary.xml" "$WORK/filelists.xml" "$here/targets.txt" "$WORK/snapshot"

mkdir -p "$WORK/run/reposdir"
cp "$here/targets.txt" "$WORK/run/targets.txt"
rm -rf "$WORK/run/snapshot"
cp -r "$WORK/snapshot" "$WORK/run/snapshot"
cat >"$WORK/run/reposdir/snapshot.repo" <<'EOF'
[snapshot]
name=snapshot
baseurl=file:///work/snapshot
gpgcheck=0
enabled=1
EOF

podman run --rm -v "$WORK/run:/work:Z" -v "$here/dnf_expected.sh:/dnf_expected.sh:ro,Z" "$image" sh /dnf_expected.sh

rm -rf "$here/snapshot" "$here/expected"
cp -r "$WORK/snapshot" "$here/snapshot"
cp -r "$WORK/run/expected" "$here/expected"

echo "snapshot and expected regenerated; scratch files are in $WORK"
