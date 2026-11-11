#!/bin/sh
# Regenerates repos/, installed/ and expected/ for scenarios.txt:
#
#   1. build.py writes the synthetic repositories with rpmbuild and createrepo_c,
#   2. dnf_scenarios.sh, in a Fedora 43 container (podman), installs the
#      packages each scenario starts with into an empty root with dnf5 (the rpm
#      database that results is kept) and records what dnf5 would do for the
#      specs of the scenario, with its repository priorities and options,
#   3. the databases are checkpointed and vacuumed so that each is one file.
#
# Needs rpmbuild, createrepo_c, python3, podman and network access (for the
# container image).
set -eu

here=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$(mktemp -d)}
image=registry.fedoraproject.org/fedora:43

rm -rf "$WORK/work"
mkdir -p "$WORK/work"
python3 "$here/build.py" "$WORK/work/repos"
cp "$here/scenarios.txt" "$WORK/work/scenarios.txt"

podman run --rm -v "$WORK/work:/work:Z" -v "$here/dnf_scenarios.sh:/dnf_scenarios.sh:ro,Z" "$image" sh /dnf_scenarios.sh

python3 - "$WORK/work/installed" <<'EOF'
import glob, os, sqlite3, sys

for db in glob.glob(os.path.join(sys.argv[1], "*", "rpmdb.sqlite")):
    c = sqlite3.connect(db)
    c.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    c.execute("PRAGMA journal_mode=DELETE")
    c.execute("VACUUM")
    c.close()
    for extra in ("-wal", "-shm"):
        if os.path.exists(db + extra):
            os.remove(db + extra)
for lock in glob.glob(os.path.join(sys.argv[1], "*", ".rpm.lock")):
    os.remove(lock)
EOF

rm -rf "$here/repos" "$here/expected" "$here/installed"
cp -r "$WORK/work/repos" "$here/repos"
cp -r "$WORK/work/expected" "$here/expected"
cp -r "$WORK/work/installed" "$here/installed"

echo "regenerated; scratch files are in $WORK"
