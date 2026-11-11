#!/bin/sh
# Rebuilds the fixtures of this directory with rpm 6.0.1:
#   meta-v6.rpm, meta-v4.rpm   binary package (RPM format 6 and 4)
#   meta-v6.nosrc.rpm, meta-v4.nosrc.rpm  its source package (rpmbuild -bs);
#                             the spec has NoSource/NoPatch, hence ".nosrc"
#   src-v6.src.rpm, src-v4.src.rpm  source package of srcpkg.spec with sources,
#                             patches and BuildRequires
set -e
cd "$(dirname "$0")"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
for fmt in 6 4; do
  rm -rf "$T/top"
  SOURCE_DATE_EPOCH=1700000000 rpmbuild --nodeps --define "_topdir $T/top" --define "_sourcedir $PWD" \
    --define "_rpmformat $fmt" --define '_buildhost localhost' \
    --define 'use_source_date_epoch_as_buildtime 1' --define 'clamp_mtime_to_source_date_epoch 1' \
    --define '_binary_payload w19.zstdio' -bb meta.spec
  cp "$T"/top/RPMS/x86_64/meta-test-1.2.3-4.x86_64.rpm "meta-v$fmt.rpm"
  SOURCE_DATE_EPOCH=1700000000 rpmbuild --nodeps --define "_topdir $T/top" --define "_sourcedir $PWD" \
    --define "_rpmformat $fmt" --define '_buildhost localhost' \
    --define 'use_source_date_epoch_as_buildtime 1' --define 'clamp_mtime_to_source_date_epoch 1' \
    --define '_source_payload w19.zstdio' -bs meta.spec
  cp "$T"/top/SRPMS/meta-test-1.2.3-4.nosrc.rpm "meta-v$fmt.nosrc.rpm"
  SOURCE_DATE_EPOCH=1700000000 rpmbuild --nodeps --define "_topdir $T/top" --define "_sourcedir $PWD" \
    --define "_rpmformat $fmt" --define '_buildhost localhost' \
    --define 'use_source_date_epoch_as_buildtime 1' --define 'clamp_mtime_to_source_date_epoch 1' \
    --define '_source_payload w19.zstdio' -bs srcpkg.spec
  cp "$T"/top/SRPMS/src-test-2.0-1.src.rpm "src-v$fmt.src.rpm"
done
