# Fixture for the payload extraction tests. Rebuild with (format 4 or 6):
#   SOURCE_DATE_EPOCH=1700000000 rpmbuild --define "_topdir $PWD/top" \
#     --define "_rpmdir $PWD/out" --define "_rpmformat 6" \
#     --define "_build_id_links none" --define "_buildhost localhost" \
#     --define "use_source_date_epoch_as_buildtime 1" \
#     --define "_binary_payload w9.gzdio" -bb extract.spec
# and copy the result to extract-v4.rpm / extract-v6.rpm.
Name: extract-test
Version: 1.0
Release: 1
Summary: payload extraction fixture
License: MIT
BuildArch: noarch
%description
Regular files with various modes, set-uid and set-gid files, a sticky
directory, a symlink, a hard link set, an empty directory, an empty file, a
FIFO and a ghost file that is not in the payload.
%install
d=%{buildroot}/opt/extract-test
mkdir -p $d/bin $d/empty $d/sticky $d/ro
printf '#!/bin/sh\necho hi\n' > $d/bin/run
printf 'suid\n' > $d/bin/suid
printf 'sgid\n' > $d/bin/sgid
printf 'readonly\n' > $d/ro/file
printf 'shared contents\n' > $d/bin/hl1
ln $d/bin/hl1 $d/bin/hl2
ln $d/bin/hl1 $d/bin/hl3
: > $d/bin/empty
ln -s run $d/bin/link
mkfifo $d/bin/pipe
touch $d/state
find $d -depth -exec touch -h -d @1600000000 {} +
%files
%defattr(-,root,root,-)
%dir /opt/extract-test
%dir /opt/extract-test/bin
%dir /opt/extract-test/empty
%dir %attr(1777,root,root) /opt/extract-test/sticky
%dir %attr(0555,root,root) /opt/extract-test/ro
%attr(0755,root,root) /opt/extract-test/bin/run
%attr(4755,root,root) /opt/extract-test/bin/suid
%attr(2755,root,root) /opt/extract-test/bin/sgid
%attr(0444,root,root) /opt/extract-test/ro/file
%attr(0644,root,root) /opt/extract-test/bin/hl1
%attr(0644,root,root) /opt/extract-test/bin/hl2
%attr(0644,root,root) /opt/extract-test/bin/hl3
%attr(0600,root,root) /opt/extract-test/bin/empty
/opt/extract-test/bin/link
%attr(0640,root,root) /opt/extract-test/bin/pipe
%ghost /opt/extract-test/state
