# Fixture for the file list tests (files.rpm). Rebuild with:
#   rpmbuild --define "_topdir $PWD" --define "_build_id_links none" \
#     --define "_buildhost localhost" --define "use_source_date_epoch_as_buildtime 1" \
#     --define "source_date_epoch_from_changelog 0" -bb files.spec
Name: files-test
Version: 2.1
Release: 3
Summary: file list fixture
License: MIT
BuildArch: noarch
Provides: tool = 2.1-3
Requires: /bin/sh
Requires(pre): shadow-utils
%description
Fixture with a command, a configuration file, a directory and a ghost file.
%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/etc %{buildroot}/usr/share/files-test %{buildroot}/var/lib/files-test
printf '#!/bin/sh\n' > %{buildroot}/usr/bin/files-tool
chmod 755 %{buildroot}/usr/bin/files-tool
echo conf > %{buildroot}/etc/files-tool.conf
echo doc > %{buildroot}/usr/share/files-test/README
touch %{buildroot}/var/lib/files-test/state
%files
/usr/bin/files-tool
%config(noreplace) /etc/files-tool.conf
%dir /usr/share/files-test
/usr/share/files-test/README
%ghost /var/lib/files-test/state
