# Fixture for the installed/archive size tests. Rebuild (format 4 or 6) with:
#   rpmbuild --define "_topdir $PWD" --define "_rpmdir $PWD/out" \
#     --define "_rpmformat 4" --define "_build_id_links none" -bb sizes.spec
Name: sizes-test
Version: 1.2.3
Release: 4
Epoch: 2
Summary: Fixture for installed/archive size parsing
License: MIT
BuildArch: noarch
Requires: bash
%description
Fixture for installed/archive size parsing.
%install
mkdir -p %{buildroot}/usr/share/sizes-test
head -c 100000 /dev/zero > %{buildroot}/usr/share/sizes-test/zeros.bin
echo hi > %{buildroot}/usr/share/sizes-test/hello.txt
ln -s hello.txt %{buildroot}/usr/share/sizes-test/link
%files
/usr/share/sizes-test
