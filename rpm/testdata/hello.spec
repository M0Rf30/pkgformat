Name: hello-test
Version: 1.0.0
Release: 1
Summary: signing test package
License: MIT
BuildArch: noarch
%description
Test package for signing. Rebuild with:
rpmbuild --define "_rpmformat 4" --define "_topdir $PWD/rb" --define "_buildhost localhost" --define "source_date_epoch_from_changelog 0" --define "_binary_payload w9.gzdio" --define "use_source_date_epoch_as_buildtime 1" -bb hello.spec
%install
mkdir -p %{buildroot}/usr/share/hello
echo hi > %{buildroot}/usr/share/hello/hello.txt
%files
/usr/share/hello/hello.txt
