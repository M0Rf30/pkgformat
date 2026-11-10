Name: hello
Version: 1.0
Release: 1
Summary: test
License: MIT
BuildArch: noarch
%description
test
%install
mkdir -p %{buildroot}/usr/share/hello
echo hi > %{buildroot}/usr/share/hello/a.txt
ln -s a.txt %{buildroot}/usr/share/hello/b
%files
/usr/share/hello
