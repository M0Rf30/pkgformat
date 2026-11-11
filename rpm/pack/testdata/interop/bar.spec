Name: bar
Version: 1
Release: 1
Summary: Package the triggers of trig watch
License: MIT
BuildArch: noarch
%description
bar

%install
mkdir -p %{buildroot}/opt/bar
echo b > %{buildroot}/opt/bar/x

%files
/opt/bar/x
