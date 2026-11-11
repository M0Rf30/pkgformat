%global debug_package %{nil}

Name:           qdb-old
Version:        0.4
Release:        1.q1
Summary:        Old fixture package
License:        MIT
BuildArch:      noarch
Provides:       qdb-virt = 0.4
Conflicts:      qdb-base
Obsoletes:      qdb-ancient = 1.0

%description
Provides the virtual capability at an old version and conflicts with the base.

%install
mkdir -p %{buildroot}/usr/share/qdb
echo old > %{buildroot}/usr/share/qdb/old.txt

%files
/usr/share/qdb/old.txt
