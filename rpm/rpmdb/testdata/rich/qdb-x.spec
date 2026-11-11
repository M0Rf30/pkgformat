%global debug_package %{nil}

Name:           qdb-x
Version:        3.1
Release:        1.q1
Summary:        Fixture package that needs the base
License:        MIT
BuildArch:      noarch
Requires:       qdb-base = 1:1.2.3-1.q1
Requires:       qdb-virt >= 2.0
Requires:       qdb-multi > 1:2.0
Requires:       qdb-plain
Requires:       /usr/share/qdb/a.txt

%description
Requires the base by exact version and the virtual capability by range.

%install
mkdir -p %{buildroot}/usr/share/qdb
echo x > %{buildroot}/usr/share/qdb/x.txt
mkdir -p %{buildroot}/usr/share/doc/qdb-x
echo notes > %{buildroot}/usr/share/doc/qdb-x/NOTES
# Also in qdb-old, with other content: once qdb-x is installed over it, qdb-old
# has this file in the "replaced" state and rpm -qf names qdb-x only.
echo replaced > %{buildroot}/usr/share/qdb/old.txt

%files
/usr/share/qdb/x.txt
/usr/share/qdb/old.txt
%doc /usr/share/doc/qdb-x/NOTES
