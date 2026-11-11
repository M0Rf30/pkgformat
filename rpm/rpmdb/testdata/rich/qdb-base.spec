%global debug_package %{nil}
%global _build_id_links none
%global __os_install_post %{nil}

Name:           qdb-base
Epoch:          1
Version:        1.2.3
Release:        1.q1
Summary:        Fixture package that carries every scriptlet and dependency kind
License:        MIT
URL:            https://example.invalid/qdb
BuildArch:      noarch

Provides:       qdb-virt = 2.0-1
Provides:       qdb-multi = 1:3.0
Provides:       qdb-plain
Requires:       qdb-lib >= 1.0
Requires:       /bin/sh
Requires:       (qdb-opt if qdb-x)
Requires:       (qdb-alt >= 2.0 or qdb-other)
Requires(pre):  qdb-lib
Requires(post): qdb-lib >= 1.4
Recommends:     qdb-extra >= 2
Suggests:       qdb-docs
Supplements:    qdb-x
Enhances:       qdb-x >= 3
Conflicts:      qdb-old < 0.5
Conflicts:      qdb-clash
Obsoletes:      qdb-legacy < 1.0
Obsoletes:      qdb-ancient

%description
Carries every kind of scriptlet and trigger rpm knows, and one of each
dependency tag, so that a database reader can be checked against rpm.

%install
mkdir -p %{buildroot}/usr/share/qdb/dir %{buildroot}/etc %{buildroot}/var/lib/qdb \
         %{buildroot}/usr/bin %{buildroot}/usr/share/doc/qdb-base
echo a > %{buildroot}/usr/share/qdb/a.txt
echo b > %{buildroot}/usr/share/qdb/dir/b.txt
echo conf > %{buildroot}/etc/qdb.conf
echo doc > %{buildroot}/usr/share/doc/qdb-base/README
ln -s ../share/qdb/a.txt %{buildroot}/usr/bin/qdb
touch %{buildroot}/var/lib/qdb/state

%files
%dir /usr/share/qdb
%dir /usr/share/qdb/dir
/usr/share/qdb/a.txt
/usr/share/qdb/dir/b.txt
%config(noreplace) /etc/qdb.conf
%ghost /var/lib/qdb/state
%doc /usr/share/doc/qdb-base/README
/usr/bin/qdb

%pretrans -p <lua>
print("pretrans of qdb-base")

%pre
echo "pre $1"

%post -e
echo "post %{name} $1"

%preun -q
echo "preun %{NAME} $1"

%postun -p /sbin/ldconfig

%posttrans
echo "posttrans $1"

%preuntrans
echo "preuntrans $1"

%postuntrans -p <lua> -e -q
print("postuntrans")

%verifyscript
echo "verify qdb-base"

%triggerprein -- qdb-old < 0.5
echo "triggerprein $1 $2"

%triggerin -- qdb-lib >= 1.0, qdb-x
echo "triggerin $1 $2"

%triggerun -p /bin/sh -e -- qdb-lib
echo "triggerun $1 $2"

%triggerpostun -- qdb-old
echo "triggerpostun $1 $2"

%filetriggerin -P 100 -- /usr/share/qdb
echo "filetriggerin"

%filetriggerun -p /bin/bash -- /usr/lib/qdb, /usr/share/qdb-extra
echo "filetriggerun"

%filetriggerpostun -- /usr/share/qdb-alt
echo "filetriggerpostun"

%transfiletriggerin -P 5000 -e -- /usr/share/qdb
echo "transfiletriggerin"

%transfiletriggerun -p <lua> -- /usr/lib/qdb
print("transfiletriggerun")

%transfiletriggerpostun -- /usr/share/qdb-alt
echo "transfiletriggerpostun"
