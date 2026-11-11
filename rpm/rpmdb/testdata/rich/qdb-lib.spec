%global debug_package %{nil}
%global __os_install_post %{nil}

Name:           qdb-lib
Version:        %{libver}
Release:        %{librel}.q1
Summary:        Fixture library package built in several versions
License:        MIT
Provides:       libqdb.so.1()(64bit)
Provides:       qdb-virt = 1.0-1
Provides:       qdb-lib-api = %{libver}

%description
Installed in several versions and architectures next to itself.

%install
mkdir -p %{buildroot}%{_libdir}/qdb
echo lib > %{buildroot}%{_libdir}/qdb/libqdb.so.%{libver}

%files
%{_libdir}/qdb/libqdb.so.%{libver}
