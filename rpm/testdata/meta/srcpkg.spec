Name: src-test
Version: 2.0
Release: 1
Summary: source package fixture
License: MIT
URL: https://example.invalid/src
Source0: s0.tar
Source5: s5.dat
Source10: %{name}.service
Patch0: fix-a.patch
Patch3: fix-b.patch
BuildRequires: gcc >= 4
BuildRequires: make
BuildRequires: (cmake or meson)
BuildConflicts: badtool < 2
Requires: bash
BuildArch: noarch
%description
Source package fixture: sources, patches, build requirements.

%prep
%build
%install
mkdir -p %{buildroot}/usr/share
echo src > %{buildroot}/usr/share/src-test
%files
/usr/share/src-test
