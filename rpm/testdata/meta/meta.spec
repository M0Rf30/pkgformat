Name: meta-test
Version: 1.2.3
Release: 4
Epoch: 2
Summary: metadata fixture
License: MIT
URL: https://example.invalid/meta
BugURL: https://example.invalid/bugs
VCS: git:https://example.invalid/meta.git
Vendor: Example Vendor
Packager: Example Packager <pkg@example.invalid>
Distribution: Example Linux
DistTag: .exl9
ModularityLabel: meta:1:20240101:abcd1234
Group: Development/Tools
ExclusiveArch: x86_64 aarch64
ExcludeArch: s390x
ExclusiveOS: linux
ExcludeOS: windows
Source0: a.tar
Source1: b.dat
Source2: c-nosource.tar
Patch0: p0.patch
Patch1: p1.patch
Patch2: p2-nosource.patch
NoSource: 2
NoPatch: 2
BuildRequires: gcc >= 4
BuildRequires: (make or gmake)
BuildConflicts: badtool
Requires: bash >= 4.0
Requires(pre): shadow-utils
Requires(post): coreutils
Requires(preun): sed
Requires(postun): grep
Requires(pretrans): glibc
Requires(posttrans): zlib
Requires(verify): findutils
Requires: (libfoo if foo)
Recommends: rec1
Suggests: sug1 >= 1
Supplements: sup1
Enhances: enh1
Conflicts: oldmeta < 1
Obsoletes: ancientmeta
Provides: metaprov = 1.2.3
BuildArch: x86_64
%description
Fixture exercising the metadata of the reader.

%prep
%build
%install
mkdir -p %{buildroot}/usr/bin %{buildroot}/etc %{buildroot}/usr/share/locale/de/LC_MESSAGES %{buildroot}/usr/share/locale/fr/LC_MESSAGES
printf '#!/bin/sh\n' > %{buildroot}/usr/bin/ping-like
chmod 755 %{buildroot}/usr/bin/ping-like
echo hard > %{buildroot}/usr/bin/hard1
ln %{buildroot}/usr/bin/hard1 %{buildroot}/usr/bin/hard2
ln %{buildroot}/usr/bin/hard1 %{buildroot}/usr/bin/hard3
echo conf > %{buildroot}/etc/meta.conf
echo de > %{buildroot}/usr/share/locale/de/LC_MESSAGES/meta.mo
echo fr > %{buildroot}/usr/share/locale/fr/LC_MESSAGES/meta.mo
ln -s ping-like %{buildroot}/usr/bin/plink
mkfifo %{buildroot}/usr/bin/fifo

%pretrans -p <lua>
print("pretrans")

%pre
echo pre

%post -p /bin/bash -e
echo post %{name}

%preun -p /usr/bin/python3
print("preun")

%postun
echo postun

%posttrans -e -q
echo posttrans

%preuntrans
echo preuntrans

%postuntrans -p <lua>
print("postuntrans")

%verifyscript
echo verify

%triggerprein -- qux
echo triggerprein

%triggerin -- foo, bar >= 2.0
echo triggerin

%triggerun -p /bin/bash -- baz < 3
echo triggerun

%triggerpostun -- old
echo triggerpostun

%filetriggerin -- /usr/lib/foo
echo ftin

%filetriggerun -p <lua> -P 100 -- /usr/share/bar
print("ftun")

%filetriggerpostun -- /opt/baz
echo ftpostun

%transfiletriggerin -P 7 -- /usr/lib64/x
echo tftin

%transfiletriggerun -- /usr/lib64/y
echo tftun

%transfiletriggerpostun -- /usr/lib64/z
echo tftpostun

%files
%attr(755,root,root) /usr/bin/ping-like
%caps(cap_net_raw=ep) /usr/bin/hard1
/usr/bin/hard2
/usr/bin/hard3
/usr/bin/plink
/usr/bin/fifo
%config(noreplace) %verify(not md5 size mtime) /etc/meta.conf
%lang(de) /usr/share/locale/de/LC_MESSAGES/meta.mo
%lang(fr) /usr/share/locale/fr/LC_MESSAGES/meta.mo
%ghost /var/lib/meta-state
%dir /usr/share/locale/de/LC_MESSAGES
