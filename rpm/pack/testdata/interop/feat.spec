Name: feat
Version: 1.2.3
Release: 4
Epoch: 2
Summary: Feature test
Summary(de): Funktionstest
License: MIT
URL: https://example.org/feat
BuildArch: noarch
Group: Misc
Vendor: Acme
Packager: Pack <p@example.org>
Distribution: Acme Linux
BugURL: https://example.org/bugs
Requires: bash >= 4
Requires(pre): coreutils
Requires(post): coreutils
Requires(preun,postun): grep
Requires(pretrans): sed
Requires(posttrans): sed
Requires(verify): gawk
Requires(meta): (foo if bar)
Recommends: rec1
Suggests: sug1
Supplements: sup1
Enhances: enh1
Provides: virt = 1.0
Conflicts: bad < 2
Obsoletes: old < 1
Requires: (a or b)
Requires: x~1^2
%description
Feature test description.
%description -l de
Beschreibung.

%install
mkdir -p %{buildroot}/opt/feat/bin %{buildroot}/etc
echo hello > %{buildroot}/opt/feat/bin/hello
chmod 755 %{buildroot}/opt/feat/bin/hello
ln %{buildroot}/opt/feat/bin/hello %{buildroot}/opt/feat/bin/hello2
echo c > %{buildroot}/etc/feat.conf
mkfifo %{buildroot}/opt/feat/fifo
ln -s hello %{buildroot}/opt/feat/bin/link
echo de > %{buildroot}/opt/feat/de.txt
echo cls > %{buildroot}/opt/feat/cls.txt
%pretrans -p <lua>
print("pretrans")
%pre -e
echo pre %{name}
%post -p "/bin/sh -e"
echo post
%preun -q
echo preun
%postun -p /usr/bin/python3
print(1)
%posttrans
echo posttrans
%preuntrans -p <lua>
print("a")
%postuntrans
echo b
%verifyscript
echo verify
%triggerprein -- foo > 1
echo tpre
%triggerin -p /bin/bash -- bar, baz >= 2.0
echo tin
%triggerun -- bar
echo tun
%triggerpostun -p <lua> -- bar < 3
print("tpostun")
%filetriggerin -p /bin/sh -P 100 -- /usr/lib
echo fti
%filetriggerun -- /usr/share
echo ftu
%filetriggerpostun -- /opt
echo ftpu
%transfiletriggerin -P 5 -- /usr/bin /usr/sbin
echo tfti
%transfiletriggerun -- /usr/lib
echo tftu
%transfiletriggerpostun -- /lib
echo tftpu
%files
%defattr(-,root,root)
%attr(0755,u1,g1) /opt/feat/bin/hello
%attr(0755,u1,g1) /opt/feat/bin/hello2
/opt/feat/bin/link
%caps(cap_net_raw=ep) /opt/feat/bin/hello
%verify(not md5 size mtime) /etc/feat.conf
%config(noreplace) /etc/feat.conf
%lang(de) /opt/feat/de.txt
%dir /opt/feat
%dir /opt/feat/bin
%ghost /opt/feat/ghost
/opt/feat/fifo
%doc /opt/feat/cls.txt
%changelog
* Mon Jan 01 2024 A <a@b> - 1.0-1
- one
