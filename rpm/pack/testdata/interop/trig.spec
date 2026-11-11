Name: trig
Version: 1
Release: 1
Summary: Scriptlet and trigger order
License: MIT
BuildArch: noarch
%description
Every scriptlet and trigger appends its name to /tmp/order.log.

%install
mkdir -p %{buildroot}/opt/trig
echo t > %{buildroot}/opt/trig/f

%pretrans -p <lua>
local f = io.open("/tmp/order.log", "a"); f:write("pretrans\n"); f:close()
%pre
echo pre >> /tmp/order.log
%post
echo post >> /tmp/order.log
%preun
echo preun >> /tmp/order.log
%postun
echo postun >> /tmp/order.log
%posttrans
echo posttrans >> /tmp/order.log
%preuntrans
echo preuntrans >> /tmp/order.log
%postuntrans
echo postuntrans >> /tmp/order.log
%triggerprein -- bar
echo triggerprein >> /tmp/order.log
%triggerin -- bar
echo triggerin >> /tmp/order.log
%triggerun -- bar
echo triggerun >> /tmp/order.log
%triggerpostun -- bar
echo triggerpostun >> /tmp/order.log
%filetriggerin -P 100 -- /opt/bar
echo filetriggerin-100 >> /tmp/order.log
%filetriggerin -P 5 -- /opt/bar
echo filetriggerin-5 >> /tmp/order.log
%filetriggerun -- /opt/bar
echo filetriggerun >> /tmp/order.log
%filetriggerpostun -- /opt/bar
echo filetriggerpostun >> /tmp/order.log
%transfiletriggerin -- /opt/bar
echo transfiletriggerin >> /tmp/order.log
%transfiletriggerun -- /opt/bar
echo transfiletriggerun >> /tmp/order.log
%transfiletriggerpostun -- /opt/bar
echo transfiletriggerpostun >> /tmp/order.log

%files
/opt/trig/f
