# Fixture for the weak dependency tests (weakdeps.rpm). Rebuild with:
#   rpmbuild --define "_topdir $PWD" --define "_rpmdir $PWD/out" \
#     --define "_build_id_links none" -bb weakdeps.spec
Name: weakdep-test
Version: 1.0
Release: 1
Epoch: 1
Summary: weak dep fixture
License: MIT
BuildArch: noarch
Requires: required-pkg >= 2:1.5-3
Requires: shadow-utils
Recommends: recommended-pkg
Suggests: suggested-pkg >= 1.0
Supplements: supplemented-pkg
Enhances: enhanced-pkg
Conflicts: conflicting-pkg < 2.0-1
Obsoletes: old-pkg < 1.0
%description
fixture
%files
