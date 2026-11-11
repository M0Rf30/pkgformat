#!/usr/bin/env python3
"""Builds the synthetic repositories of the scenarios: tiny noarch rpm packages
without files, written by rpmbuild, and the repodata createrepo_c makes for them.

usage: build.py OUTDIR

OUTDIR/<repo>/*.rpm and OUTDIR/<repo>/repodata/. Needs rpmbuild and createrepo_c.
"""

import os
import shutil
import subprocess
import sys
import tempfile

# (repo, name, version, extra tags). A tag value is a list of dependency texts.
PACKAGES = [
    # repository priority: the lower number wins, whatever the versions
    ("hi", "lib", "1.0", {}),
    ("lo", "lib", "2.0", {}),
    ("lo", "app", "1.0", {"Requires": ["lib"]}),
    # repository cost: of equal priority, the cheaper repository
    ("dear", "tool", "1.0", {}),
    ("cheap", "tool", "1.0", {}),
    ("dear", "gadget", "2.0", {}),
    ("cheap", "gadget", "1.0", {}),
    # upgrades of an installed package and of what depends on it
    ("v1", "core", "1.0", {}),
    ("v1", "core-plugin", "1.0", {"Requires": ["core = 1.0"]}),
    ("v1", "core-other", "1.0", {"Requires": ["core >= 1.0"]}),
    ("v2", "core", "2.0", {}),
    ("v2", "core-plugin", "2.0", {"Requires": ["core = 2.0"]}),
    ("v2", "core-other", "2.0", {"Requires": ["core >= 2.0"]}),
    # obsoletes
    ("v1", "oldname", "1.0", {}),
    ("v2", "newname", "1.0", {"Obsoletes": ["oldname < 2"], "Provides": ["oldname = 2.0"]}),
    ("v2", "user-of-old", "1.0", {"Requires": ["oldname >= 2"]}),
    # conflicts
    ("base", "mta-a", "1.0", {"Conflicts": ["mta-b"], "Provides": ["mta"]}),
    ("base", "mta-b", "1.0", {"Provides": ["mta"]}),
    ("base", "mailer", "1.0", {"Requires": ["mta"]}),
    # installonly packages
    ("old", "kernel", "1.0", {"Provides": ["installonlypkg(kernel)"]}),
    ("old", "kernel", "2.0", {"Provides": ["installonlypkg(kernel)"]}),
    ("old", "kernel", "3.0", {"Provides": ["installonlypkg(kernel)"]}),
    ("new", "kernel", "4.0", {"Provides": ["installonlypkg(kernel)"]}),
    ("old", "vm-image", "1.0", {"Provides": ["installonlypkg(vm)"]}),
    ("old", "vm-image", "2.0", {"Provides": ["installonlypkg(vm)"]}),
    ("new", "vm-image", "3.0", {"Provides": ["installonlypkg(vm)"]}),
    # best: the newest version cannot be installed
    ("best", "app-b", "1.0", {}),
    ("best", "app-b", "2.0", {"Requires": ["libnothing"]}),
    ("best", "app-c", "1.0", {"Requires": ["dep-c"]}),
    ("best", "dep-c", "1.0", {}),
    ("best", "dep-c", "2.0", {"Requires": ["libnothing"]}),
    ("best", "app-d", "1.0", {}),
    ("best", "app-d", "2.0", {"Conflicts": ["blocker"]}),
    ("best", "blocker", "1.0", {}),
    # weak dependencies
    ("weak", "app-w", "1.0", {"Recommends": ["rec-w", "rec-missing"], "Suggests": ["sug-w"]}),
    ("weak", "rec-w", "1.0", {}),
    ("weak", "sug-w", "1.0", {}),
    ("weak", "app-w-docs", "1.0", {"Supplements": ["app-w"]}),
    ("weak", "app-w-lang", "1.0", {"Supplements": ["(app-w and langpack)"]}),
    ("weak", "langpack", "1.0", {}),
    ("weak", "unrelated", "1.0", {}),
]

TEMPLATE = """\
Name: {name}
Version: {version}
Release: 1
Summary: {name} of the dnf scenarios
License: MIT
BuildArch: noarch
{tags}
%description
Synthetic package for the resolver scenarios.

%files
"""


def main(out):
    out = os.path.abspath(out)
    shutil.rmtree(out, ignore_errors=True)
    env = dict(os.environ, SOURCE_DATE_EPOCH="1700000000")

    with tempfile.TemporaryDirectory() as top:
        for repo, name, version, tags in PACKAGES:
            lines = []
            for tag, values in tags.items():
                lines += [f"{tag}: {v}" for v in values]
            spec = os.path.join(top, f"{name}.spec")
            with open(spec, "w") as f:
                f.write(TEMPLATE.format(name=name, version=version, tags="\n".join(lines)))
            dest = os.path.join(out, repo)
            os.makedirs(dest, exist_ok=True)
            subprocess.run(
                ["rpmbuild", "-bb", "--quiet", "--define", f"_topdir {top}", "--define", f"_rpmdir {top}/rpms",
                 "--define", "use_source_date_epoch_as_buildtime 1", "--define", "build_mtime_policy clamp_to_source_date_epoch",
                 "--define", "_buildhost scenarios",
                 spec],
                check=True, env=env, stdout=subprocess.DEVNULL)
            for f in os.listdir(f"{top}/rpms/noarch"):
                shutil.move(f"{top}/rpms/noarch/{f}", os.path.join(dest, f))

    for repo in sorted(os.listdir(out)):
        subprocess.run(["createrepo_c", "-q", "--revision", "1", os.path.join(out, repo)], check=True)


if __name__ == "__main__":
    main(sys.argv[1])
