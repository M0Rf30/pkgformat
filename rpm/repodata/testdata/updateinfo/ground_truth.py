"""Writes model.xml and dnf.xml with the updateinfo writer of createrepo_c (its
python binding): the advisories below are the ones updateinfo_test.go builds in
Go and compares byte for byte.

    python3 ground_truth.py OUTDIR
"""
import os
import datetime
import sys

import createrepo_c as cr

HELLO_SHA = "48131ebba95c88df0e452931707a42dfdfd0c3c2832522c1c686a82449d45dab"
FILES_SHA = "9ce47f4720a1d2348899eb9d6baf4f4f89fbb2d69d800bfc030046f28f497481"


def package(**kw):
    p = cr.UpdateCollectionPackage()
    sha = kw.pop("sha", None)
    for k, v in kw.items():
        setattr(p, k, v)
    if sha:
        p.sum, p.sum_type = sha, cr.SHA256
    return p


def reference(href, rid=None, title=None, typ=None):
    r = cr.UpdateReference()
    r.href, r.type = href, typ
    if rid:
        r.id = rid
    if title:
        r.title = title
    return r


def model():
    updates = []

    a = cr.UpdateRecord()
    a.fromstr, a.status, a.type, a.version = "updates@fedoraproject.org", "stable", "security", "2.0"
    a.id = "FEDORA-2026-1f3a9c0b52"
    a.title = "hello-test-1.0.0-1.fc45"
    a.issued_date = datetime.datetime(2026, 3, 13, 21, 14, 55)
    a.updated_date = datetime.datetime(2026, 3, 22, 0, 52, 45)
    a.rights = "Copyright (C) 2026 Red Hat, Inc. and others."
    a.release = "Fedora 45"
    a.severity = "Important"
    a.summary = "hello-test-1.0.0-1.fc45 security update"
    a.description = "Fix a heap overflow in the greeting parser (CVE-2026-0001).\n\nThe parser trusted the length of a <greeting> & wrote past the buffer."
    a.reboot_suggested = True
    a.append_reference(reference("https://bugzilla.redhat.com/show_bug.cgi?id=2400001", "2400001", "CVE-2026-0001 hello-test: heap overflow in the greeting parser", "bugzilla"))
    a.append_reference(reference("https://bodhi.fedoraproject.org/updates/FEDORA-2026-1f3a9c0b52", "FEDORA-2026-1f3a9c0b52", "FEDORA-2026-1f3a9c0b52", "self"))
    c = cr.UpdateCollection()
    c.shortname, c.name = "F45", "Fedora 45"
    c.append(package(name="hello-test", version="1.0.0", release="1", epoch="0", arch="noarch",
                     src="https://download.fedoraproject.org/pub/fedora/linux/updates/45/SRPMS/h/hello-test-1.0.0-1.fc45.src.rpm",
                     filename="hello-test-1.0.0-1.noarch.rpm", sha=HELLO_SHA,
                     reboot_suggested=True, restart_suggested=True, relogin_suggested=True))
    a.append_collection(c)
    updates.append(a)

    b = cr.UpdateRecord()
    b.fromstr, b.status, b.type, b.version = "releng@rockylinux.org", "final", "bugfix", "2"
    b.id = "RLBA-2026:0001"
    b.title = "files-test and weakdep-test bug fix update"
    b.issued_date = datetime.datetime(2026, 1, 20, 9, 30, 0)
    b.updated_date = datetime.datetime(2026, 2, 2, 12, 0, 0)
    b.rights = "Copyright 2026 Rocky Enterprise Software Foundation. © Red Hat, Inc."
    b.release = "Rocky Linux 9"
    b.pushcount = "1"
    b.severity = "None"
    b.summary = "An update is available for files-test and weakdep-test."
    b.description = "Both packages were rebuilt with the new macros.\n  * files-test ships the missing directory\n  * weakdep-test keeps its weak dependencies"
    b.solution = "Update the packages with dnf update."
    b.append_reference(reference("https://errata.rockylinux.org/RLBA-2026:0001", "RLBA-2026:0001", "RLBA-2026:0001", "self"))
    c = cr.UpdateCollection()
    c.shortname = c.name = "rocky-linux-9-x86-64-baseos-rpms"
    c.append(package(name="files-test", version="2.1", release="3", epoch="0", arch="noarch",
                     src="files-test-2.1-3.src.rpm", filename="files-test-2.1-3.noarch.rpm", sha=FILES_SHA))
    c.append(package(name="weakdep-test", version="1.0", release="1", epoch="1", arch="noarch",
                     src="weakdep-test-1.0-1.src.rpm", filename="weakdep-test-1.0-1.noarch.rpm"))
    b.append_collection(c)
    updates.append(b)

    m = cr.UpdateRecord()
    m.fromstr, m.status, m.type, m.version = "releng@rockylinux.org", "final", "security", "2"
    m.id = "RLSA-2026:0002"
    m.title = "Moderate: nodejs:20 security update"
    m.issued_date = datetime.datetime(2026, 4, 1, 8, 0, 0)
    m.rights = "Copyright 2026 Rocky Enterprise Software Foundation."
    m.release = "Rocky Linux 9"
    m.pushcount = "2"
    m.severity = "Moderate"
    m.summary = "An update for the nodejs:20 module is available."
    m.description = "Security fix for the nodejs:20 module stream."
    m.append_reference(reference("https://access.redhat.com/security/cve/CVE-2026-0002", "CVE-2026-0002", "CVE-2026-0002", "cve"))
    c = cr.UpdateCollection()
    c.shortname = c.name = "rocky-linux-9-x86-64-appstream-rpms"
    mod = cr.UpdateCollectionModule()
    mod.name, mod.stream, mod.version, mod.context, mod.arch = "nodejs", "20", 9060020260401080000, "rhel9", "x86_64"
    c.module = mod
    c.append(package(name="nodejs", version="20.11.1", release="1.module+el9.6.0+1+abcdef01", epoch="1", arch="x86_64",
                     src="nodejs-20.11.1-1.module+el9.6.0+1+abcdef01.src.rpm",
                     filename="nodejs-20.11.1-1.module+el9.6.0+1+abcdef01.x86_64.rpm"))
    m.append_collection(c)
    c = cr.UpdateCollection()
    c.shortname, c.name = "empty", "A collection without packages"
    m.append_collection(c)
    updates.append(m)

    bare = cr.UpdateRecord()
    bare.id = "BARE-1"
    updates.append(bare)

    return updates


def dnf():
    """Advisories for packages every Fedora image has installed, at an epoch
    that makes them newer than the installed ones, so that dnf lists them."""
    updates = []

    a = cr.UpdateRecord()
    a.fromstr, a.status, a.type, a.version = "updates@fedoraproject.org", "stable", "security", "2.0"
    a.id = "FEDORA-2026-c3b1d2e4f5"
    a.title = "bash-5.3.99-1.fc45"
    a.issued_date = datetime.datetime(2026, 10, 2, 11, 43, 19)
    a.updated_date = datetime.datetime(2026, 10, 15, 1, 7, 46)
    a.rights = "Copyright (C) 2026 Red Hat, Inc. and others."
    a.release = "Fedora 45"
    a.severity = "Important"
    a.summary = "bash-5.3.99-1.fc45 security update"
    a.description = "Update to bash 5.3 patch level 99.\n\nFixes an out-of-bounds read in the history expansion code (CVE-2026-0101)."
    a.append_reference(reference("https://bugzilla.redhat.com/show_bug.cgi?id=2410101", "2410101", "CVE-2026-0101 bash: out-of-bounds read in history expansion", "bugzilla"))
    a.append_reference(reference("https://bodhi.fedoraproject.org/updates/FEDORA-2026-c3b1d2e4f5", "FEDORA-2026-c3b1d2e4f5", "FEDORA-2026-c3b1d2e4f5", "self"))
    c = cr.UpdateCollection()
    c.shortname, c.name = "F45", "Fedora 45"
    c.append(package(name="bash", version="5.3.99", release="1.fc45", epoch="99", arch="x86_64",
                     src="bash-5.3.99-1.fc45.src.rpm", filename="bash-5.3.99-1.fc45.x86_64.rpm",
                     sha="0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"))
    a.append_collection(c)
    updates.append(a)

    b = cr.UpdateRecord()
    b.fromstr, b.status, b.type, b.version = "updates@fedoraproject.org", "stable", "bugfix", "2.0"
    b.id = "FEDORA-2026-7e8f9a0b1c"
    b.title = "coreutils-9.99-1.fc45"
    b.issued_date = datetime.datetime(2026, 9, 12, 8, 30, 0)
    b.updated_date = datetime.datetime(2026, 9, 20, 17, 5, 1)
    b.rights = "Copyright (C) 2026 Red Hat, Inc. and others."
    b.release = "Fedora 45"
    b.severity = "None"
    b.summary = "coreutils-9.99-1.fc45 bugfix update"
    b.description = "Fix `ls --color` crashing on a dangling symlink in a directory that is being removed."
    b.reboot_suggested = True
    b.append_reference(reference("https://bugzilla.redhat.com/show_bug.cgi?id=2409999", "2409999", "ls --color segfaults on a dangling symlink", "bugzilla"))
    c = cr.UpdateCollection()
    c.shortname, c.name = "F45", "Fedora 45"
    c.append(package(name="coreutils", version="9.99", release="1.fc45", epoch="99", arch="x86_64",
                     src="coreutils-9.99-1.fc45.src.rpm", filename="coreutils-9.99-1.fc45.x86_64.rpm",
                     sha="1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
                     reboot_suggested=True))
    b.append_collection(c)
    updates.append(b)

    e = cr.UpdateRecord()
    e.fromstr, e.status, e.type, e.version = "updates@fedoraproject.org", "stable", "enhancement", "2.0"
    e.id = "FEDORA-2026-a0b1c2d3e4"
    e.title = "filesystem-3.99-1.fc45"
    e.issued_date = datetime.datetime(2026, 8, 1, 6, 0, 0)
    e.updated_date = datetime.datetime(2026, 8, 3, 6, 0, 0)
    e.rights = "Copyright (C) 2026 Red Hat, Inc. and others."
    e.release = "Fedora 45"
    e.severity = "Low"
    e.summary = "filesystem-3.99-1.fc45 enhancement update"
    e.description = "Add /usr/share/factory to the directories the filesystem package owns."
    c = cr.UpdateCollection()
    c.shortname, c.name = "F45", "Fedora 45"
    c.append(package(name="filesystem", version="3.99", release="1.fc45", epoch="99", arch="x86_64",
                     src="filesystem-3.99-1.fc45.src.rpm", filename="filesystem-3.99-1.fc45.x86_64.rpm"))
    e.append_collection(c)
    updates.append(e)

    return updates


def write(path, updates):
    if os.path.exists(path):
        os.remove(path)
    f = cr.UpdateInfoXmlFile(path, cr.NO_COMPRESSION)
    for u in updates:
        f.add_chunk(cr.xml_dump_updaterecord(u))
    f.close()


def main(outdir):
    write(os.path.join(outdir, "model.xml"), model())
    write(os.path.join(outdir, "dnf.xml"), dnf())


main(sys.argv[1])
