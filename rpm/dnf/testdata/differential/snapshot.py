#!/usr/bin/env python3
"""Trim a Fedora repository to the closure of a list of targets.

usage: snapshot.py PRIMARY.xml FILELISTS.xml TARGETS OUTDIR

The closure holds, for every package kept, the packages that provide each of its
requirements (at most CAP per requirement, so that the alternatives of a
requirement stay in the snapshot), the packages that conflict with it or
obsolete it and the ones it conflicts with or obsoletes. Packages whose
requirements cannot be met by the packages that are left are dropped until none
is: every package of the snapshot is installable on an empty system, so that a
solver is never offered a candidate that only fails later. OUTDIR gets
repodata/{repomd.xml,*-primary.xml.gz,*-filelists.xml.gz}; filelists.xml keeps
only the paths that a package of the snapshot requires.

It needs the rpm python module, for the version comparison of rpm itself.
"""

import gzip
import hashlib
import os
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict

import rpm

CAP = 4
ARCHES = {"x86_64", "i686", "noarch"}
NS = {"c": "http://linux.duke.edu/metadata/common", "r": "http://linux.duke.edu/metadata/rpm"}
LT, GT, EQ = 2, 4, 8
FLAGS = {"LT": LT, "GT": GT, "EQ": EQ, "LE": LT | EQ, "GE": GT | EQ}


class Pkg:
    __slots__ = ("name", "arch", "epoch", "ver", "rel", "raw", "pkgid", "provides", "requires",
                 "conflicts", "obsoletes", "files", "id")


def evr_of(e):
    return (e.get("epoch") or "0", e.get("ver"), e.get("rel"))


def entries(node, tag):
    out = []
    sect = node.find("c:format/r:" + tag, NS)
    if sect is None:
        return out
    for e in sect.findall("r:entry", NS):
        flags = FLAGS.get(e.get("flags"), 0)
        evr = evr_of(e) if flags else None
        out.append((e.get("name"), flags, evr))
    return out


def load_primary(path):
    text = open(path, encoding="utf-8").read()
    pkgs = []
    for m in re.finditer(r'<package type="rpm">.*?</package>', text, re.S):
        raw = m.group(0)
        node = ET.fromstring(
            '<w xmlns="%s" xmlns:rpm="%s">%s</w>' % (NS["c"], NS["r"], raw))[0]
        arch = node.find("c:arch", NS).text
        if arch not in ARCHES:
            continue
        p = Pkg()
        p.name = node.find("c:name", NS).text
        p.arch = arch
        v = node.find("c:version", NS)
        p.epoch, p.ver, p.rel = evr_of(v)
        p.raw = raw
        p.pkgid = node.find("c:checksum", NS).text
        p.provides = entries(node, "provides") + [(p.name, EQ, (p.epoch, p.ver, p.rel))]
        p.requires = [r for r in entries(node, "requires") if not r[0].startswith("rpmlib(")]
        p.conflicts = entries(node, "conflicts")
        p.obsoletes = entries(node, "obsoletes")
        p.files = [f.text for f in node.findall("c:format/c:file", NS)]
        p.id = len(pkgs)
        pkgs.append(p)
    return pkgs


def cmp_evr(a, b):
    # a missing release matches any release
    if a[2] is None or b[2] is None:
        a, b = (a[0], a[1], None), (b[0], b[1], None)
    return rpm.labelCompare(tuple(x or "" for x in a), tuple(x or "" for x in b))


def overlaps(pflags, pevr, rflags, revr):
    if not pflags or not rflags:
        return True
    sense = cmp_evr(pevr, revr)
    if sense < 0:
        return bool(rflags & LT or pflags & GT)
    if sense > 0:
        return bool(rflags & GT or pflags & LT)
    return bool((rflags & EQ and pflags & EQ) or (rflags & LT and pflags & LT) or (rflags & GT and pflags & GT))


BOOL_OPS = {"and", "or", "if", "unless", "else", "with", "without"}


def tokenize(s):
    """Splits a rich dependency: parentheses open a group where a group may
    start, and are part of a name inside it (perl(Foo), libfoo.so.1()(64bit))."""
    toks, i = [], 0
    while i < len(s):
        if s[i].isspace():
            i += 1
        elif s[i] == "(" and (not toks or toks[-1] == "(" or toks[-1] in BOOL_OPS):
            toks.append("(")
            i += 1
        elif s[i] == ")":
            toks.append(")")
            i += 1
        else:
            j, depth = i, 0
            while j < len(s) and not s[j].isspace():
                if s[j] == "(":
                    depth += 1
                elif s[j] == ")":
                    if depth == 0:
                        break
                    depth -= 1
                j += 1
            toks.append(s[i:j])
            i = j
    return toks


CMP = {"<": LT, "<=": LT | EQ, "=": EQ, ">=": GT | EQ, ">": GT}


def parse_rich(s):
    toks = tokenize(s)
    pos = 0

    def atom():
        nonlocal pos
        name = toks[pos]
        pos += 1
        if pos < len(toks) and toks[pos] in CMP:
            fl = CMP[toks[pos]]
            ver = toks[pos + 1]
            pos += 2
            m = re.match(r"^(?:(\d+):)?([^-]*)(?:-(.*))?$", ver)
            return ("atom", name, fl, (m.group(1) or "0", m.group(2), m.group(3)))
        return ("atom", name, 0, None)

    def expr():
        nonlocal pos
        pos += 1  # (
        if toks[pos] == "(":
            left = expr()
        else:
            left = atom()
        while toks[pos] != ")":
            op = toks[pos]
            pos += 1
            right = expr() if toks[pos] == "(" else atom()
            left = (op, left, right)
        pos += 1
        return left

    return expr()


def rich_names(node, out):
    if node[0] == "atom":
        out.append((node[1], node[2], node[3]))
    else:
        for c in node[1:]:
            rich_names(c, out)


class Repo:
    def __init__(self, pkgs, filelist_owners):
        self.pkgs = pkgs
        self.by_prov = defaultdict(list)
        self.by_file = defaultdict(list)
        self.by_name = defaultdict(list)
        self.rev_conf = defaultdict(list)
        for p in pkgs:
            self.by_name[p.name].append(p)
            for n, fl, evr in p.provides:
                self.by_prov[n].append((p, fl, evr))
            for f in p.files:
                self.by_file[f].append(p)
            for n, _, _ in p.conflicts + p.obsoletes:
                self.rev_conf[n].append(p)
        for f, owners in filelist_owners.items():
            for o in owners:
                self.by_file[f].append(o)

    def providers(self, name, fl=0, evr=None):
        if name.startswith("/"):
            return list({p.id: p for p in self.by_file.get(name, []) +
                         [q for q, _, _ in self.by_prov.get(name, [])]}.values())
        return [p for p, pf, pe in self.by_prov.get(name, []) if overlaps(pf, pe, fl, evr)]

    def sat(self, node, alive):
        op = node[0]
        if op == "atom":
            return any(p.id in alive for p in self.providers(node[1], node[2], node[3]))
        if op in ("and", "with", "without"):
            return all(self.sat(c, alive) for c in node[1:])
        if op == "or":
            return any(self.sat(c, alive) for c in node[1:])
        if op == "if":
            return True if not self.sat(node[2], alive) else self.sat(node[1], alive)
        if op == "unless":
            return True if self.sat(node[2], alive) else self.sat(node[1], alive)
        if op == "else":
            cond = node[1]
            if cond[0] in ("if", "unless"):
                holds = self.sat(cond[2], alive)
                if cond[0] == "unless":
                    holds = not holds
                return self.sat(cond[1], alive) if holds else self.sat(node[2], alive)
        return True

    def requirement_ok(self, req, alive):
        name, fl, evr = req
        if name.startswith("("):
            return self.sat(parse_rich(name), alive)
        return any(p.id in alive for p in self.providers(name, fl, evr))


def rank(name):
    def key(p):
        return (p.name != name, p.arch != "x86_64", len(p.name), p.name, p.arch)
    return key


def closure(repo, seeds):
    keep = {}
    queue = list(seeds)
    while queue:
        p = queue.pop()
        if p.id in keep:
            continue
        keep[p.id] = p
        near = []
        for name, fl, evr in p.requires:
            wanted = []
            if name.startswith("("):
                names = []
                rich_names(parse_rich(name), names)
                for n, f, e in names:
                    wanted += sorted(repo.providers(n, f, e), key=rank(n))[:CAP]
            else:
                wanted = sorted(repo.providers(name, fl, evr), key=rank(name))[:CAP]
            near += wanted
        for name, fl, evr in p.conflicts + p.obsoletes:
            near += sorted(repo.providers(name, fl, evr), key=rank(name))[:CAP]
        for n, _, _ in p.provides[:-1] + [(p.name, 0, None)]:
            near += sorted(repo.rev_conf.get(n, []), key=rank(n))[:CAP]
        queue += [q for q in near if q.id not in keep]
    return keep


def prune(repo, keep, seeds):
    alive = set(keep)
    changed = True
    while changed:
        changed = False
        for pid in list(alive):
            p = keep[pid]
            if not all(repo.requirement_ok(r, alive) for r in p.requires):
                alive.discard(pid)
                changed = True
    lost = [s for s in seeds if s.id not in alive]
    return alive, lost


def required_files(pkgs):
    out = set()
    for p in pkgs:
        for name, _, _ in p.requires:
            if name.startswith("/"):
                out.add(name)
            elif name.startswith("("):
                names = []
                rich_names(parse_rich(name), names)
                out.update(n for n, _, _ in names if n.startswith("/"))
    return out


def scan_filelists(path, wanted):
    owners = defaultdict(list)
    text = open(path, encoding="utf-8").read()
    for m in re.finditer(r'<package pkgid="([0-9a-f]+)"[^>]*>(.*?)</package>', text, re.S):
        files = re.findall(r"<file[^>]*>([^<]*)</file>", m.group(2))
        for f in files:
            if f in wanted:
                owners[f].append(m.group(1))
    return owners


def filelists_entries(path, keep_ids, wanted):
    text = open(path, encoding="utf-8").read()
    out = []
    for m in re.finditer(r'<package pkgid="([0-9a-f]+)"([^>]*)>(.*?)</package>', text, re.S):
        if m.group(1) not in keep_ids:
            continue
        head = re.search(r"<version[^>]*/>", m.group(3))
        files = [f for f in re.findall(r"<file[^>]*>([^<]*)</file>", m.group(3)) if f in wanted]
        out.append('<package pkgid="%s"%s>%s%s</package>' % (
            m.group(1), m.group(2), head.group(0) if head else "",
            "".join("<file>%s</file>" % f for f in files)))
    return out


def write_repodata(outdir, primary_xml, filelists_xml):
    rd = os.path.join(outdir, "repodata")
    os.makedirs(rd, exist_ok=True)
    data = []
    for kind, xml in (("primary", primary_xml), ("filelists", filelists_xml)):
        raw = xml.encode()
        gz = gzip.compress(raw, 9, mtime=0)
        sha = hashlib.sha256(gz).hexdigest()
        name = "repodata/%s-%s.xml.gz" % (sha, kind)
        with open(os.path.join(outdir, name), "wb") as f:
            f.write(gz)
        data.append('<data type="%s"><checksum type="sha256">%s</checksum>'
                    '<open-checksum type="sha256">%s</open-checksum><location href="%s"/>'
                    '<timestamp>1</timestamp><size>%d</size><open-size>%d</open-size></data>' % (
                        kind, sha, hashlib.sha256(raw).hexdigest(), name, len(gz), len(raw)))
    repomd = ('<?xml version="1.0" encoding="UTF-8"?>\n'
              '<repomd xmlns="http://linux.duke.edu/metadata/repo" '
              'xmlns:rpm="http://linux.duke.edu/metadata/rpm"><revision>1</revision>%s</repomd>\n'
              % "".join(data))
    with open(os.path.join(rd, "repomd.xml"), "w") as f:
        f.write(repomd)


def main():
    primary, filelists, targets, outdir = sys.argv[1:5]
    pkgs = load_primary(primary)
    wanted_files = set()
    for p in pkgs:
        for name, _, _ in p.requires:
            if name.startswith("/"):
                wanted_files.add(name)
            elif name.startswith("("):
                names = []
                rich_names(parse_rich(name), names)
                wanted_files.update(n for n, _, _ in names if n.startswith("/"))
    for line in open(targets):
        wanted_files.update(s for s in line.split("#")[0].partition(":")[2].split() if s.startswith("/"))
    owners_by_sum = scan_filelists(filelists, wanted_files)
    byid = {p.pkgid: p for p in pkgs}
    owners = {f: [byid[i] for i in ids if i in byid] for f, ids in owners_by_sum.items()}
    repo = Repo(pkgs, owners)

    seeds = []
    for line in open(targets):
        line = line.split("#")[0].strip()
        if not line:
            continue
        _, _, specs = line.partition(":")
        for spec in specs.split():
            name = spec.rsplit(".", 1)[0] if spec.rsplit(".", 1)[-1] in ARCHES else spec
            arch = spec.rsplit(".", 1)[-1] if name != spec else None
            found = repo.providers(name)
            found = [p for p in found if arch is None or p.arch == arch]
            if not found:
                sys.exit("target %s not in the repository" % spec)
            seeds += sorted(found, key=rank(name))[:CAP]

    keep = closure(repo, seeds)
    alive, lost = prune(repo, keep, seeds)
    if lost:
        print("seeds that cannot be installed:", sorted(p.name + "." + p.arch for p in lost), file=sys.stderr)
    final = [keep[i] for i in sorted(alive)]
    final.sort(key=lambda p: (p.name, p.arch, p.epoch, p.ver, p.rel))
    wanted = required_files(final) | {s for line in open(targets) for s in line.split("#")[0].partition(":")[2].split() if s.startswith("/")}
    primary_xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                   '<metadata xmlns="http://linux.duke.edu/metadata/common" '
                   'xmlns:rpm="http://linux.duke.edu/metadata/rpm" packages="%d">\n%s\n</metadata>\n' % (
                       len(final), "\n".join(p.raw for p in final)))
    fl = filelists_entries(filelists, {p.pkgid for p in final}, wanted)
    filelists_xml = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                     '<filelists xmlns="http://linux.duke.edu/metadata/filelists" packages="%d">\n%s\n</filelists>\n' % (
                         len(fl), "\n".join(fl)))
    write_repodata(outdir, primary_xml, filelists_xml)
    print("%d packages, %d with listed files" % (len(final), len(fl)), file=sys.stderr)


if __name__ == "__main__":
    main()
