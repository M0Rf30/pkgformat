#!/usr/bin/env python3
"""Regenerates fedora_golden.tsv: boolean dependencies of real Fedora packages.

usage: python3 fedora_corpus.py PRIMARY.xml     (needs rpmbuild)

PRIMARY.xml is the decompressed primary.xml of the Fedora 43 release repository
(repodata/*-primary.xml.zst under
https://dl.fedoraproject.org/pub/fedora/linux/releases/43/Everything/x86_64/os/).
Every rich dependency of its Requires, Recommends, Suggests, Supplements and
Enhances is a candidate; the corpus keeps, for each distinct shape (the tree of
operators and comparison operators, names and versions stripped) up to
PER_SHAPE of them, and then a random sample of the rest (SAMPLE entries per tag).
rpmbuild then confirms that librpm accepts each one as the value of its tag,
and the file records tag, 1 or 0, and the dependency, as parse_golden.tsv does.
"""
import html
import os
import random
import re
import subprocess
import sys
import tempfile
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
PER_SHAPE = 3
SAMPLE = {"Requires": 800, "Recommends": 100, "Suggests": 20, "Supplements": 200, "Enhances": 20}
TAGS = {"requires": "Requires", "recommends": "Recommends", "suggests": "Suggests",
        "supplements": "Supplements", "enhances": "Enhances"}


def shape(dep):
    toks = re.findall(r"\(|\)|[^\s()]+", dep)
    out = []
    for t in toks:
        if t in ("(", ")", "and", "or", "if", "unless", "else", "with", "without", "<", "<=", "=", ">=", ">"):
            out.append(t)
        elif out and out[-1] in ("<", "<=", "=", ">=", ">"):
            out.append("V")
        else:
            out.append("N")
    return " ".join(out)


def accepted(tag, deps, work):
    spec = ("Name: t\nVersion: 1\nRelease: 1\nSummary: t\nLicense: MIT\nBuildArch: noarch\n%s\n"
            "%%description\nt\n%%files\n") % "\n".join("%s: %s" % (tag, d) for d in deps)
    path = os.path.join(work, "t.spec")
    with open(path, "w") as f:
        f.write(spec)
    r = subprocess.run(["rpmbuild", "-bp", "--define", "_topdir " + work, path], capture_output=True)
    return r.returncode == 0


def main():
    text = open(sys.argv[1], encoding="utf-8").read()
    seen = defaultdict(set)
    for sect, tag in TAGS.items():
        for m in re.finditer(r"<rpm:%s>(.*?)</rpm:%s>" % (sect, sect), text, re.S):
            for e in re.finditer(r'<rpm:entry name="(\([^"]*)"', m.group(1)):
                seen[tag].add(html.unescape(e.group(1)))

    rng = random.Random(43)
    chosen = []
    for tag in sorted(seen):
        by_shape = defaultdict(list)
        for d in sorted(seen[tag]):
            by_shape[shape(d)].append(d)
        rest = []
        for s in sorted(by_shape):
            deps = by_shape[s]
            rng.shuffle(deps)
            chosen += [(tag, d) for d in deps[:PER_SHAPE]]
            rest += [(tag, d) for d in deps[PER_SHAPE:]]
        rng.shuffle(rest)
        chosen += rest[:SAMPLE[tag]]

    chosen = sorted(set(chosen))
    work = tempfile.mkdtemp(prefix="fedora-corpus-")
    rows = []
    for tag in sorted({t for t, _ in chosen}):
        deps = [d for t, d in chosen if t == tag]
        for i in range(0, len(deps), 50):
            part = deps[i:i + 50]
            if accepted(tag, part, work):
                rows += [(tag, 1, d) for d in part]
            else:
                rows += [(tag, 1 if accepted(tag, [d], work) else 0, d) for d in part]

    with open(os.path.join(HERE, "fedora_golden.tsv"), "w") as f:
        for tag, ok, d in rows:
            f.write("%s\t%d\t%s\n" % (tag, ok, d))
    print(len(rows), "dependencies,", sum(1 for r in rows if not r[1]), "refused by rpmbuild", file=sys.stderr)


main()
