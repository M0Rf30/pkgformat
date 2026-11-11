#!/usr/bin/env python3
"""Cut a few entries out of a published comps.xml, keeping their text as it is.

usage: trim.py SOURCE OUTPUT [--groups a,b] [--categories a,b]
               [--environments a,b] [--langpacks a,b] [--blacklist N]
               [--whiteout N]

Only whole top-level elements are copied, line for line. Two things are
changed so that the result is self-consistent: the document header is the
single-line form of the DOCTYPE, and <groupid> lines that name a group that
was not kept are dropped from the categories and environments that were.
--blacklist N and --whiteout N keep the first N entries of those lists;
--langpacks keeps the <match> lines whose name is listed.
"""
import argparse
import re
import sys

HEADER = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE comps PUBLIC "-//Red Hat, Inc.//DTD Comps info//EN" "comps.dtd">\n'
    "<comps>\n"
)


def blocks(lines):
    """Yield (tag, [lines]) for every top-level element of the document."""
    i = 0
    while i < len(lines):
        m = re.match(r"^  <(\w+)>$", lines[i])
        if not m:
            i += 1
            continue
        tag = m.group(1)
        j = i
        while lines[j] != "  </%s>" % tag:
            j += 1
        yield tag, lines[i : j + 1]
        i = j + 1


def ident(block):
    for line in block:
        m = re.match(r"^    <id>(.*)</id>$", line)
        if m:
            return m.group(1)
    raise SystemExit("element without id")


def csv(s):
    return [x for x in (s or "").split(",") if x]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source")
    ap.add_argument("output")
    ap.add_argument("--groups", default="")
    ap.add_argument("--categories", default="")
    ap.add_argument("--environments", default="")
    ap.add_argument("--langpacks", default="")
    ap.add_argument("--blacklist", type=int, default=0)
    ap.add_argument("--whiteout", type=int, default=0)
    a = ap.parse_args()

    with open(a.source, encoding="utf-8") as f:
        lines = f.read().split("\n")

    want = {
        "group": csv(a.groups),
        "category": csv(a.categories),
        "environment": csv(a.environments),
    }
    kept = set(want["group"])
    found = {k: {} for k in want}
    rules = {}
    for tag, block in blocks(lines):
        if tag in want:
            found[tag][ident(block)] = block
        else:
            rules[tag] = block

    out = []
    for tag in ("group", "category", "environment"):
        for gid in want[tag]:
            if gid not in found[tag]:
                raise SystemExit("%s %s not found" % (tag, gid))
            block = found[tag][gid]
            if tag != "group":
                block = [
                    l
                    for l in block
                    if not re.match(r"^      <groupid[ >]", l)
                    or re.sub(r"<[^>]*>", "", l).strip() in kept
                ]
            out += block

    langpacks = csv(a.langpacks)
    if langpacks:
        block = rules["langpacks"]
        out += [block[0]]
        out += [
            l
            for l in block[1:-1]
            if re.search(r'name="([^"]*)"', l).group(1) in langpacks
        ]
        out += [block[-1]]
    for tag, n in (("blacklist", a.blacklist), ("whiteout", a.whiteout)):
        if n:
            block = rules[tag]
            out += block[: n + 1] + [block[-1]]

    with open(a.output, "w", encoding="utf-8") as f:
        f.write(HEADER + "\n".join(out) + "\n</comps>\n")


if __name__ == "__main__":
    sys.exit(main())
