"""Version-aware dependency queries, answered by librpm itself.

For each line "v:<tag>\t<capability>" of queries.txt, print the packages of the
database whose <tag> dependencies overlap the capability, as rpm decides it
(rpmdsCompare), in the record format of the other queries:

    v:<tag>\t<capability>\t<NEVRA> <NEVRA> ...

usage: queries.py <root> <queries.txt>
"""
import re
import sys

import rpm

ROOT, QUERIES = sys.argv[1], sys.argv[2]

FLAGS = {
    "<": rpm.RPMSENSE_LESS,
    "<=": rpm.RPMSENSE_LESS | rpm.RPMSENSE_EQUAL,
    "=": rpm.RPMSENSE_EQUAL,
    ">=": rpm.RPMSENSE_GREATER | rpm.RPMSENSE_EQUAL,
    ">": rpm.RPMSENSE_GREATER,
}

TAGS = {
    "provides": (rpm.RPMTAG_PROVIDENAME, rpm.RPMTAG_PROVIDEFLAGS, rpm.RPMTAG_PROVIDEVERSION),
    "requires": (rpm.RPMTAG_REQUIRENAME, rpm.RPMTAG_REQUIREFLAGS, rpm.RPMTAG_REQUIREVERSION),
    "conflicts": (rpm.RPMTAG_CONFLICTNAME, rpm.RPMTAG_CONFLICTFLAGS, rpm.RPMTAG_CONFLICTVERSION),
    "obsoletes": (rpm.RPMTAG_OBSOLETENAME, rpm.RPMTAG_OBSOLETEFLAGS, rpm.RPMTAG_OBSOLETEVERSION),
    "recommends": (rpm.RPMTAG_RECOMMENDNAME, rpm.RPMTAG_RECOMMENDFLAGS, rpm.RPMTAG_RECOMMENDVERSION),
    "suggests": (rpm.RPMTAG_SUGGESTNAME, rpm.RPMTAG_SUGGESTFLAGS, rpm.RPMTAG_SUGGESTVERSION),
    "supplements": (rpm.RPMTAG_SUPPLEMENTNAME, rpm.RPMTAG_SUPPLEMENTFLAGS, rpm.RPMTAG_SUPPLEMENTVERSION),
    "enhances": (rpm.RPMTAG_ENHANCENAME, rpm.RPMTAG_ENHANCEFLAGS, rpm.RPMTAG_ENHANCEVERSION),
}


def capability(spec, kind):
    """A one-entry dependency set of the given kind holding spec."""
    m = re.fullmatch(r"(\S+)(?: (<=|>=|<|>|=) (\S+))?", spec)
    name, op, evr = m.groups()
    nametag, flagstag, versiontag = TAGS[kind]
    h = rpm.hdr()
    h[nametag] = [name]
    h[flagstag] = [FLAGS[op] if op else 0]
    h[versiontag] = [evr or ""]
    ds = rpm.ds(h, kind)
    next(iter(ds))  # position on the only entry
    return ds


headers = list(rpm.TransactionSet(ROOT).dbMatch())

for line in open(QUERIES):
    fields = line.rstrip("\n").split("\t")
    if not fields[0].startswith("v:"):
        continue
    kind, spec = fields[0][2:], fields[1]
    cap = capability(spec, kind)
    found = []
    for h in headers:
        deps = rpm.ds(h, kind)
        if any(deps.Compare(cap) for _ in deps):
            found.append(h.sprintf("%{NEVRA}"))
    print("\t".join([fields[0], spec, " ".join(sorted(found))]))
