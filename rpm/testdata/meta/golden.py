#!/usr/bin/env python3
# Writes golden.json: what librpm (python3 rpm bindings) reads from the
# fixtures of this directory. package_meta_test.go compares the reader to it.
import glob
import json
import os

import rpm

os.chdir(os.path.dirname(os.path.abspath(__file__)))
ts = rpm.TransactionSet()
ts.setVSFlags(-1)


def s(x):
    return x.decode() if isinstance(x, bytes) else x


def strs(h, t):
    v = h[t]
    if isinstance(v, list):
        return [s(i) for i in v]
    return [] if v in (None, b"", "") else [s(v)]


SCRIPTS = [("pretrans", "PRETRANS"), ("pre", "PREIN"), ("post", "POSTIN"),
           ("preun", "PREUN"), ("postun", "POSTUN"), ("posttrans", "POSTTRANS"),
           ("preuntrans", "PREUNTRANS"), ("postuntrans", "POSTUNTRANS"),
           ("verify", "VERIFYSCRIPT")]

out = {}
for f in sorted(glob.glob("*.rpm")):
    fd = os.open(f, os.O_RDONLY)
    h = ts.hdrFromFdno(fd)
    os.close(fd)
    g = {"scripts": {}}
    for name, base in SCRIPTS:
        body = h[getattr(rpm, "RPMTAG_" + base)]
        prog = strs(h, getattr(rpm, "RPMTAG_" + base + "PROG"))
        if body or prog:
            g["scripts"][name] = {"body": s(body) or "", "prog": prog,
                                  "flags": h[getattr(rpm, "RPMTAG_" + base + "FLAGS")] or 0}
    g["files"] = [{"path": x.name, "caps": x.caps or "", "nlink": x.nlink,
                   "lang": x.langs or "", "class": s(getattr(x, "class")) or "",
                   "verify": x.vflags & 0xFFFFFFFF, "rdev": x.rdev}
                  for x in rpm.files(h)]
    g["triggers"] = [s(x) for x in h[rpm.RPMTAG_TRIGGERNAME] or []]
    g["triggerscripts"] = [s(x) for x in h[rpm.RPMTAG_TRIGGERSCRIPTS] or []]
    g["filetriggerscripts"] = [s(x) for x in h[rpm.RPMTAG_FILETRIGGERSCRIPTS] or []]
    g["transfiletriggerscripts"] = [s(x) for x in h[rpm.RPMTAG_TRANSFILETRIGGERSCRIPTS] or []]
    g["filetriggerpriorities"] = list(h[rpm.RPMTAG_FILETRIGGERPRIORITIES] or [])
    g["transfiletriggerpriorities"] = list(h[rpm.RPMTAG_TRANSFILETRIGGERPRIORITIES] or [])
    g["sources"] = strs(h, rpm.RPMTAG_SOURCE)
    g["patches"] = strs(h, rpm.RPMTAG_PATCH)
    g["nosource"] = list(h[rpm.RPMTAG_NOSOURCE] or [])
    g["nopatch"] = list(h[rpm.RPMTAG_NOPATCH] or [])
    for k in ["MODULARITYLABEL", "DISTTAG", "BUGURL", "VCS", "DISTRIBUTION",
              "PLATFORM", "COOKIE", "PAYLOADFLAGS"]:
        g[k.lower()] = s(h[getattr(rpm, "RPMTAG_" + k)]) or ""
    for k in ["EXCLUSIVEARCH", "EXCLUDEARCH", "EXCLUSIVEOS", "EXCLUDEOS"]:
        g[k.lower()] = strs(h, getattr(rpm, "RPMTAG_" + k))
    g["source"] = bool(h.isSource())
    g["requires"] = [{"name": s(n), "flags": fl} for n, fl in
                     zip(strs(h, rpm.RPMTAG_REQUIRENAME), h[rpm.RPMTAG_REQUIREFLAGS])]
    out[f] = g

with open("golden.json", "w") as fp:
    json.dump(out, fp, indent=1, sort_keys=True)
    fp.write("\n")
