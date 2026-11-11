#!/usr/bin/env python3
"""Keep a few documents of a modules.yaml, byte for byte.

usage: trim_modules.py modules.yaml RULE...

A RULE is KIND:MODULE[:STREAM[:COUNT]] with KIND one of defaults, stream or
obsoletes. For streams, COUNT (default 1) is how many documents of the module
stream are kept, in file order. The kept documents are written to stdout in
the order of the rules.
"""
import re
import sys


def header(doc):
    kind = re.search(r"^document: (\S+)", doc, re.M).group(1)
    module = re.search(r"^  (?:module|name): (\S+)", doc, re.M).group(1)
    stream = re.search(r'^  stream: "?([^"\n]+)"?', doc, re.M)
    return kind, module.strip("\"'"), stream and stream.group(1)


def main():
    docs = [d.strip() for d in open(sys.argv[1], encoding="utf-8").read().split("\n...\n")]
    docs = [d for d in docs if d]
    parsed = [(d, header(d)) for d in docs]
    kinds = {"defaults": "modulemd-defaults", "stream": "modulemd", "obsoletes": "modulemd-obsoletes"}

    for rule in sys.argv[2:]:
        kind, module, *rest = rule.split(":")
        stream = rest[0] if rest else None
        count = int(rest[1]) if len(rest) > 1 else 1
        kept = 0
        for doc, (k, m, s) in parsed:
            if k != kinds[kind] or m != module or (stream and s != stream):
                continue
            if not doc.startswith("---"):
                doc = "---\n" + doc
            sys.stdout.write(doc.rstrip("\n").removesuffix("...").rstrip("\n") + "\n...\n")
            kept += 1
            if kind != "stream" or kept == count:
                break
        if kept == 0:
            sys.exit("no document matches " + rule)


main()
