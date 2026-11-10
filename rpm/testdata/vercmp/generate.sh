#!/bin/sh
# Regenerates golden.jsonl: version pairs with the result of librpm's
# comparison, one JSON array [first, second, result] per line.
#
# The reference is rpm.labelCompare of the python bindings of librpm (rpm
# 6.0.1 when this file was generated), which calls rpmvercmp for the version
# and release; the epoch and the release are fixed, so the result is the
# comparison of the two versions. The pairs come from a fixed seed: random
# strings of digits, letters, separators, tildes and carets, and mutations of
# them, so that most pairs are close to each other.
#
#   ./generate.sh > golden.jsonl
set -eu
exec python3 - <<'PY'
import json
import random
import rpm

rng = random.Random(20241110)
ALPHABET = "0123456789" * 3 + "abcdefghijklmnopqrstuvwxyzABCXYZ" + "..-_+:/ ~^~^^" + "é"
WORDS = ["rc", "beta", "alpha", "git", "snap", "pre", "post", "fc40", "el9", "20240101", "0", "00", "007", "1", "2", "10"]


def random_version():
    parts = []
    for _ in range(rng.randint(0, 6)):
        kind = rng.random()
        if kind < 0.5:
            parts.append(rng.choice(WORDS))
        elif kind < 0.8:
            parts.append("".join(rng.choice(ALPHABET) for _ in range(rng.randint(1, 4))))
        else:
            parts.append(rng.choice(["~", "^", ".", "-", "_", "+", "~^", "^~", ".."]))
        if rng.random() < 0.6:
            parts.append(rng.choice([".", "-", "_", "+", "", "~", "^"]))
    return "".join(parts)


def mutate(s):
    for _ in range(rng.randint(1, 3)):
        op = rng.randrange(6)
        i = rng.randint(0, len(s))
        if op == 0:
            s = s[:i] + rng.choice(ALPHABET) + s[i:]
        elif op == 1 and s:
            i = min(i, len(s) - 1)
            s = s[:i] + s[i + 1:]
        elif op == 2 and s:
            i = min(i, len(s) - 1)
            s = s[:i] + rng.choice(ALPHABET) + s[i + 1:]
        elif op == 3:
            s += rng.choice(["^", "~", "^git1", "~rc1", ".1", "a", "0", "^20240101"])
        elif op == 4:
            s = s[:i] + rng.choice(["^", "~", ".", "0"]) + s[i:]
        else:
            s = s.replace(".", rng.choice(["_", "-", ".."]), 1)
    return s


FIXED = [
    ("1.0", "1.0^"), ("1.0^git1", "1.0a"), ("2^a", "2.a"), ("1.0^20160101", "1.0.1"),
    ("1.0~rc1", "1.0"), ("1.0~rc1^git1", "1.0~rc1"), ("1.0^", "1.0^"), ("^", "1"), ("~", "^"),
    ("a", "1"), ("1", "a"), ("01", "1"), ("1.0\n", "1.0"), ("a\nb", "a"),
    ("1.0", "1.0 "), ("1_0", "1.0"), ("1.0", "1..0"), ("é", "a"), ("1.é", "1.a"),
    ("99999999999999999999999", "100000000000000000000000"),
]

pairs = list(FIXED)
while len(pairs) < 6000:
    a = random_version()
    b = mutate(a) if rng.random() < 0.7 else random_version()
    if a and b:  # the bindings reject an empty version
        pairs.append((a, b))

for a, b in pairs:
    print(json.dumps([a, b, rpm.labelCompare(("0", a, "1"), ("0", b, "1"))], ensure_ascii=False))
PY
