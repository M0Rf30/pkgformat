#!/usr/bin/env python3
"""Regenerates parse_golden.tsv and eval_golden.tsv from librpm (rpmbuild, rpm).

Usage: python3 generate.py   (needs rpmbuild and rpm; takes a minute)

parse_golden.tsv: tag<TAB>accepted(1|0)<TAB>dependency   -- does rpmbuild accept
    the dependency as the value of a Requires/Conflicts line.
eval_golden.tsv:  tag<TAB>satisfied(1|0)<TAB>dependency  -- with the installed
    set of FIXTURES, is the Requires satisfied / does the Conflicts fire, as
    "rpm -U --test" decides it.
"""
import itertools, os, random, re, shutil, subprocess, sys, tempfile
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
WORK = tempfile.mkdtemp(prefix="richdep-")
TOP = os.path.join(WORK, "top")

# name -> list of provides (besides its own name = 1-1)
FIXTURES = {
    "a": ["a-virt = 2"],
    "b": [],
    "c": ["c-old < 1"],
    "x1": ["s1", "s2"],
    "x2": ["s1 = 1.5"],
    "x3": ["s2 = 3-4", "ep = 1:2.0"],
}

ATOMS = ["a", "b", "d", "e", "a >= 1", "a < 1", "a = 1", "a > 1-2", "a-virt >= 2", "a-virt = 1",
         "c-old < 1", "c-old > 1", "s1", "s2", "s1 >= 1.5", "s2 = 3", "s2 = 3-4", "s2 > 3-5",
         "x1", "x2", "x3", "ep = 2.0", "ep = 1:2.0", "ep >= 0:2", "ep < 1:3", "f = 1", "libfoo.so.1()(64bit)",
         "perl(Foo::Bar)", "/usr/bin/x"]

TAGS = ["Requires", "Conflicts", "Recommends", "Suggests", "Supplements", "Enhances", "Provides"]


def spec(lines, name="t"):
    return ("Name: %s\nVersion: 1\nRelease: 1\nSummary: t\nLicense: MIT\nBuildArch: noarch\n%s\n"
            "%%description\nt\n%%files\n") % (name, "\n".join(lines))


def rpmbuild(sp, mode, tag):
    path = os.path.join(WORK, "s-%s.spec" % tag)
    with open(path, "w") as f:
        f.write(sp)
    return subprocess.run(["rpmbuild", mode, "--define", "_topdir " + TOP, "--define", "_build_name_fmt %{ARCH}/%{NAME}.rpm",
                           path], capture_output=True, text=True)


def norm(e):
    """The text rpm prints for a rich dependency in a failure line: blanks and
    commas collapse to one space, the comparison operators are canonical."""
    e = re.sub(r"[\s,]+", " ", e.strip())
    e = re.sub(r"\(\s+", "(", e)
    e = re.sub(r"\s+\)", ")", e)
    return e.replace("=<", "<=").replace("=>", ">=").replace("==", "=")


def accepted(args):
    tag, expr, i = args
    r = rpmbuild(spec(["%s: %s" % (tag, expr)], "p%d" % i), "-bp", "p%d" % i)
    return r.returncode == 0


def gen_exprs(rng, n):
    out = set()
    ops2 = ["and", "or", "if", "unless", "with", "without"]

    def atom():
        return rng.choice(ATOMS)

    def grp(depth):
        k = rng.random()
        if depth == 0 or k < 0.3:
            return atom()
        if k < 0.45:
            op = rng.choice(["and", "or", "with"])
            m = rng.randint(2, 4)
            return "(" + (" %s " % op).join(grp(depth - 1) for _ in range(m)) + ")"
        if k < 0.6:
            op = rng.choice(["if", "unless"])
            return "(%s %s %s else %s)" % (grp(depth - 1), op, grp(depth - 1), grp(depth - 1))
        op = rng.choice(ops2)
        return "(%s %s %s)" % (grp(depth - 1), op, grp(depth - 1))

    while len(out) < n:
        e = grp(rng.randint(1, 3))
        if e.startswith("("):
            out.add(e)
    return sorted(out)


HAND = [
    "(a if b)", "(a unless b)", "(a and b and c)", "(a or b or c)", "(a with b)", "(a without b)",
    "(a if b else c)", "(a unless b else c)", "(a)", "((a))", "(a and (b or c))", "((a or b) and c)",
    "(a >= 1 and b)", "(a >= 1, b)", "(a,b)", "(a and)", "(and a)", "()", "(a b)", "(a >=)", "(a >= 1 2)",
    "(a if b if c)", "(a if b and c)", "(a and b or c)", "(a else b)", "(a if b else c else d)",
    "((a and b) with c)", "((a or b) with c)", "((a with b) or c)", "(a with b with c)", "(a without b without c)",
    "(a if (b or c))", "(a if (b and c))", "(a unless (b or c))", "((a if b) and c)", "((a unless b) or c)",
    "(perl(Foo) if perl(Bar))", "(libfoo.so.1()(64bit) or foo)", "(a >= 1:2.0-3 and b < 2)", "(a == 1)", "(a =< 1)", "(a => 1)",
    "(a  and   b)", "(A AND b)", "(a And b)",
    "a", "a >= 1", "(a >= 1", "((a if b)", "(a if b))", "(a xor b)", "(a with (b and c))",
    "(rpmlib(CompressedFileNames) <= 3.0.4-1 and a)", "(a if b else (c and d))",
    "(a unless b else (c or d))", "((a if b else c) with d)", "(a if (b else c))", "((a or b) if c else d)",
]


def main():
    rng = random.Random(20260101)
    os.makedirs(TOP, exist_ok=True)
    exprs = HAND + gen_exprs(rng, 700)

    jobs = [(t, e, i) for i, (t, e) in enumerate(itertools.product(["Requires", "Conflicts"], exprs))]
    # the other tags only for a smaller sample
    for t in TAGS[2:]:
        jobs += [(t, e, 100000 + len(jobs) + k) for k, e in enumerate(HAND + exprs[len(HAND):len(HAND) + 60])]

    with ThreadPoolExecutor(8) as ex:
        res = list(ex.map(accepted, jobs))

    with open(os.path.join(HERE, "parse_golden.tsv"), "w") as f:
        for (t, e, _), ok in zip(jobs, res):
            f.write("%s\t%d\t%s\n" % (t, 1 if ok else 0, e))

    # --- evaluation
    dbp = os.path.join(WORK, "db")
    os.makedirs(dbp)
    subprocess.run(["rpm", "--dbpath", dbp, "--initdb"], check=True)
    for n, provs in FIXTURES.items():
        lines = ["Provides: " + p for p in provs]
        r = rpmbuild(spec(lines, n), "-bb", n)
        if r.returncode:
            sys.exit(r.stderr)
        subprocess.run(["rpm", "--dbpath", dbp, "-i", "--justdb", "--nodeps", "--noscripts", "--nosignature", "--nodigest",
                        os.path.join(TOP, "RPMS", "noarch", n + ".rpm")], check=True)

    evals = [(t, e) for (t, e, _), ok in zip(jobs, res) if ok and t in ("Requires", "Conflicts") and e.startswith("(")]
    out = []
    for tag in ("Requires", "Conflicts"):
        es = sorted({e for t, e in evals if t == tag})
        for chunk in range(0, len(es), 200):
            part = es[chunk:chunk + 200]
            r = rpmbuild(spec(["%s: %s" % (tag, e) for e in part], "req"), "-bb", "req")
            if r.returncode:
                sys.exit(r.stderr)
            t = subprocess.run(["rpm", "--dbpath", dbp, "-U", "--test", "--nosignature", "--nodigest",
                                os.path.join(TOP, "RPMS", "noarch", "req.rpm")], capture_output=True, text=True)
            failed = set()
            for line in (t.stdout + t.stderr).splitlines():
                m = re.match(r"\t(.*) is needed by req-1-1\.noarch$", line) if tag == "Requires" else \
                    re.match(r"\t(.*) conflicts with (installed )?.*$", line)
                if m:
                    failed.add(norm(m.group(1)))
            for e in part:
                if tag == "Requires":
                    out.append((tag, 0 if norm(e) in failed else 1, e))
                else:
                    out.append((tag, 1 if norm(e) in failed else 0, e))
    with open(os.path.join(HERE, "eval_golden.tsv"), "w") as f:
        for tag, v, e in out:
            f.write("%s\t%d\t%s\n" % (tag, v, e))
    shutil.rmtree(WORK)
    overlaps(rng)


def overlaps(rng):
    """overlap_golden.tsv: flags1 TAB evr1 TAB flags2 TAB evr2 TAB result, where
    result is what the python bindings' ds.Compare says of the two same-named
    capabilities (a provide with flags1/evr1 against a requirement with
    flags2/evr2). Needs the rpm python module."""
    import rpm

    flags = [rpm.RPMSENSE_LESS, rpm.RPMSENSE_LESS | rpm.RPMSENSE_EQUAL, rpm.RPMSENSE_EQUAL,
             rpm.RPMSENSE_GREATER | rpm.RPMSENSE_EQUAL, rpm.RPMSENSE_GREATER]
    epochs = ["", "0:", "1:", "2:", ":"]
    versions = ["1", "1.0", "1.0.1", "1.1", "2", "10", "1~rc1", "1^post", "1a", "a", "01", "1.0~beta", "1_2", "5.2"]
    releases = ["", "-1", "-2", "-10", "-1.fc40", "-1~pre"]
    evrs = [e + v + r for e in epochs for v in versions for r in releases]
    seen, rows = set(), []
    while len(rows) < 6000:
        k = (rng.choice(flags), rng.choice(evrs), rng.choice(flags), rng.choice(evrs))
        if k in seen:
            continue
        seen.add(k)
        a = rpm.ds(("n", k[0], k[1]), "Provides")
        b = rpm.ds(("n", k[2], k[3]), "Requires")
        rows.append((k, 1 if a.Compare(b) else 0))
    # unversioned sides overlap whatever the other says
    with open(os.path.join(HERE, "overlap_golden.tsv"), "w") as f:
        for k, v in rows:
            f.write("%d\t%s\t%d\t%s\t%d\n" % (k[0], k[1], k[2], k[3], v))


main()
