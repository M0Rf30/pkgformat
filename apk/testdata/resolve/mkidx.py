import sys, base64, hashlib
# Compact universe description -> APKINDEX text with unique canonical C: lines.
# line: name version | D=... | p=... | i=... | k=prio
def build(src):
    out=[]; n=0
    for line in src.strip().splitlines():
        line=line.strip()
        if not line or line.startswith('#'): continue
        parts=[x.strip() for x in line.split('|')]
        name,ver=parts[0].split()
        f={}
        for p in parts[1:]:
            k,v=p.split('=',1); f[k]=v
        c=base64.b64encode(hashlib.sha1((name+ver).encode()).digest()).decode()
        out.append("C:Q1"+c)
        out.append("P:"+name); out.append("V:"+ver); out.append("A:x86_64")
        out.append("S:1000"); out.append("I:4096"); out.append("T:"+name); out.append("U:https://example.org")
        out.append("L:MIT"); out.append("o:"+f.get('o',name)); out.append("t:1700000000")
        if 'D' in f: out.append("D:"+f['D'])
        if 'p' in f: out.append("p:"+f['p'])
        if 'i' in f: out.append("i:"+f['i'])
        if 'k' in f: out.append("k:"+f['k'])
        out.append("")
    return "\n".join(out)+"\n"
sys.stdout.write(build(open(sys.argv[1]).read()))
