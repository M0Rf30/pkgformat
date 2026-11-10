#!/bin/sh
# Regenerates the version fixtures in this directory with the host's apk
# (apk-tools 3.0.9 was used for the committed files):
#
#   pairs.golden   "a op b" lines, op being what `apk version -t a b` prints
#                  (<, = or >), for 3000+ generated and hand-written pairs
#   valid.golden   "V|I version" lines, from `apk version -c`, which lists the
#                  strings that are not versions
#
# The generated versions come from a seeded awk generator, so the pair list
# is stable. Needs apk 3 in PATH; no network, no root.
set -eu

cd "$(dirname "$0")"

gen() {
	awk -v seed=20260101 -v count=4000 '
	function pick(n) { return int(rand() * n) }
	function ver(   v, n, i, s) {
		v = (1 + pick(12))
		n = pick(4)
		for (i = 0; i < n; i++) v = v "." (pick(4) == 0 ? "0" pick(10) : pick(30))
		if (pick(4) == 0) v = v sprintf("%c", 97 + pick(4))
		n = pick(3) == 0 ? 1 + pick(2) : 0
		for (i = 0; i < n; i++) {
			split("alpha beta pre rc cvs svn git hg p", S, " ")
			s = S[1 + pick(9)]
			v = v "_" s (pick(2) ? pick(5) : "")
		}
		if (pick(10) == 0) v = v "~" substr("0123456789abcdef9fceb02", 1 + pick(8), 3 + pick(4))
		if (pick(3) == 0) v = v "-r" pick(6)
		return v
	}
	function mutate(v,   r) {
		r = pick(8)
		if (r == 0) return v "-r" pick(4)
		if (r == 1) return v "." pick(3)
		if (r == 2) return v "_rc" pick(3)
		if (r == 3) return v "_p" pick(3)
		if (r == 4) return v "a"
		if (r == 5) { sub(/-r[0-9]+$/, "", v); return v }
		if (r == 6) return v "_git"
		return v "~" substr("abcdef0123", 1 + pick(5), 4)
	}
	BEGIN {
		srand(seed)
		for (i = 0; i < count; i++) {
			a = ver()
			b = (pick(2) == 0) ? ver() : mutate(a)
			print a, b
		}
	}'
}

edge() {
	cat <<'EOT'
1.0 1.0
1.0 1.0.0
1.0 1.00
1.01 1.1
1.1 1.10
1.2.3 1.2.3-r0
1.2.3-r1 1.2.3-r2
1.2.3-r10 1.2.3-r9
1.0 1.0a
1.0a 1.0b
1.0z 1.0.1
1.0_alpha 1.0_beta
1.0_beta 1.0_pre
1.0_pre 1.0_rc
1.0_rc1 1.0_rc2
1.0_rc1 1.0
1.0 1.0_cvs
1.0_cvs 1.0_svn
1.0_svn 1.0_git
1.0_git 1.0_hg
1.0_hg 1.0_p
1.0_p1 1.0_p2
1.0_p 1.0_p0
1.0_p1 1.0.1
1.0_rc1 1.0_rc1-r1
1.0~abc 1.0
1.0~abc 1.0~abd
1.0~ABC 1.0~abc
1.0_git~abc 1.0_git~abd
1.0_git20240101 1.0_git20230101
2.0_alpha1 1.9.9
10.0 9.9
0.1 0.01
0.1 0.2
9223372036854775807 9223372036854775806
18446744073709551615 18446744073709551614
1.0-r0 1.0
1.0_alpha_beta 1.0_alpha
1.0_p1_rc1 1.0_p1
1.2.3_rc1_p1 1.2.3_rc1
1.2a_rc1 1.2a
1.2a 1.2_p1
1.0.0.0 1.0.0
1.0.0 1.0
EOT
}

gen > /tmp/version-pairs.$$
edge >> /tmp/version-pairs.$$

while read -r a b; do
	op=$(apk version -t "$a" "$b" 2>/dev/null || true)
	# apk prints nothing when a string is not a version.
	[ -z "$op" ] || printf '%s %s %s\n' "$a" "$op" "$b"
done < /tmp/version-pairs.$$ > pairs.golden
rm -f /tmp/version-pairs.$$

# Which strings are versions.
cand='1.0 1 0 00 1.0.0 1. .1 1..0 1.0a 1.0ab a1.0 1.0-r1 1.0-r 1.0-1 1.0-r01 1.0_rc1 1.0_rc
1.0_foo 1.0_ 1.0__rc1 1.0_RC1 1.0~abc 1.0~ 1.0~xyz 1.0_rc1~abc 1.0~abc_rc1 1.0~abc-r1 1.0-r1~abc
1.0-r1-r1 1.0_rc1a 1.0a_rc1 1.0_rc1.1 1.0.a 1.0 -1 +1 1.0+1 1:1.0 1.0_p1_p2_p3_p4 1a 1a.1
18446744073709551616 1.18446744073709551616 1.0_rc18446744073709551616 1.0-r18446744073709551616
1.2.3.4.5.6.7.8.9.10.11.12'
bad=$(apk version -c -- $cand 2>&1 || true)
for c in $cand; do
	case "
$bad
" in
	*"
$c
"*) echo "I $c" ;;
	*) echo "V $c" ;;
	esac
done > valid.golden
