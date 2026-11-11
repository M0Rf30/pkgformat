package pacman

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// fnmatchPattern reports whether name matches the shell-style pattern the way
// fnmatch(3) with no flags does, which is what pacman uses for HoldPkg,
// IgnorePkg, IgnoreGroup, NoUpgrade and NoExtract: "*" matches any run of
// characters (a "/" included), "?" one character, "[...]" a set with ranges,
// "!" or "^" negation and POSIX classes such as "[:alpha:]", and a backslash
// quotes the next character.
func fnmatchPattern(pattern, name string) bool {
	var (
		pi, si       int
		starP, starS = -1, 0
	)

	for si < len(name) {
		r, rl := utf8.DecodeRuneInString(name[si:])

		if pi < len(pattern) {
			consumed, ok := matchOne(pattern[pi:], r)

			switch {
			case consumed < 0: // a star
				starP, starS = pi, si
				pi++

				continue
			case ok:
				pi += consumed
				si += rl

				continue
			}
		}

		if starP < 0 {
			return false
		}

		_, l := utf8.DecodeRuneInString(name[starS:])
		starS += l
		si, pi = starS, starP+1
	}

	return strings.Trim(pattern[pi:], "*") == ""
}

// matchOne matches the first element of pattern against r. It returns the
// length of the element consumed and whether r matched; a negative length
// reports "*".
func matchOne(pattern string, r rune) (consumed int, matched bool) {
	switch pattern[0] {
	case '*':
		return -1, false
	case '?':
		return 1, true
	case '[':
		if ok, n, valid := matchBracket(pattern, r); valid {
			return n, ok
		}

		return 1, r == '['
	case '\\':
		if len(pattern) > 1 {
			lit, l := utf8.DecodeRuneInString(pattern[1:])

			return 1 + l, r == lit
		}
	}

	lit, l := utf8.DecodeRuneInString(pattern)

	return l, r == lit
}

// matchBracket matches r against the bracket expression at the start of p. It
// returns whether r is in the set, the expression's length, and false for valid
// when the expression is not terminated (it is then a literal "[").
func matchBracket(p string, r rune) (in bool, n int, valid bool) {
	i := 1
	negate := false

	if i < len(p) && (p[i] == '!' || p[i] == '^') {
		negate = true
		i++
	}

	first := true

	for i < len(p) {
		c := p[i]

		if c == ']' && !first {
			return in != negate, i + 1, true
		}

		first = false

		if c == '[' && i+1 < len(p) && p[i+1] == ':' {
			if end := strings.Index(p[i+2:], ":]"); end >= 0 {
				if class, ok := posixClass(p[i+2 : i+2+end]); ok {
					in = in || class(r)
					i += end + 4

					continue
				}
			}
		}

		lo, l := bracketRune(p[i:])
		i += l

		if i+1 < len(p) && p[i] == '-' && p[i+1] != ']' {
			hi, hl := bracketRune(p[i+1:])
			i += 1 + hl
			in = in || (lo <= r && r <= hi)

			continue
		}

		in = in || r == lo
	}

	return false, 0, false
}

// bracketRune returns the character at the start of s, which a backslash may
// quote, and the bytes it takes.
func bracketRune(s string) (rune, int) {
	if s[0] == '\\' && len(s) > 1 {
		r, l := utf8.DecodeRuneInString(s[1:])

		return r, 1 + l
	}

	return utf8.DecodeRuneInString(s)
}

func posixClass(name string) (func(rune) bool, bool) {
	switch name {
	case "alpha":
		return unicode.IsLetter, true
	case "digit":
		return func(r rune) bool { return r >= '0' && r <= '9' }, true
	case "alnum":
		return func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }, true
	case "upper":
		return unicode.IsUpper, true
	case "lower":
		return unicode.IsLower, true
	case "space":
		return unicode.IsSpace, true
	case "punct":
		return func(r rune) bool { return unicode.IsPunct(r) || unicode.IsSymbol(r) }, true
	case "xdigit":
		return func(r rune) bool {
			return r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F'
		}, true
	}

	return nil, false
}

// matchAny reports whether name matches any of the patterns.
func matchAny(patterns []string, name string) bool {
	for _, p := range patterns {
		if fnmatchPattern(p, name) {
			return true
		}
	}

	return false
}
