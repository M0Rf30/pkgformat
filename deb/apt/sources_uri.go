package apt

import (
	"strconv"
	"strings"
)

// aptURI is a URI split the way apt's URI class does (apt-pkg/contrib/
// strutl.cc, URI::CopyFrom). It is deliberately not net/url: apt splits at
// the first colon and the first slash after the authority, keeps whatever
// follows verbatim, and the list file names derive from that exact split.
type aptURI struct {
	access   string
	user     string
	password string
	host     string
	port     uint64
	path     string
}

// parseAptURI splits raw like URI::CopyFrom. It reports false for a URI apt
// would give an empty host although it names one: an unterminated "[" in the
// host. A string without a colon is split too, as apt does, but is reported
// as not a URI.
func parseAptURI(raw string) (aptURI, bool) {
	var u aptURI

	n := len(raw)
	firstColon := strings.IndexByte(raw, ':')
	hasScheme := firstColon >= 0

	if !hasScheme {
		firstColon = n
	}

	// An authority "//" is followed by the first single slash, which ends
	// the host; slashes inside square brackets do not count.
	singleSlash := firstColon
	if firstColon+3 < n && raw[firstColon+1] == '/' && raw[firstColon+2] == '/' {
		singleSlash += 3
	}

	inBracket := false

	for ; singleSlash < n && (raw[singleSlash] != '/' || inBracket); singleSlash++ {
		if raw[singleSlash] == '[' {
			inBracket = true
		}

		if inBracket && raw[singleSlash] == ']' {
			inBracket = false
		}
	}

	u.access = raw[:firstColon]

	if singleSlash != n {
		u.path = raw[singleSlash:]
	}

	if u.path == "" {
		u.path = "/"
	}

	// user:password@host
	if firstColon+2 < n && raw[firstColon+1] == '/' && raw[firstColon+2] == '/' {
		firstColon += 3
	} else {
		firstColon++
	}

	if firstColon >= n {
		return u, hasScheme
	}

	firstColon = min(firstColon, singleSlash)
	from := min(firstColon+1, singleSlash)

	at := singleSlash
	if i := strings.LastIndexByte(raw[from:singleSlash], '@'); i >= 0 {
		at = from + i
	}

	if at == singleSlash {
		if firstColon < singleSlash {
			u.host = raw[firstColon:singleSlash]
		}
	} else {
		secondColon := at
		if i := strings.IndexByte(raw[from:at], ':'); i >= 0 {
			secondColon = from + i
		}

		u.host = raw[at+1 : singleSlash]
		u.user = dequote(raw[firstColon:secondColon])

		if secondColon < at {
			u.password = dequote(raw[secondColon+1 : at])
		}
	}

	// RFC 2732 "[v6]" hosts: drop the brackets, remember where they ended so
	// that the colons inside are not mistaken for a port.
	host := []byte(u.host)
	portEnd := 0
	inBracket = false

	for i := 0; i < len(host); {
		switch {
		case host[i] == '[':
			inBracket = true
			host = append(host[:i], host[i+1:]...)
		case inBracket && host[i] == ']':
			inBracket = false
			host = append(host[:i], host[i+1:]...)
			portEnd = i
		default:
			i++
		}
	}

	if inBracket {
		u.host = ""

		return u, false
	}

	u.host = string(host)

	if pos := strings.LastIndexByte(u.host, ':'); pos >= 0 && pos >= portEnd {
		u.port = atoiPort(u.host[pos+1:])
		u.host = u.host[:pos]
	}

	return u, hasScheme
}

// atoiPort reads the leading decimal digits of s like atoi, saturating
// instead of overflowing; anything else is port 0.
func atoiPort(s string) uint64 {
	s = strings.TrimLeft(s, " \t\n\v\f\r")

	var port uint64

	for i := 0; i < len(s) && s[i] >= '0' && s[i] <= '9'; i++ {
		port = port*10 + uint64(s[i]-'0')
		if port > 1<<31 {
			return 1 << 31
		}
	}

	return port
}

// dequote undoes QuoteString: "%xx" becomes the byte. It keeps a "%" that is
// not followed by two hex digits (and, like apt, one that ends the string).
func dequote(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}

	var sb strings.Builder

	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if hi, ok := unhex(s[i+1]); ok {
				if lo, ok := unhex(s[i+2]); ok {
					sb.WriteByte(hi<<4 | lo)

					i += 2

					continue
				}
			}
		}

		sb.WriteByte(s[i])
	}

	return sb.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}

	return 0, false
}

// quoteString is apt's QuoteString: every byte that is in bad, a control or
// blank (<= 0x20), non-ASCII (>= 0x7f) or a percent sign becomes "%" and two
// lower-case hex digits.
func quoteString(s, bad string) string {
	const hexDigits = "0123456789abcdef"

	var sb strings.Builder

	for i := range len(s) {
		c := s[i]

		if c <= 0x20 || c >= 0x7f || c == '%' || strings.IndexByte(bad, c) >= 0 {
			sb.WriteByte('%')
			sb.WriteByte(hexDigits[c>>4])
			sb.WriteByte(hexDigits[c&0xf])

			continue
		}

		sb.WriteByte(c)
	}

	return sb.String()
}

// Characters apt quotes in the file name of a URI (URItoFileName) and in the
// path parts of a request URI (pkgAcquire::URIEncode).
const (
	fileNameBad  = "\\|{}[]<>\"^~_=!@#$%^&*"
	uriEncodeBad = "+~ "
)

// uriToFileName is apt's URItoFileName: the URI without scheme, user and
// password, with every unsafe byte percent-quoted and "/" turned into "_". It
// reports false for a string that is not a URI (no scheme, or an unterminated
// "[" in the host).
func uriToFileName(raw string) (string, bool) {
	u, ok := parseAptURI(raw)
	if !ok {
		return "", false
	}

	var sb strings.Builder

	if u.host != "" {
		sb.WriteString(u.host)

		if u.port != 0 {
			sb.WriteByte(':')
			sb.WriteString(strconv.FormatUint(u.port, 10))
		}
	}

	if u.path != "" {
		if u.path[0] != '/' {
			sb.WriteByte('/')
		}

		sb.WriteString(u.path)
	}

	return strings.ReplaceAll(quoteString(sb.String(), fileNameBad), "/", "_"), true
}

// encodeHostPath is the host-and-path prefix apt gives the files it stores for
// a repository: "https://ports.ubuntu.com/ubuntu-ports/" becomes
// "ports.ubuntu.com_ubuntu-ports". It is "" for a URL that is none.
func encodeHostPath(rawURL string) string {
	name, ok := uriToFileName(withSlash(rawURL))
	if !ok {
		return ""
	}

	return strings.TrimSuffix(name, "_")
}

// withSlash returns raw with exactly one trailing slash.
func withSlash(raw string) string {
	if strings.HasSuffix(raw, "/") {
		return raw
	}

	return raw + "/"
}

// BaseURLs maps the encoded host-and-path prefix of apt's list file names to
// the URL of the source. Of several sources with the same prefix the last wins.
func BaseURLs(sources []Source) map[string]string {
	m := make(map[string]string, len(sources))

	for _, s := range sources {
		if key := encodeHostPath(s.URL); key != "" {
			m[key] = s.URL
		}
	}

	return m
}

// ListFileName returns the name apt stores relPath of a repository under:
// ("https://archive.ubuntu.com/ubuntu/", "jammy", "main/binary-amd64/Packages.xz")
// gives "archive.ubuntu.com_ubuntu_dists_jammy_main_binary-amd64_Packages.xz".
// It is ListFileNameFor of a source with that URL and suite. It returns "" for
// a URL that does not parse.
func ListFileName(baseURL, suite, relPath string) string {
	return ListFileNameFor(&Source{URL: baseURL, Suite: suite}, relPath)
}

// ListFileNameFor returns the name apt (URItoFileName of the file's URI) stores
// a file of the source under in /var/lib/apt/lists. relPath is the path below
// the suite directory: "InRelease", "Release", "Release.gpg",
// "main/binary-amd64/Packages", "main/binary-amd64/Packages.xz",
// "main/i18n/Translation-en", "main/Contents-amd64.gz", "main/source/Sources".
//
// The URI is the base URL, then "dists/<suite>/" (or the suite itself when it
// ends in a slash, nothing for the suite "/"), then relPath; user, password
// and scheme are dropped, host and port kept (a port is kept even when it is
// the default, 0 is dropped), and every byte apt quotes becomes "%xx" in lower
// case: "\|{}[]<>"^~_=!@#$%&*", blanks, controls and bytes over 0x7e. "/"
// becomes "_", so a file: URL, which has no host, starts with "_". The suite is
// quoted once for the request ("+", "~" and blank, as pkgAcquire::URIEncode
// does) and once more for the name, so "a+b" gives "a%252bb".
//
// It returns "" for a URL that is none (without scheme, or with an
// unterminated "[" in its host).
func ListFileNameFor(src *Source, relPath string) string {
	uri := withSlash(src.URL)

	base, ok := parseAptURI(uri)
	if !ok {
		return ""
	}

	switch {
	case src.Suite == "/":
	case strings.HasSuffix(src.Suite, "/"):
		uri += quoteString(src.Suite, uriEncodeBad)
	default:
		uri += "dists/" + quoteString(src.Suite, uriEncodeBad) + "/"
	}

	full, ok := parseAptURI(uri + relPath)

	// The suite and path must not be what gives the URL its scheme or its
	// host (a base URL such as "http://" with nothing after the slashes), and
	// must end up in the path (not swallowed by an unclosed "[" of the host).
	if !ok || full.access != base.access || full.host != base.host || full.port != base.port ||
		!strings.HasSuffix(full.path, uri[len(withSlash(src.URL)):]+relPath) {
		return ""
	}

	name, _ := uriToFileName(uri + relPath)

	return name
}
