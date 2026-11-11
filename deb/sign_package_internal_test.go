package deb

import "testing"

func FuzzParseDpkgSigManifest(f *testing.F) {
	f.Add("Version: 4\nSigner: a\nRole: builder\nFiles: \n\taa bb 4 debian-binary\n")
	f.Add("Files:\n\t1 2 3\n x\n:\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, body string) {
		fields, files := parseDpkgSigManifest(body)
		for k := range fields {
			if k != lowerASCII(k) {
				t.Fatalf("field name %q is not lower-cased", k)
			}
		}

		for _, d := range files {
			if d.name == "" {
				t.Fatalf("file without a name in %q", body)
			}
		}

		_ = roleOfMember(body)
	})
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}

	return string(b)
}
