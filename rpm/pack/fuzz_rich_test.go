package pack

import (
	"errors"
	"io"
	"testing"
)

func FuzzValidateRich(f *testing.F) {
	for _, s := range []string{"(a or b)", "(a if b else c)", "((a and b) or c)", "(a with b)", "(", "", "(a >= 1 or b)"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		err := ValidateRich(s)
		if err != nil && !errors.Is(err, ErrInvalidRelation) {
			t.Fatalf("error %v does not wrap ErrInvalidRelation", err)
		}
		// the context rules only reject more
		if err != nil && validateRich(s, richAnd) == nil {
			t.Fatalf("%q: rejected without context but accepted in one", s)
		}
	})
}

func FuzzWriteFiles(f *testing.F) {
	f.Add("/a/b", uint(0644), "root", "body", int64(0))
	f.Add("/dev/x", uint(020644), "u", "", int64(5))
	f.Add("//x/../y", uint(0120777), "", "t", int64(-1))
	f.Fuzz(func(t *testing.T, name string, mode uint, owner, body string, size int64) {
		r, err := NewRPM(RPMMetaData{Name: "f", Version: "1", Release: "1"})
		if err != nil {
			t.Fatal(err)
		}
		r.AddFile(RPMFile{Name: name, Mode: mode, Owner: owner, Body: []byte(body), Size: size})
		if err := r.Write(io.Discard); err != nil &&
			!errors.Is(err, ErrInvalidFile) && !errors.Is(err, ErrInvalidMetadata) {
			t.Fatalf("unexpected error type: %v", err)
		}
	})
}
