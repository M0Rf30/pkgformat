package pack

import (
	"io"
	"testing"
)

// entriesOf returns the files of r as Write sees them.
func entriesOf(t *testing.T, r *RPM) []*fileEntry {
	t.Helper()
	e, err := r.prepareFiles()
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func basenamesOf(t *testing.T, r *RPM) []string {
	t.Helper()
	var out []string
	for _, e := range entriesOf(t, r) {
		out = append(out, e.base)
	}
	return out
}

func modesOf(t *testing.T, r *RPM) []uint16 {
	t.Helper()
	var out []uint16
	for _, e := range entriesOf(t, r) {
		out = append(out, uint16(e.Mode))
	}
	return out
}

// compressorWriter returns the writer r compresses its payload with.
func compressorWriter(t *testing.T, r *RPM) io.WriteCloser {
	t.Helper()
	w, err := r.comp.open(io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return w
}
