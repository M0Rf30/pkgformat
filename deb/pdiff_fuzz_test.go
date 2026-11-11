package deb_test

import (
	"bytes"
	"testing"

	"github.com/M0Rf30/pkgformat/deb"
)

func FuzzParsePDiffIndex(f *testing.F) {
	for _, p := range [][]string{{"buster-updates", "Index"}, {"trixie-updates", "Index"}} {
		f.Add(pdiffRawFile(f, p...))
	}

	f.Add([]byte("SHA256-Current: " + deb.PDiffSHA256(nil) + " 0\nSHA256-History:\n " + deb.PDiffSHA256(nil) + " 0 a\nSHA256-Patches:\n " + deb.PDiffSHA256(nil) + " 0 a\nSHA256-Download:\n " + deb.PDiffSHA256(nil) + " 0 a.gz\n"))
	f.Add([]byte(""))
	f.Add([]byte("X-Patch-Precedence: merged\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		idx, err := deb.ParsePDiffIndex(data)
		if err != nil {
			return
		}

		// What parses marshals and parses to the same thing.
		again, err := deb.ParsePDiffIndex(idx.Marshal())
		if err != nil {
			t.Fatalf("Marshal output does not parse: %v", err)
		}

		if !bytes.Equal(again.Marshal(), idx.Marshal()) {
			t.Fatalf("Marshal is not stable")
		}

		// Chains never panic, whatever hash is asked for.
		_, _ = idx.Chain(idx.Current.SHA256)

		for _, p := range idx.Patches {
			_, _ = idx.Chain(p.From.SHA256)
		}
	})
}

func FuzzApplyPDiff(f *testing.F) {
	f.Add([]byte("a\nb\nc\n"), []byte("2c\nX\n.\n"))
	f.Add([]byte("a\nb\nc\n"), []byte("3a\nx\n.\n1d\n"))
	f.Add([]byte("a\nb"), []byte("0a\nz\n.\n"))
	f.Add([]byte(""), []byte("0a\nz\n.\n"))
	f.Add([]byte("a\n"), []byte("1,5d\n"))
	f.Add([]byte("a\n"), []byte("1a\nx\n"))

	opts := deb.PDiffApplyOptions{MaxPatchSize: 1 << 16, MaxResultSize: 1 << 16, MaxCommands: 1 << 10}

	f.Fuzz(func(t *testing.T, base, patch []byte) {
		out, err := deb.ApplyPDiffWith(base, patch, opts)
		if err != nil {
			return
		}

		if int64(len(out)) > opts.MaxResultSize {
			t.Fatalf("result of %d bytes exceeds the limit", len(out))
		}

		// A patch that applies also merges with itself on the result...
		// ...and the merge of a patch with nothing is the patch's effect.
		merged, err := deb.MergePDiffsWith(opts, patch)
		if err != nil {
			t.Fatalf("a patch that applies does not merge: %v", err)
		}

		again, err := deb.ApplyPDiffWith(base, merged, opts)
		if err != nil {
			t.Fatalf("the merged patch does not apply: %v", err)
		}

		if !bytes.Equal(again, out) {
			t.Fatalf("merge of one patch changed its effect: %q vs %q", again, out)
		}
	})
}

func FuzzGenerateApply(f *testing.F) {
	f.Add([]byte("a\nb\nc\n"), []byte("a\nX\nc\n"))
	f.Add([]byte(""), []byte("a\n"))
	f.Add([]byte("a\n"), []byte(""))
	f.Add([]byte("a\n.\nb\n"), []byte("a\nb\n"))
	f.Add([]byte("a\nb"), []byte("a\nc"))

	f.Fuzz(func(t *testing.T, oldData, newData []byte) {
		if len(oldData) > 1<<14 || len(newData) > 1<<14 {
			return
		}

		patch, err := deb.GeneratePDiff(oldData, newData)
		if err != nil {
			return
		}

		got, err := deb.ApplyPDiff(oldData, patch)
		if err != nil {
			t.Fatalf("generated patch does not apply: %v\nold=%q new=%q patch=%q", err, oldData, newData, patch)
		}

		if !bytes.Equal(got, newData) {
			t.Fatalf("round trip mismatch\nold=%q new=%q patch=%q got=%q", oldData, newData, patch, got)
		}
	})
}

func FuzzMergePDiffs(f *testing.F) {
	f.Add([]byte("a\nb\nc\nd\n"), []byte("2c\nX\n.\n"), []byte("3d\n1a\nw\n.\n"))
	f.Add([]byte("a\n"), []byte("1a\nx\ny\n.\n"), []byte("2d\n"))

	opts := deb.PDiffApplyOptions{MaxPatchSize: 1 << 14, MaxResultSize: 1 << 16, MaxCommands: 1 << 10}

	f.Fuzz(func(t *testing.T, base, p1, p2 []byte) {
		// Merging works on whole lines; a file that ends without a newline
		// has no whole last line, and applying patches to it is byte-level.
		if len(base) > 0 && base[len(base)-1] != '\n' {
			return
		}

		mid, err := deb.ApplyPDiffWith(base, p1, opts)
		if err != nil {
			return
		}

		want, err := deb.ApplyPDiffWith(mid, p2, opts)
		if err != nil {
			return
		}

		merged, err := deb.MergePDiffsWith(opts, p1, p2)
		if err != nil {
			t.Fatalf("patches that apply in turn do not merge: %v", err)
		}

		got, err := deb.ApplyPDiffWith(base, merged, opts)
		if err != nil {
			t.Fatalf("merged patch does not apply: %v\nmerged=%q", err, merged)
		}

		if !bytes.Equal(got, want) {
			t.Fatalf("merge differs from sequential apply\nbase=%q p1=%q p2=%q merged=%q\ngot=%q want=%q", base, p1, p2, merged, got, want)
		}
	})
}
