package deb_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/deb"
)

// The interop tests compare this package with the tools that read pdiffs in
// the real world: rred (apt's patch applier) and GNU ed. The fixtures and the
// way they were made are described in testdata/repo-pdiff/README.md.

const pdiffSemanticBase = "1\n2\n3\n4\n5\n"

// pdiffSemanticCases are hand-written scripts and what they turn
// pdiffSemanticBase into; rred and ed agree with every one of them.
var pdiffSemanticCases = []struct{ name, patch, want string }{
	{"empty-patch", "", pdiffSemanticBase},
	{"append-after-line", "2a\nx\ny\n.\n", "1\n2\nx\ny\n3\n4\n5\n"},
	{"append-at-start", "0a\nx\n.\n", "x\n" + pdiffSemanticBase},
	{"append-at-end", "5a\nx\n.\n", pdiffSemanticBase + "x\n"},
	{"append-nothing", "3a\n.\n", pdiffSemanticBase},
	{"change-one", "3c\nX\n.\n", "1\n2\nX\n4\n5\n"},
	{"change-range", "2,4c\nX\n.\n", "1\nX\n5\n"},
	{"change-to-more-lines", "3c\nX\nY\nZ\n.\n", "1\n2\nX\nY\nZ\n4\n5\n"},
	{"change-to-nothing", "3c\n.\n", "1\n2\n4\n5\n"},
	{"delete-one", "3d\n", "1\n2\n4\n5\n"},
	{"delete-range", "2,3d\n", "1\n4\n5\n"},
	{"delete-all", "1,5d\n", ""},
	{"delete-last", "5d\n", "1\n2\n3\n4\n"},
	{"descending-order", "5c\nE\n.\n3a\nC\n.\n1d\n", "2\n3\nC\n4\nE\n"},
	{"two-appends-stack-like-ed", "2a\nX\n.\n2a\nY\n.\n", "1\n2\nY\nX\n3\n4\n5\n"},
	{"append-then-change-same-line", "3a\nA\n.\n3c\nC\n.\n", "1\n2\nC\nA\n4\n5\n"},
	{"insert-before-changed-line", "2c\nB\n.\n1a\nA\n.\n", "1\nA\nB\n3\n4\n5\n"},
	{"text-of-dots", "1a\n..\n...\n.\n", "1\n..\n...\n2\n3\n4\n5\n"},
	{"text-looks-like-command", "1a\n2d\n.\n", "1\n2d\n2\n3\n4\n5\n"},
	{"append-then-delete-the-line-it-follows", "3a\nx\n.\n3d\n", "1\n2\nx\n4\n5\n"},
}

// pdiffInteropCase is one old/new pair with a patch from old to new.
type pdiffInteropCase struct {
	ID              string
	Old, New, Patch []byte
	Handwritten     bool // the patch is not made by GeneratePDiff
}

// pdiffSyntheticCases builds the cases kept in testdata/repo-pdiff/interop.
func pdiffSyntheticCases(tb testing.TB) []pdiffInteropCase {
	tb.Helper()

	var cases []pdiffInteropCase

	for i, c := range pdiffSemanticCases {
		cases = append(cases, pdiffInteropCase{
			ID:  fmt.Sprintf("sem-%02d-%s", i+1, c.name),
			Old: []byte(pdiffSemanticBase), New: []byte(c.want), Patch: []byte(c.patch), Handwritten: true,
		})
	}

	edge := []struct{ name, old, new string }{
		{"from-empty", "", "a\nb\n"},
		{"to-empty", "a\nb\n", ""},
		{"replace-all", "a\nb\n", "x\ny\nz\n"},
		{"dot-line-stays", "a\n.\nb\n", "A\n.\nb\n"},
		{"dot-line-deleted", "a\n.\nb\n", "a\nb\n"},
		{"two-hunks", "a\nb\nc\nd\ne\n", "A\nb\nc\nd\nE\n"},
		{"append-and-prepend", "b\n", "a\nb\nc\n"},
		{"blank-lines", "\n\na\n\n", "\na\n\n\n"},
	}
	for i, e := range edge {
		patch, err := deb.GeneratePDiff([]byte(e.old), []byte(e.new))
		require.NoError(tb, err)

		cases = append(cases, pdiffInteropCase{
			ID:  fmt.Sprintf("gen-%02d-%s", i+1, e.name),
			Old: []byte(e.old), New: []byte(e.new), Patch: patch,
		})
	}

	r := rand.New(rand.NewPCG(2024, 7))

	for i := range 12 {
		alphabet := 3 + r.IntN(20)
		oldData := pdiffRandomFile(r, 10+r.IntN(30), alphabet)
		newData := pdiffMutate(r, oldData, 1+r.IntN(6), alphabet)

		patch, err := deb.GeneratePDiff([]byte(oldData), []byte(newData))
		require.NoError(tb, err)

		cases = append(cases, pdiffInteropCase{
			ID:  fmt.Sprintf("rand-%02d", i+1),
			Old: []byte(oldData), New: []byte(newData), Patch: patch,
		})
	}

	return cases
}

// pdiffRealBases lists the Packages files of the trixie-updates fixture, oldest
// first, ending with the current one.
func pdiffRealBases(tb testing.TB) []string {
	tb.Helper()

	names, err := filepath.Glob(filepath.Join(pdiffTestdata, "trixie-updates", "base-*.xz"))
	require.NoError(tb, err)
	slices.Sort(names)

	for i, n := range names {
		names[i] = filepath.Base(n)
	}

	return names
}

// pdiffRealCases are the pairs of neighbouring archive snapshots, with the
// patches this package makes for them.
func pdiffRealCases(tb testing.TB) []pdiffInteropCase {
	tb.Helper()

	files := pdiffRealBases(tb)
	data := make([][]byte, 0, len(files)+1)

	for _, f := range files {
		data = append(data, pdiffReadFile(tb, "trixie-updates", f))
	}

	data = append(data, pdiffReadFile(tb, "trixie-updates", "Packages.xz"))

	// The buster-updates chain starts from an empty file.
	var cases []pdiffInteropCase

	for i := 1; i < len(data); i++ {
		if bytes.Equal(data[i-1], data[i]) {
			continue
		}

		patch, err := deb.GeneratePDiff(data[i-1], data[i])
		require.NoError(tb, err)

		cases = append(cases, pdiffInteropCase{
			ID:  fmt.Sprintf("real-trixie-%d", i),
			Old: data[i-1], New: data[i], Patch: patch,
		})
	}

	return cases
}

// TestPDiffInteropDump writes the cases and the matrix inputs to the directory
// named by PKGFORMAT_PDIFF_OUT; generate.sh runs it. Without the variable it is
// skipped.
func TestPDiffInteropDump(t *testing.T) {
	out := os.Getenv("PKGFORMAT_PDIFF_OUT")
	if out == "" {
		t.Skip("PKGFORMAT_PDIFF_OUT not set")
	}

	for _, d := range []string{"interop", "real", "matrix/pp"} {
		require.NoError(t, os.MkdirAll(filepath.Join(out, d), 0o755))
	}

	write := func(dir string, c pdiffInteropCase) {
		for ext, data := range map[string][]byte{".old": c.Old, ".new": c.New, ".patch": c.Patch} {
			require.NoError(t, os.WriteFile(filepath.Join(out, dir, c.ID+ext), data, 0o644))
		}
	}

	for _, c := range pdiffSyntheticCases(t) {
		write("interop", c)
	}

	for _, c := range pdiffRealCases(t) {
		write("real", c)
	}

	// The matrix: every real patch of the fixtures against every real base.
	for _, dir := range []string{"buster-updates", "trixie-updates"} {
		names, err := filepath.Glob(filepath.Join(pdiffTestdata, dir, "*.gz"))
		require.NoError(t, err)

		for _, n := range names {
			patch := pdiffReadFile(t, dir, filepath.Base(n))
			require.NoError(t, os.WriteFile(filepath.Join(out, "matrix/pp", dir+"-"+strings.TrimSuffix(filepath.Base(n), ".gz")+".ed"), patch, 0o644))
		}
	}

	for _, f := range pdiffRealBases(t) {
		require.NoError(t, os.WriteFile(filepath.Join(out, "matrix", "base-"+strings.TrimSuffix(f, ".xz")[len("base-"):]+".txt"), pdiffReadFile(t, "trixie-updates", f), 0o644))
	}

	require.NoError(t, os.WriteFile(filepath.Join(out, "matrix", "base-current.txt"), pdiffReadFile(t, "trixie-updates", "Packages.xz"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(out, "matrix", "base-buster-current.txt"), pdiffReadFile(t, "buster-updates", "Packages.xz"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(out, "matrix", "base-empty.txt"), nil, 0o644))
}

// pdiffExpected is one line of interop-expected.txt.
type pdiffExpected struct{ New, Patch, Rred, Ed string }

// pdiffLoadExpected reads interop-expected.txt: "id new patch rred ed" lines
// of SHA-256 digests; the tools' columns are the digests of what they made of
// old and patch.
func pdiffLoadExpected(tb testing.TB) map[string]pdiffExpected {
	tb.Helper()

	f, err := os.Open(filepath.Join(pdiffTestdata, "interop-expected.txt"))
	require.NoError(tb, err)

	defer f.Close()

	out := map[string]pdiffExpected{}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}

		require.Len(tb, fields, 5, sc.Text())

		out[fields[0]] = pdiffExpected{New: fields[1], Patch: fields[2], Rred: fields[3], Ed: fields[4]}
	}

	require.NoError(tb, sc.Err())

	return out
}

// pdiffCommittedCases reads the cases of testdata/repo-pdiff/interop.
func pdiffCommittedCases(tb testing.TB) []pdiffInteropCase {
	tb.Helper()

	names, err := filepath.Glob(filepath.Join(pdiffTestdata, "interop", "*.old"))
	require.NoError(tb, err)
	require.NotEmpty(tb, names)
	slices.Sort(names)

	var cases []pdiffInteropCase

	for _, n := range names {
		id := strings.TrimSuffix(filepath.Base(n), ".old")
		read := func(ext string) []byte {
			data, err := os.ReadFile(filepath.Join(pdiffTestdata, "interop", id+ext))
			require.NoError(tb, err)

			return data
		}

		cases = append(cases, pdiffInteropCase{
			ID: id, Old: read(".old"), New: read(".new"), Patch: read(".patch"),
			Handwritten: strings.HasPrefix(id, "sem-"),
		})
	}

	return cases
}

// TestPDiffInteropAgainstRredAndEd needs no tools: it checks this package
// against the digests rred and GNU ed were recorded to produce (see
// generate.sh) for the same inputs.
func TestPDiffInteropAgainstRredAndEd(t *testing.T) {
	expected := pdiffLoadExpected(t)

	cases := append(pdiffCommittedCases(t), pdiffRealCases(t)...)
	require.Greater(t, len(cases), 40)

	for _, c := range cases {
		t.Run(c.ID, func(t *testing.T) {
			want, ok := expected[c.ID]
			require.True(t, ok, "no recorded digests; run generate.sh")

			require.Equal(t, want.New, deb.PDiffSHA256(c.New), "recorded digest of the new file")
			require.Equal(t, want.Patch, deb.PDiffSHA256(c.Patch), "the patch changed: generate.sh records the patches this package makes")

			// The tools got the same inputs and produced the new file.
			require.Equal(t, want.New, want.Rred, "rred")
			require.Equal(t, want.New, want.Ed, "ed")

			// So does this package, with the patch it makes and with the recorded one.
			got, err := deb.ApplyPDiff(c.Old, c.Patch)
			require.NoError(t, err)
			require.Equal(t, string(c.New), string(got))

			if !c.Handwritten {
				patch, err := deb.GeneratePDiff(c.Old, c.New)
				require.NoError(t, err)
				require.Equal(t, string(c.Patch), string(patch))
			}
		})
	}
}

// pdiffLoadMatrix reads rred-matrix.txt: "patch base sha256|error" lines.
func pdiffLoadMatrix(tb testing.TB) [][3]string {
	tb.Helper()

	f, err := os.Open(filepath.Join(pdiffTestdata, "rred-matrix.txt"))
	require.NoError(tb, err)

	defer f.Close()

	var rows [][3]string

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}

		require.Len(tb, fields, 3, sc.Text())

		rows = append(rows, [3]string{fields[0], fields[1], fields[2]})
	}

	require.NoError(tb, sc.Err())

	return rows
}

// TestPDiffRredMatrix applies every real patch of the fixtures to every real
// base file and compares with what rred made of the same pair (recorded by
// generate.sh): the same bytes where rred succeeded, and no success where it
// failed. Wrong bases are included on purpose.
func TestPDiffRredMatrix(t *testing.T) {
	rows := pdiffLoadMatrix(t)
	require.Len(t, rows, 90, "10 patches on 9 base files")

	patches := map[string][]byte{}
	bases := map[string][]byte{"base-empty": nil, "base-current": pdiffReadFile(t, "trixie-updates", "Packages.xz"), "base-buster-current": pdiffReadFile(t, "buster-updates", "Packages.xz")}

	for _, f := range pdiffRealBases(t) {
		bases["base-"+strings.TrimSuffix(f, ".xz")[len("base-"):]] = pdiffReadFile(t, "trixie-updates", f)
	}

	for _, dir := range []string{"buster-updates", "trixie-updates"} {
		names, err := filepath.Glob(filepath.Join(pdiffTestdata, dir, "*.gz"))
		require.NoError(t, err)

		for _, n := range names {
			patches[dir+"-"+strings.TrimSuffix(filepath.Base(n), ".gz")] = pdiffReadFile(t, dir, filepath.Base(n))
		}
	}

	var same, stricter int

	for _, row := range rows {
		patch, base := patches[row[0]], bases[strings.TrimSuffix(row[1], ".txt")]
		require.NotNil(t, patch, row[0])

		got, err := deb.ApplyPDiff(base, patch)

		switch {
		case row[2] == "error":
			require.Error(t, err, "rred refused %s on %s", row[0], row[1])
		case err == nil:
			same++

			require.Equal(t, row[2], deb.PDiffSHA256(got), "%s on %s", row[0], row[1])
		default:
			// rred does not notice a command that addresses lines past the end
			// of a wrong base file and gives some output; this package reports
			// it. Nothing else may differ.
			stricter++

			require.ErrorIs(t, err, deb.ErrPDiffScript, "%s on %s", row[0], row[1])

			var pe *deb.PDiffError

			require.ErrorAs(t, err, &pe)
			require.Zero(t, pe.Line, "%s on %s: %v", row[0], row[1], err)
		}
	}

	require.Greater(t, same, 20)
	require.Positive(t, stricter)
}

// pdiffContainerImage finds an image with apt's rred that is already present:
// the tests never pull.
func pdiffContainerImage(tb testing.TB) string {
	tb.Helper()

	if _, err := exec.LookPath("podman"); err != nil {
		tb.Skip("podman not available")
	}

	candidates := []string{"localhost/debtools:bookworm", "docker.io/library/debian:bookworm", "docker.io/library/debian:bookworm-slim", "docker.io/library/debian:trixie-slim", "docker.io/library/debian:stable-slim"}
	if env := os.Getenv("PKGFORMAT_RRED_IMAGE"); env != "" {
		candidates = []string{env}
	}

	for _, img := range candidates {
		if exec.Command("podman", "image", "exists", img).Run() == nil {
			return img
		}
	}

	tb.Skip("no Debian image with apt present locally (set PKGFORMAT_RRED_IMAGE)")

	return ""
}

// TestPDiffRredLive applies this package's patches with the rred of a Debian
// container: the interop proof, run again. It skips without podman or a local
// image, and never pulls.
func TestPDiffRredLive(t *testing.T) {
	img := pdiffContainerImage(t)

	cases := append(pdiffCommittedCases(t), pdiffRealCases(t)...)

	dir := t.TempDir()

	var ids []string

	for _, c := range cases {
		ids = append(ids, c.ID)

		for ext, data := range map[string][]byte{".old": c.Old, ".patch": c.Patch} {
			require.NoError(t, os.WriteFile(filepath.Join(dir, c.ID+ext), data, 0o644))
		}
	}

	script, err := os.ReadFile(filepath.Join(pdiffTestdata, "container", "apply-rred.sh"))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "apply-rred.sh"), script, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ids"), []byte(strings.Join(ids, "\n")+"\n"), 0o644))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	out, err := exec.CommandContext(ctx, "podman", "run", "--rm", "--network=none", "-v", dir+":/w:ro", img, "sh", "/w/apply-rred.sh").CombinedOutput()
	require.NoError(t, err, string(out))

	got := map[string]string{}

	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 {
			got[f[0]] = f[1]
		}
	}

	for _, c := range cases {
		require.Equal(t, deb.PDiffSHA256(c.New), got[c.ID], "rred on %s", c.ID)
	}
}
