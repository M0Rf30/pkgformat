package source_test

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/deb/source"
)

func indexPackages(t *testing.T, opts *source.SourcesOptions) []source.SourceEntry {
	t.Helper()

	entries, err := source.IndexSources(filepath.Join("testdata", "packages"), opts)
	if err != nil {
		t.Fatal(err)
	}

	return entries
}

func writeIndex(t *testing.T, entries []source.SourceEntry, compression string) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := source.WriteSources(&buf, entries, compression); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func TestIndexSourcesMatchesAptFtparchive(t *testing.T) {
	// apt-ftparchive copies "Uploaders:  name" with its two spaces; the
	// parser reads one, as dpkg-source writes it.
	want := bytes.ReplaceAll(mustRead(t, filepath.Join("testdata", "sources", "Sources.apt-ftparchive")), []byte(":  "), []byte(": "))
	got := writeIndex(t, indexPackages(t, &source.SourcesOptions{Directory: "packages"}), "none")

	if !bytes.Equal(got, want) {
		t.Fatalf("differs from apt-ftparchive sources\n%s", firstDiff(got, want))
	}
}

// paragraphs parses a Sources index into field maps.
func paragraphs(t *testing.T, data []byte) []map[string]string {
	t.Helper()

	var out []map[string]string

	err := deb.ScanControl(bytes.NewReader(data), func(cf *deb.ControlFile) error {
		m := map[string]string{}
		for k, v := range cf.Fields {
			m[k] = v
		}

		out = append(out, m)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return out
}

func TestIndexSourcesMatchesDpkgScansources(t *testing.T) {
	// dpkg-scansources orders the fields differently and adds Priority and
	// Section; the content must agree stanza by stanza.
	want := paragraphs(t, mustRead(t, filepath.Join("testdata", "sources", "Sources.dpkg-scansources")))
	got := paragraphs(t, writeIndex(t, indexPackages(t, &source.SourcesOptions{
		Directory: "packages", Priority: "optional", Section: "unknown",
	}), "none"))

	if len(got) != len(want) || len(got) != len(fixtures) {
		t.Fatalf("%d stanzas, want %d", len(got), len(want))
	}

	for i := range want {
		// Whitespace inside values may differ (real maintainers write odd
		// spacing); compare normalised.
		if !reflect.DeepEqual(squash(got[i]), squash(want[i])) {
			t.Errorf("stanza %d (%s) differs\n got %v\nwant %v", i, want[i]["Package"], got[i], want[i])
		}
	}
}

// squash normalises the whitespace of the values and drops the SHA-512 list,
// which dpkg-scansources does not write.
func squash(m map[string]string) map[string]string {
	out := map[string]string{}

	for k, v := range m {
		if k == "Checksums-Sha512" {
			continue
		}

		out[k] = strings.Join(strings.Fields(v), " ")
	}

	return out
}

func TestIndexSourcesMatchesLiveTools(t *testing.T) {
	ftp, err := exec.LookPath("apt-ftparchive")
	if err != nil {
		t.Skip("apt-ftparchive not installed")
	}

	scan, err := exec.LookPath("dpkg-scansources")
	if err != nil {
		t.Skip("dpkg-scansources not installed")
	}

	conf := filepath.Join(t.TempDir(), "ftp.conf")
	_ = os.WriteFile(conf, []byte("APT::FTPArchive::Sources::Packages \"\";\n"), 0o600)

	run := func(bin string, args ...string) []byte {
		cmd := exec.Command(bin, args...)
		cmd.Dir = "testdata"

		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", bin, err)
		}

		return out
	}

	got := writeIndex(t, indexPackages(t, &source.SourcesOptions{Directory: "packages"}), "none")
	if want := bytes.ReplaceAll(run(ftp, "-c", conf, "sources", "packages"), []byte(":  "), []byte(": ")); !bytes.Equal(got, want) {
		t.Errorf("apt-ftparchive differs\n%s", firstDiff(got, want))
	}

	got = writeIndex(t, indexPackages(t, &source.SourcesOptions{Directory: "packages", Priority: "optional", Section: "unknown"}), "none")
	if !reflect.DeepEqual(squashAll(paragraphs(t, got)), squashAll(paragraphs(t, run(scan, "packages")))) {
		t.Error("dpkg-scansources differs")
	}
}

func squashAll(ms []map[string]string) []map[string]string {
	for i := range ms {
		ms[i] = squash(ms[i])
	}

	return ms
}

func TestSourcesCompressedRoundTrip(t *testing.T) {
	entries := indexPackages(t, &source.SourcesOptions{Directory: "packages"})

	plain := writeIndex(t, entries, "none")

	for _, c := range []string{"", "none", "gzip", "xz", "zstd"} {
		name, err := source.SourcesFileName(c)
		if err != nil {
			t.Fatal(err)
		}

		data := writeIndex(t, entries, c)

		got, err := source.ReadSources(bytes.NewReader(data), name)
		if err != nil {
			t.Fatalf("%q: %v", c, err)
		}

		if len(got) != len(entries) {
			t.Fatalf("%q: %d entries", c, len(got))
		}

		var again bytes.Buffer
		if err := source.WriteSources(&again, got, "none"); err != nil || !bytes.Equal(again.Bytes(), plain) {
			t.Errorf("%q: re-marshal differs (%v)", c, err)
		}
	}

	if _, err := source.SourcesFileName("bzip3"); !errors.Is(err, deb.ErrUnsupportedCompression) {
		t.Errorf("SourcesFileName: %v", err)
	}

	if err := source.WriteSources(&bytes.Buffer{}, entries, "bzip3"); err == nil {
		t.Error("unknown compression accepted")
	}

	// Our compressed output is readable by the host tools too.
	if gz, err := exec.LookPath("gzip"); err == nil {
		cmd := exec.Command(gz, "-dc")
		cmd.Stdin = bytes.NewReader(writeIndex(t, entries, "gzip"))

		if out, err := cmd.Output(); err != nil || !bytes.Equal(out, plain) {
			t.Errorf("gzip -dc: %v", err)
		}
	}

	// A real Debian Sources index, as apt-ftparchive wrote it, reads back.
	e := entries[0]
	if e.Directory == "" || e.Source == "" || e.Format == "" || len(e.Files) < 2 || e.Files[0].SHA512 == "" {
		t.Errorf("entry: %+v", e)
	}
}

func TestReadSourcesDefaultsAndErrors(t *testing.T) {
	// An index stanza may omit the Format; it is then 1.0.
	got, err := source.ReadSources(strings.NewReader("Package: foo\nVersion: 1.0\nDirectory: pool/foo\nPriority: extra\nSection: misc\n\nPackage: bar\nVersion: 2\n"), "Sources")
	if err != nil || len(got) != 2 || got[0].Format != source.Format10 || got[0].Directory != "pool/foo" ||
		got[0].Priority != "extra" || got[0].Section != "misc" {
		t.Fatalf("got %+v, %v", got, err)
	}

	if _, err := source.ReadSources(strings.NewReader("Version: 1\n"), "Sources"); !errors.Is(err, source.ErrInvalid) {
		t.Errorf("no package: %v", err)
	}

	if _, err := source.ReadSources(strings.NewReader("not gzip"), "Sources.gz"); err == nil {
		t.Error("bad gzip accepted")
	}

	// A decompression bomb stops at the index limit.
	var bomb bytes.Buffer

	zw := gzip.NewWriter(&bomb)
	chunk := []byte(strings.Repeat("X-Pad: x\n", 1<<16))

	for range int(deb.MaxIndexBytes)/len(chunk) + 2 {
		_, _ = zw.Write(chunk)
	}

	_ = zw.Close()

	if _, err := source.ReadSources(&bomb, "Sources.gz"); err == nil {
		t.Error("bomb accepted")
	}
}

func TestIndexSourcesErrors(t *testing.T) {
	dir := t.TempDir()
	d, p := fixtureDSC(t, "sl")

	// The .dsc without its files.
	if err := os.WriteFile(filepath.Join(dir, filepath.Base(p)), mustRead(t, p), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := source.IndexSources(dir, nil); err == nil {
		t.Error("missing files accepted")
	}

	// Files whose content differs from the digests.
	for _, f := range d.Files {
		if err := os.WriteFile(filepath.Join(dir, f.Name), []byte("changed"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := source.IndexSources(dir, nil); !errors.Is(err, source.ErrChecksum) {
		t.Errorf("changed files: %v", err)
	}

	// A broken .dsc.
	bad := t.TempDir()
	_ = os.WriteFile(filepath.Join(bad, "x.dsc"), []byte("junk\n"), 0o600)

	if _, err := source.IndexSources(bad, nil); err == nil {
		t.Error("broken .dsc accepted")
	}

	if _, err := source.IndexSources(filepath.Join(dir, "absent"), nil); err == nil {
		t.Error("absent root accepted")
	}
}

func TestIndexSourcesOrdersByVersion(t *testing.T) {
	root := t.TempDir()

	for _, v := range []string{"1.10-1", "1.9-1", "1:0.1-1"} {
		dsc := "Format: 3.0 (native)\nSource: foo\nVersion: " + v + "\n"
		if err := os.WriteFile(filepath.Join(root, "foo_"+strings.ReplaceAll(v, ":", "_")+".dsc"), []byte(dsc), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	entries, err := source.IndexSources(root, &source.SourcesOptions{Directory: "pool"})
	if err != nil {
		t.Fatal(err)
	}

	var versions []string
	for _, e := range entries {
		versions = append(versions, e.Version)
	}

	if !reflect.DeepEqual(versions, []string{"1.9-1", "1.10-1", "1:0.1-1"}) || entries[0].Directory != "pool" {
		t.Errorf("order %v dir %q", versions, entries[0].Directory)
	}
}

func firstDiff(got, want []byte) string {
	g, w := strings.Split(string(got), "\n"), strings.Split(string(want), "\n")
	for i := 0; i < len(g) && i < len(w); i++ {
		if g[i] != w[i] {
			return fmt.Sprintf("line %d\n got: %s\nwant: %s", i+1, g[i], w[i])
		}
	}

	return fmt.Sprintf("lengths %d vs %d lines", len(g), len(w))
}
