package repodata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

// The fixtures of testdata/deltainfo come from createrepo_c --deltas: see
// generate.sh there.
var fixtureDeltaInfo = &DeltaInfo{NewPackages: []DeltaPackage{
	{
		Name: "delta-demo", Epoch: 1, Version: "1.2", Release: "1", Arch: "noarch",
		Deltas: []Delta{
			{
				Epoch: 1, Version: "1.1", Release: "1",
				Filename: "drpms/delta-demo-1.1-1_1.2-1.noarch.drpm",
				Sequence: "delta-demo-1:1.1-1-e8dc98a6e3721d68b676ab99649b547010",
				Size:     2748,
				Checksum: DeltaChecksum{"sha256", "0f69b2a8d5e307a3409a46f9443532ea8b2e7d05c70b0bbdb89133c05215aa3c"},
			},
			{
				Epoch: 1, Version: "1.0", Release: "1",
				Filename: "drpms/delta-demo-1.0-1_1.2-1.noarch.drpm",
				Sequence: "delta-demo-1:1.0-1-5c8c029b2051935dfc1d202f7360934c10",
				Size:     2765,
				Checksum: DeltaChecksum{"sha256", "f379f8fc3c9669184ec299f3f6f51e0c60698e8fe9a2d04025ae49fc2cc5c205"},
			},
		},
	},
	{
		Name: "delta-lib", Epoch: 0, Version: "2.4", Release: "1.el9", Arch: "x86_64",
		Deltas: []Delta{{
			Epoch: 0, Version: "2.3", Release: "4.el9",
			Filename: "drpms/delta-lib-2.3-4.el9_2.4-1.el9.x86_64.drpm",
			Sequence: "delta-lib-2.3-4.el9-5451756ba9a11a48209a26aa15f0a20f10",
			Size:     2825,
			Checksum: DeltaChecksum{"sha256", "cca9cee155a39d6637b08417edd08beabe76c3a172aafcf380ed8dee764429d0"},
		}},
	},
}}

func deltaFixturePath(parts ...string) string {
	return filepath.Join(append([]string{"testdata", "deltainfo"}, parts...)...)
}

func deltaFixtureBytes(t testing.TB, parts ...string) []byte {
	t.Helper()

	data, err := os.ReadFile(deltaFixturePath(parts...))
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestParseDeltaInfoFixture(t *testing.T) {
	got, err := ParseDeltaInfo(bytes.NewReader(deltaFixtureBytes(t, "prestodelta.xml")), DeltaInfoLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(got, fixtureDeltaInfo) {
		t.Fatalf("got %+v, want %+v", got, fixtureDeltaInfo)
	}
}

// TestDeltaInfoRoundTrip writes what createrepo_c --deltas wrote back: the
// document is the same byte for byte.
func TestDeltaInfoRoundTrip(t *testing.T) {
	want := deltaFixtureBytes(t, "prestodelta.xml")

	var got bytes.Buffer
	if err := WriteDeltaInfoXML(&got, fixtureDeltaInfo); err != nil {
		t.Fatal(err)
	}

	if got.String() != string(want) {
		t.Fatalf("differs at byte %d:\n%s", firstStringDiff(got.String(), string(want)), context(got.String(), string(want)))
	}

	// The compressed document in the repository holds the same text.
	rc, err := OpenMetadata(io.NopCloser(bytes.NewReader(deltaFixtureBytes(t, "repo", "repodata", "prestodelta.xml.gz"))), "prestodelta.xml.gz", 0)
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = rc.Close() }()

	var plain bytes.Buffer
	if _, err := plain.ReadFrom(rc); err != nil {
		t.Fatal(err)
	}

	if plain.String() != string(want) {
		t.Fatal("repo/repodata/prestodelta.xml.gz differs from prestodelta.xml")
	}
}

// TestDeltaInfoMatchesFiles checks the document against the files it
// describes, which are the independent evidence: every delta rpm has the size
// and digest listed, its header is the one of the new package, the old
// version is that of an older package of the repository, and the sequence
// starts with the NEVR of that package.
func TestDeltaInfoMatchesFiles(t *testing.T) {
	identity := func(p *rpm.Package) string {
		return fmt.Sprintf("%s %d %s %s %s", p.Name, p.Epoch, p.Version, p.Release, p.Arch)
	}

	readRPM := func(path string) *rpm.Package {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}

		defer func() { _ = f.Close() }()

		p, err := rpm.ReadPackage(f)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}

		return p
	}

	newer := map[string]bool{}
	older := map[string]bool{}

	for dir, set := range map[string]map[string]bool{"repo": newer, "old": older} {
		files, err := filepath.Glob(deltaFixturePath(dir, "*.rpm"))
		if err != nil || len(files) == 0 {
			t.Fatalf("no packages in %s: %v", dir, err)
		}

		for _, f := range files {
			set[identity(readRPM(f))] = true
		}
	}

	for _, np := range fixtureDeltaInfo.NewPackages {
		id := fmt.Sprintf("%s %d %s %s %s", np.Name, np.Epoch, np.Version, np.Release, np.Arch)
		if !newer[id] {
			t.Fatalf("%s is not a package of the repository", id)
		}

		for _, d := range np.Deltas {
			oldID := fmt.Sprintf("%s %d %s %s %s", np.Name, d.Epoch, d.Version, d.Release, np.Arch)
			if !older[oldID] {
				t.Fatalf("%s: old version %q is not one of the old packages", d.Filename, oldID)
			}

			data := deltaFixtureBytes(t, "repo", d.Filename)
			sum := sha256.Sum256(data)

			if int64(len(data)) != d.Size || hex.EncodeToString(sum[:]) != d.Checksum.Value || d.Checksum.Type != "sha256" {
				t.Fatalf("%s: size %d and sha256 %x, document says %d and %s", d.Filename, len(data), sum, d.Size, d.Checksum.Value)
			}

			// A delta rpm is an rpm whose header is the new package's.
			if got := identity(readRPM(deltaFixturePath("repo", d.Filename))); got != id {
				t.Fatalf("%s: header of %q, want %q", d.Filename, got, id)
			}

			nevr := np.Name + "-" + d.Version + "-" + d.Release
			if d.Epoch != 0 {
				nevr = fmt.Sprintf("%s-%d:%s-%s", np.Name, d.Epoch, d.Version, d.Release)
			}

			digest, ok := strings.CutPrefix(d.Sequence, nevr+"-")
			if !ok || len(digest) < 32 {
				t.Fatalf("sequence %q does not follow %q", d.Sequence, nevr)
			}

			if _, err := hex.DecodeString(digest); err != nil {
				t.Fatalf("sequence %q: digest is not hex: %v", d.Sequence, err)
			}
		}
	}
}

func TestWriteDeltaInfoXMLEmpty(t *testing.T) {
	for _, info := range []*DeltaInfo{{}, {NewPackages: []DeltaPackage{{Name: "n", Version: "1", Release: "1", Arch: "a"}}}} {
		var buf bytes.Buffer
		if err := WriteDeltaInfoXML(&buf, info); err != nil {
			t.Fatal(err)
		}

		// createrepo_c writes the same for a repository without deltas; a
		// package with no delta is not listed.
		if want := "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<prestodelta>\n</prestodelta>"; buf.String() != want {
			t.Fatalf("got %q, want %q", buf.String(), want)
		}
	}
}

func TestWriteDeltaInfoXMLEscapes(t *testing.T) {
	info := &DeltaInfo{NewPackages: []DeltaPackage{{
		Name: `a&b`, Epoch: 3, Version: "1<2", Release: `"r"`, Arch: "x",
		Deltas: []Delta{{
			Epoch: 1, Version: "0'", Release: "1>",
			Filename: "drpms/a&b.drpm", Sequence: "s&", Size: 7, Checksum: DeltaChecksum{"sha256", "ab"},
		}},
	}}}

	var buf bytes.Buffer
	if err := WriteDeltaInfoXML(&buf, info); err != nil {
		t.Fatal(err)
	}

	want := `<?xml version="1.0" encoding="UTF-8"?>
<prestodelta>
  <newpackage name="a&amp;b" epoch="3" version="1&lt;2" release="&quot;r&quot;" arch="x">
    <delta oldepoch="1" oldversion="0'" oldrelease="1&gt;">
      <filename>drpms/a&amp;b.drpm</filename>
      <sequence>s&amp;</sequence>
      <size>7</size>
      <checksum type="sha256">ab</checksum>
    </delta>
  </newpackage>
</prestodelta>`
	if buf.String() != want {
		t.Fatalf("got:\n%s\nwant:\n%s", buf.String(), want)
	}

	got, err := ParseDeltaInfo(&buf, DeltaInfoLimits{})
	if err != nil || !reflect.DeepEqual(got, info) {
		t.Fatalf("read back %+v (%v), wrote %+v", got, err, info)
	}
}

func TestWriteDeltaInfoXMLInvalid(t *testing.T) {
	good := func() DeltaPackage {
		return DeltaPackage{Name: "n", Version: "1", Release: "1", Arch: "a", Deltas: []Delta{{
			Version: "0", Release: "1", Filename: "f", Sequence: "s", Size: 1, Checksum: DeltaChecksum{"sha256", "ab"},
		}}}
	}

	for name, mutate := range map[string]func(*DeltaPackage){
		"name":      func(p *DeltaPackage) { p.Name = "" },
		"version":   func(p *DeltaPackage) { p.Version = "" },
		"release":   func(p *DeltaPackage) { p.Release = "" },
		"arch":      func(p *DeltaPackage) { p.Arch = "" },
		"oldver":    func(p *DeltaPackage) { p.Deltas[0].Version = "" },
		"oldrel":    func(p *DeltaPackage) { p.Deltas[0].Release = "" },
		"filename":  func(p *DeltaPackage) { p.Deltas[0].Filename = "" },
		"sequence":  func(p *DeltaPackage) { p.Deltas[0].Sequence = "" },
		"sumtype":   func(p *DeltaPackage) { p.Deltas[0].Checksum.Type = "" },
		"sumvalue":  func(p *DeltaPackage) { p.Deltas[0].Checksum.Value = "" },
		"negsize":   func(p *DeltaPackage) { p.Deltas[0].Size = -1 },
		"emptyname": func(p *DeltaPackage) { p.Name = ""; p.Deltas = nil },
	} {
		t.Run(name, func(t *testing.T) {
			p := good()
			mutate(&p)

			var buf bytes.Buffer

			err := WriteDeltaInfoXML(&buf, &DeltaInfo{NewPackages: []DeltaPackage{p}})
			if !errors.Is(err, ErrMalformedDeltaInfo) {
				t.Fatalf("err = %v, want ErrMalformedDeltaInfo", err)
			}
		})
	}
}

func TestDeltaInfoWriterStreams(t *testing.T) {
	var buf bytes.Buffer

	w := NewDeltaInfoWriter(&buf)
	for i := range fixtureDeltaInfo.NewPackages {
		if err := w.Package(&fixtureDeltaInfo.NewPackages[i]); err != nil {
			t.Fatal(err)
		}
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf.Bytes(), deltaFixtureBytes(t, "prestodelta.xml")) {
		t.Fatal("the streamed document differs from the fixture")
	}

	if err := WriteDeltaInfoXML(failingWriter{}, fixtureDeltaInfo); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("write error = %v", err)
	}
}

const deltaDoc = `<?xml version="1.0" encoding="UTF-8"?>
<prestodelta>
  <newpackage name="n" epoch="2" version="3" release="4" arch="a">
    <delta oldepoch="1" oldversion="1" oldrelease="2">
      <filename> drpms/n.drpm </filename>
      <sequence>n-1:1-2-ab</sequence>
      <size>10</size>
      <checksum type="sha256">cd</checksum>
    </delta>
  </newpackage>
</prestodelta>`

func TestReadDeltaInfo(t *testing.T) {
	t.Run("lenient about what is not defined", func(t *testing.T) {
		doc := strings.NewReplacer(
			`<prestodelta>`, `<prestodelta><unknown><newpackage/></unknown>`,
			`<size>`, `<extra>text<b>x</b></extra><size>`,
			`epoch="2"`, `epoch="2" other="x"`,
			`</newpackage>`, `<comment/></newpackage>`,
		).Replace(deltaDoc)

		got, err := ParseDeltaInfo(strings.NewReader(doc), DeltaInfoLimits{})
		if err != nil {
			t.Fatal(err)
		}

		want := &DeltaInfo{NewPackages: []DeltaPackage{{
			Name: "n", Epoch: 2, Version: "3", Release: "4", Arch: "a",
			Deltas: []Delta{{
				Epoch: 1, Version: "1", Release: "2", Filename: "drpms/n.drpm", Sequence: "n-1:1-2-ab",
				Size: 10, Checksum: DeltaChecksum{"sha256", "cd"},
			}},
		}}}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	})

	t.Run("missing epochs are zero", func(t *testing.T) {
		doc := strings.NewReplacer(` epoch="2"`, "", ` oldepoch="1"`, "").Replace(deltaDoc)

		got, err := ParseDeltaInfo(strings.NewReader(doc), DeltaInfoLimits{})
		if err != nil || got.NewPackages[0].Epoch != 0 || got.NewPackages[0].Deltas[0].Epoch != 0 {
			t.Fatalf("got %+v (%v)", got, err)
		}
	})

	t.Run("callback error stops the read", func(t *testing.T) {
		boom := errors.New("boom")

		err := ReadDeltaInfo(strings.NewReader(deltaDoc), DeltaInfoLimits{}, func(*DeltaPackage) error { return boom })
		if !errors.Is(err, boom) || errors.Is(err, ErrMalformedDeltaInfo) {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestReadDeltaInfoMalformed(t *testing.T) {
	for name, doc := range map[string]string{
		"empty":          "",
		"text":           "not xml",
		"wrong root":     `<updates></updates>`,
		"truncated":      deltaDoc[:len(deltaDoc)/2],
		"unclosed root":  strings.TrimSuffix(deltaDoc, "</prestodelta>"),
		"no name":        strings.Replace(deltaDoc, ` name="n"`, "", 1),
		"no arch":        strings.Replace(deltaDoc, ` arch="a"`, "", 1),
		"no version":     strings.Replace(deltaDoc, ` version="3"`, "", 1),
		"no release":     strings.Replace(deltaDoc, ` release="4"`, "", 1),
		"bad epoch":      strings.Replace(deltaDoc, `epoch="2"`, `epoch="two"`, 1),
		"negative epoch": strings.Replace(deltaDoc, `epoch="2"`, `epoch="-2"`, 1),
		"big epoch":      strings.Replace(deltaDoc, `epoch="2"`, `epoch="4294967296"`, 1),
		"bad old epoch":  strings.Replace(deltaDoc, `oldepoch="1"`, `oldepoch="x"`, 1),
		"no old version": strings.Replace(deltaDoc, ` oldversion="1"`, "", 1),
		"no old release": strings.Replace(deltaDoc, ` oldrelease="2"`, "", 1),
		"no filename":    strings.Replace(deltaDoc, `<filename> drpms/n.drpm </filename>`, "", 1),
		"no sequence":    strings.Replace(deltaDoc, `<sequence>n-1:1-2-ab</sequence>`, "", 1),
		"no size":        strings.Replace(deltaDoc, `<size>10</size>`, "", 1),
		"bad size":       strings.Replace(deltaDoc, `<size>10</size>`, `<size>ten</size>`, 1),
		"negative size":  strings.Replace(deltaDoc, `<size>10</size>`, `<size>-1</size>`, 1),
		"no checksum":    strings.Replace(deltaDoc, `<checksum type="sha256">cd</checksum>`, "", 1),
		"no sum type":    strings.Replace(deltaDoc, ` type="sha256"`, "", 1),
		"empty sum":      strings.Replace(deltaDoc, `>cd<`, `><`, 1),
		"mismatched tag": strings.Replace(deltaDoc, `</filename>`, `</size>`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseDeltaInfo(strings.NewReader(doc), DeltaInfoLimits{})
			if !errors.Is(err, ErrMalformedDeltaInfo) {
				t.Fatalf("err = %v, want ErrMalformedDeltaInfo", err)
			}

			if errors.Is(err, ErrTooLarge) {
				t.Fatalf("err = %v is also ErrTooLarge", err)
			}
		})
	}
}

func TestReadDeltaInfoLimits(t *testing.T) {
	delta := func(n int) string {
		return strings.Repeat(`<delta oldepoch="1" oldversion="1" oldrelease="2"><filename>f</filename><sequence>s</sequence>`+
			`<size>1</size><checksum type="sha256">c</checksum></delta>`, n)
	}
	pkg := func(n int) string {
		return strings.Repeat(`<newpackage name="n" epoch="0" version="1" release="1" arch="a">`+delta(1)+`</newpackage>`, n)
	}
	doc := func(body string) string { return "<prestodelta>" + body + "</prestodelta>" }

	long := strings.Repeat("x", 200)

	for _, tc := range []struct {
		name string
		doc  string
		lim  DeltaInfoLimits
	}{
		{"packages", doc(pkg(3)), DeltaInfoLimits{MaxPackages: 2}},
		{"deltas", doc(`<newpackage name="n" version="1" release="1" arch="a">` + delta(3) + `</newpackage>`), DeltaInfoLimits{MaxDeltas: 2}},
		{"package attribute", doc(`<newpackage name="` + long + `" version="1" release="1" arch="a">` + delta(1) + `</newpackage>`), DeltaInfoLimits{MaxFieldBytes: 100}},
		{"delta attribute", doc(`<newpackage name="n" version="1" release="1" arch="a"><delta oldversion="` + long + `" oldrelease="1"></delta></newpackage>`), DeltaInfoLimits{MaxFieldBytes: 100}},
		{"filename", doc(`<newpackage name="n" version="1" release="1" arch="a"><delta oldversion="1" oldrelease="1"><filename>` + long + `</filename></delta></newpackage>`), DeltaInfoLimits{MaxFieldBytes: 100}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseDeltaInfo(strings.NewReader(tc.doc), tc.lim)
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("err = %v, want ErrTooLarge", err)
			}

			if errors.Is(err, ErrMalformedDeltaInfo) {
				t.Fatalf("err = %v is also ErrMalformedDeltaInfo", err)
			}
		})
	}

	// The same documents within the limits are fine.
	if _, err := ParseDeltaInfo(strings.NewReader(doc(pkg(2))), DeltaInfoLimits{MaxPackages: 2, MaxDeltas: 1}); err != nil {
		t.Fatal(err)
	}
}

func FuzzReadDeltaInfo(f *testing.F) {
	f.Add(deltaFixtureBytes(f, "prestodelta.xml"))
	f.Add([]byte(deltaDoc))
	f.Add([]byte("<prestodelta><newpackage name=\"n\" version=\"1\" release=\"1\" arch=\"a\"></newpackage></prestodelta>"))
	f.Add([]byte("<prestodelta><newpackage"))
	f.Add([]byte(""))

	f.Fuzz(func(t *testing.T, data []byte) {
		lim := DeltaInfoLimits{MaxPackages: 32, MaxDeltas: 32, MaxFieldBytes: 1 << 10}

		first, err := ParseDeltaInfo(bytes.NewReader(data), lim)
		if err != nil {
			if !errors.Is(err, ErrMalformedDeltaInfo) && !errors.Is(err, ErrTooLarge) {
				t.Fatalf("untyped error %v", err)
			}

			return
		}

		// What was read is writable (packages without deltas are not
		// listed) and reads back the same.
		var listed []DeltaPackage

		for _, p := range first.NewPackages {
			if len(p.Deltas) > 0 {
				listed = append(listed, p)
			}
		}

		var doc bytes.Buffer
		if err := WriteDeltaInfoXML(&doc, &DeltaInfo{NewPackages: listed}); err != nil {
			t.Fatal(err)
		}

		second, err := ParseDeltaInfo(&doc, lim)
		if err != nil {
			t.Fatalf("rereading the written document: %v", err)
		}

		if len(listed) == 0 && len(second.NewPackages) == 0 {
			return
		}

		if !reflect.DeepEqual(second.NewPackages, listed) {
			t.Fatalf("wrote %+v, read back %+v", listed, second.NewPackages)
		}
	})
}
