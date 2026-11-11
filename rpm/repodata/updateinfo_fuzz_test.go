package repodata

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func addUpdateinfoSeeds(f *testing.F) {
	f.Helper()

	for _, name := range []string{"model.xml", "dnf.xml", "real/rocky9-baseos.xml", "real/rocky8-appstream.xml", "real/fedora43-updates.xml"} {
		data, err := os.ReadFile(filepath.Join(updateinfoTestdata, filepath.FromSlash(name)))
		if err != nil {
			f.Fatal(err)
		}

		f.Add(data)
	}

	f.Add([]byte(`<updates><update><id>a</id><issued date="x"/>`))
	f.Add([]byte(`<update><id>a</id><pkglist><collection><module version="1"/><package><sum type="md5">1</sum></package></collection></pkglist></update>`))
	f.Add([]byte(""))
}

func FuzzReadUpdateinfo(f *testing.F) {
	addUpdateinfoSeeds(f)

	f.Fuzz(func(_ *testing.T, data []byte) {
		lim := UpdateinfoLimits{MaxUpdates: 50, MaxReferences: 50, MaxCollections: 50, MaxPackages: 50, MaxFieldBytes: 1 << 12}
		_ = ReadUpdateinfo(bytes.NewReader(data), lim, func(*Advisory) error { return nil })
	})
}

// FuzzUpdateinfoRoundTrip writes an advisory built from arbitrary text and
// reads it back: whatever the writer accepts, the reader must return, and
// writing that again must change nothing.
func FuzzUpdateinfoRoundTrip(f *testing.F) {
	f.Add("id", "title", "desc & <x>", "name", "sha256", "abc", int64(1700000000), uint64(7), true)
	f.Add(" spaced ", "a\r\nb\tc", "\x01\xff", "\n", "", "", int64(0), uint64(0), false)

	f.Fuzz(func(t *testing.T, id, title, desc, name, sumType, sum string, ts int64, version uint64, flag bool) {
		// Dates outside the years 0000-9999 have no four digit representation.
		date := time.Unix(((ts%253402300800)+253402300800)%253402300800, 0).UTC()

		a := Advisory{
			ID: id, Title: title, Description: desc, Issued: date, Updated: date, RebootSuggested: flag,
			References: []AdvisoryReference{{Href: title, ID: id, Title: desc, Type: name}},
			Collections: []AdvisoryCollection{{
				Short: name, Name: title,
				Module: &AdvisoryModule{Name: name, Stream: title, Version: version, Context: desc, Arch: id},
				Packages: []AdvisoryPackage{{
					Name: name, Version: title, Release: desc, Epoch: id, Arch: name, Src: desc, Filename: name,
					Sum: AdvisorySum{Type: sumType, Value: sum}, RebootSuggested: flag, ReloginSuggested: flag,
				}},
			}},
		}

		var first bytes.Buffer
		if err := WriteUpdateinfoXML(&first, []Advisory{a}); err != nil {
			return
		}

		read := func(doc []byte) []Advisory {
			var out []Advisory

			err := ReadUpdateinfo(bytes.NewReader(doc), UpdateinfoLimits{}, func(a *Advisory) error {
				out = append(out, *a)

				return nil
			})
			if err != nil {
				t.Fatalf("the reader rejects what the writer wrote: %v\n%s", err, doc)
			}

			return out
		}

		got := read(first.Bytes())
		if len(got) != 1 && strings.TrimSpace(id) != "" {
			t.Fatalf("read %d advisories from\n%s", len(got), first.Bytes())
		}

		if len(got) == 0 {
			return
		}

		var second bytes.Buffer
		if err := WriteUpdateinfoXML(&second, got); err != nil {
			t.Fatalf("the writer rejects what the reader returned: %v", err)
		}

		if again := read(second.Bytes()); !reflect.DeepEqual(again, got) {
			t.Fatalf("a second round trip changed the advisory:\n%+v\n%+v", again, got)
		}
	})
}

func FuzzMergeUpdateinfo(f *testing.F) {
	f.Add([]byte(`<updates><update><id>a</id><updated date="2026-01-01 00:00:00"/></update></updates>`),
		[]byte(`<updates><update><id>a</id><updated date="2026-02-01 00:00:00"/></update><update><id>b</id></update></updates>`))

	f.Fuzz(func(_ *testing.T, a, b []byte) {
		lim := UpdateinfoLimits{MaxUpdates: 50, MaxReferences: 50, MaxCollections: 50, MaxPackages: 50, MaxFieldBytes: 1 << 12}
		_, _ = MergeUpdateinfo(io.Discard, []io.Reader{bytes.NewReader(a), bytes.NewReader(b)}, lim)
	})
}
