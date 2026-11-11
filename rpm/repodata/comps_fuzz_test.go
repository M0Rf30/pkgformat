package repodata

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// FuzzReadComps: whatever the input, the reader returns an error or a model;
// a model writes out and reads back as itself, and the visitor sees the same
// groups as the model.
func FuzzReadComps(f *testing.F) {
	var buf bytes.Buffer

	_ = WriteCompsXML(&buf, testComps())

	f.Add(buf.Bytes())
	f.Add([]byte(readDoc))
	f.Add([]byte("<comps>"))
	f.Add([]byte("<comps><group><id>g</id><packagelist><packagereq type=\"conditional\" requires=\"x\">p</packagereq></packagelist></group></comps>"))
	f.Add([]byte("<comps><langpacks><match name=\"a\" install=\"b\"/></langpacks><blacklist><package name=\"p\"/></blacklist></comps>"))

	f.Fuzz(func(t *testing.T, data []byte) {
		lim := CompsLimits{MaxBytes: 1 << 20, MaxEntries: 1 << 10, MaxListItems: 1 << 10, MaxFieldBytes: 1 << 10}

		c, err := ParseComps(bytes.NewReader(data), lim)
		if err != nil {
			return
		}

		var out bytes.Buffer
		if err := WriteCompsXML(&out, c); err != nil {
			t.Fatalf("a parsed model does not write: %v\n%+v", err, c)
		}

		again, err := ParseComps(bytes.NewReader(out.Bytes()), CompsLimits{})
		if err != nil {
			t.Fatalf("what was written does not read: %v\n%s", err, out.Bytes())
		}

		if !reflect.DeepEqual(again, c) {
			t.Fatalf("round trip differs:\n got %+v\nwant %+v\n%s", again, c, out.Bytes())
		}

		var again2 bytes.Buffer
		if err := WriteCompsXML(&again2, again); err != nil || !bytes.Equal(again2.Bytes(), out.Bytes()) {
			t.Fatalf("the writer is not stable: %v", err)
		}
	})
}

// FuzzWriteComps: a model built from arbitrary strings is rejected with
// ErrInvalidComps or writes a document that reads back to the same model.
func FuzzWriteComps(f *testing.F) {
	f.Add("g", "Name <&>", "desc", "de", "pkg", "default", "a,b", "req", 3, true)
	f.Add("", "", "", "", "", "", "", "", 0, false)
	f.Add("g\x00", "\xff", "\r\n", "x\ty", "p\"q", "optional", " ", "r", -1, true)

	f.Fuzz(func(t *testing.T, id, name, desc, lang, pkg, typ, arch, req string, order int, flag bool) {
		c := &Comps{
			Groups: []CompsGroup{{
				ID: id, Name: name, Description: desc, Default: flag, UserVisible: !flag, BiarchOnly: flag, DisplayOrder: order,
				NameLocalized: map[string]string{lang: name}, DescriptionLocalized: map[string]string{lang: desc},
				LangOnly: lang, Arch: strings.Split(arch, ","),
				Packages: []CompsPackage{{Name: pkg, Type: typ, Requires: req, BaseArchOnly: flag, Arch: strings.Split(arch, ",")}},
			}},
			Categories:   []CompsCategory{{ID: id, Name: name, Groups: []CompsGroupRef{{ID: pkg, Default: flag}}}},
			Environments: []CompsEnvironment{{ID: id, Name: name, Options: []CompsGroupRef{{ID: pkg}}}},
			Langpacks:    []CompsLangpack{{Name: pkg, Install: name}},
			Blacklist:    []CompsBlacklisted{{Name: pkg, Arch: arch}},
			Whiteout:     []CompsIgnoredDep{{Requires: req, Package: pkg}},
		}

		var buf bytes.Buffer

		err := WriteCompsXML(&buf, c)
		if err != nil {
			if !errors.Is(err, ErrInvalidComps) {
				t.Fatalf("unexpected error: %v", err)
			}

			if buf.Len() != 0 {
				t.Fatal("an invalid model wrote output")
			}

			return
		}

		first, err := ParseComps(bytes.NewReader(buf.Bytes()), CompsLimits{})
		if err != nil {
			t.Fatalf("what was written does not read: %v\n%s", err, buf.Bytes())
		}

		var out bytes.Buffer
		if err := WriteCompsXML(&out, first); err != nil || !bytes.Equal(out.Bytes(), buf.Bytes()) {
			t.Fatalf("read and write again changes the document: %v\n%s\n---\n%s", err, buf.Bytes(), out.Bytes())
		}
	})
}
