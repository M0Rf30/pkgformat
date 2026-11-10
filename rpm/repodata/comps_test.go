package repodata

import (
	"bytes"
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testComps() *Comps {
	return &Comps{
		Groups: []CompsGroup{{
			ID: "build-tools", Name: "Build & Tools", Description: "Compilers <and> friends", Default: true, UserVisible: true,
			Packages: []CompsPackage{
				{Name: "gcc", Type: CompsMandatory},
				{Name: "make"},
				{Name: "gdb", Type: CompsOptional},
				{Name: "gcc-plugin", Type: CompsConditional, Condition: "gcc"},
			},
		}},
		Categories: []CompsCategory{{ID: "development", Name: "Development", GroupIDs: []string{"build-tools"}}},
	}
}

func TestWriteCompsXML(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCompsXML(&buf, testComps()); err != nil {
		t.Fatal(err)
	}

	if err := ValidateCompsXML(buf.Bytes()); err != nil {
		t.Fatalf("written comps.xml is not well-formed: %v\n%s", err, buf.String())
	}

	var doc struct {
		Groups []struct {
			ID       string `xml:"id"`
			Name     string `xml:"name"`
			Default  bool   `xml:"default"`
			Packages []struct {
				Type     string `xml:"type,attr"`
				Requires string `xml:"requires,attr"`
				Name     string `xml:",chardata"`
			} `xml:"packagelist>packagereq"`
		} `xml:"group"`
		Categories []struct {
			ID      string   `xml:"id"`
			GroupID []string `xml:"grouplist>groupid"`
		} `xml:"category"`
	}

	if err := xml.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}

	g := doc.Groups[0]
	if g.ID != "build-tools" || g.Name != "Build & Tools" || !g.Default || len(g.Packages) != 4 {
		t.Fatalf("group = %+v", g)
	}

	if g.Packages[1].Type != "default" || g.Packages[3].Requires != "gcc" || g.Packages[3].Name != "gcc-plugin" {
		t.Errorf("packages = %+v", g.Packages)
	}

	if len(doc.Categories) != 1 || doc.Categories[0].GroupID[0] != "build-tools" {
		t.Errorf("categories = %+v", doc.Categories)
	}
}

func TestValidateCompsXML(t *testing.T) {
	if err := ValidateCompsXML([]byte("<comps></comps>")); err != nil {
		t.Error(err)
	}

	if err := ValidateCompsXML([]byte("<comps><group>")); err == nil {
		t.Error("a truncated comps.xml must be invalid")
	}

	if err := ValidateCompsXML([]byte("<a></b>")); err == nil || errors.Is(err, ErrTooLarge) {
		t.Errorf("mismatched tags: %v", err)
	}
}

// TestCompsAcceptedByCreaterepo has createrepo_c ingest the written comps.xml
// as the group file of a repository.
func TestCompsAcceptedByCreaterepo(t *testing.T) {
	if _, err := exec.LookPath("createrepo_c"); err != nil {
		t.Skip("createrepo_c is not installed")
	}

	dir := t.TempDir()

	data, err := os.ReadFile(filepath.Join("..", "testdata", "hello.rpm"))
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(dir, "hello.rpm"), data, 0o600); err != nil {
		t.Fatal(err)
	}

	var comps bytes.Buffer
	if err := WriteCompsXML(&comps, testComps()); err != nil {
		t.Fatal(err)
	}

	compsPath := filepath.Join(dir, "comps.xml")
	if err := os.WriteFile(compsPath, comps.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command("createrepo_c", "--no-database", "-g", compsPath, dir).CombinedOutput()
	if err != nil {
		t.Fatalf("createrepo_c: %v\n%s", err, out)
	}

	if strings.Contains(string(out), "arning") {
		t.Errorf("createrepo_c warns about comps.xml:\n%s", out)
	}

	repomd, err := os.Open(filepath.Join(dir, "repodata", "repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = repomd.Close() }()

	m, err := ParseRepomd(repomd)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok := m.Find("group"); !ok {
		t.Error("repomd.xml has no group entry")
	}
}
