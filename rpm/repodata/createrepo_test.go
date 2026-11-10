package repodata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

var groundTruthFixtures = []string{"files.rpm", "hello.rpm", "weakdeps.rpm", "sizes-v4.rpm"}

// readDocument opens the compressed metadata file of the given repomd type.
func readDocument(t *testing.T, repo string, m *Repomd, typ string) []byte {
	t.Helper()

	entry, ok := m.Find(typ)
	if !ok {
		t.Fatalf("repomd.xml has no %s entry", typ)
	}

	f, err := os.Open(filepath.Join(repo, filepath.FromSlash(entry.Location)))
	if err != nil {
		t.Fatal(err)
	}

	rc, err := OpenMetadata(f, entry.Location, 0)
	if err != nil {
		_ = f.Close()
		t.Fatal(err)
	}

	defer func() { _ = rc.Close() }()

	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

// TestMatchesCreaterepo checks the metadata written for real packages against
// the one createrepo_c produces for the same files: the packages read back from
// both primary.xml documents are equal, and so are the filelists.xml elements.
func TestMatchesCreaterepo(t *testing.T) {
	if _, err := exec.LookPath("createrepo_c"); err != nil {
		t.Skip("createrepo_c is not installed")
	}

	repo := t.TempDir()

	var pkgs []rpm.Package

	for _, name := range groundTruthFixtures {
		data, err := os.ReadFile(filepath.Join("..", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}

		path := filepath.Join(repo, name)
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}

		pkg, err := rpm.ReadPackage(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		sum := sha256.Sum256(data)
		pkg.SHA256 = hex.EncodeToString(sum[:])
		pkg.PackageSize = int64(len(data))
		pkg.FileTime = info.ModTime().Unix()
		pkgs = append(pkgs, *pkg)
	}

	if out, err := exec.Command("createrepo_c", "--no-database", repo).CombinedOutput(); err != nil {
		t.Fatalf("createrepo_c: %v\n%s", err, out)
	}

	rf, err := os.Open(filepath.Join(repo, "repodata", "repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = rf.Close() }()

	repomd, err := ParseRepomd(rf)
	if err != nil {
		t.Fatal(err)
	}

	want := readDocument(t, repo, repomd, "primary")

	var got bytes.Buffer
	if err := WritePrimaryXML(&got, pkgs); err != nil {
		t.Fatal(err)
	}

	wantPkgs := readPrimaryAll(t, want)
	gotPkgs := readPrimaryAll(t, got.Bytes())

	if len(wantPkgs) != len(pkgs) || len(gotPkgs) != len(pkgs) {
		t.Fatalf("packages: createrepo_c %d, written %d, want %d", len(wantPkgs), len(gotPkgs), len(pkgs))
	}

	for name, w := range wantPkgs {
		g, ok := gotPkgs[name]
		if !ok {
			t.Fatalf("%s is missing from the written primary.xml", name)
		}

		// The location differs by layout, not by content.
		w.Location, g.Location = "", ""

		if !reflect.DeepEqual(w, g) {
			t.Errorf("%s: primary entry differs\ncreaterepo_c: %+v\nwritten:      %+v", name, w, g)
		}
	}

	for typ, write := range map[string]func(io.Writer, []rpm.Package) error{
		"filelists": WriteFilelistsXML,
		"other":     WriteOtherXML,
	} {
		var buf bytes.Buffer
		if err := write(&buf, pkgs); err != nil {
			t.Fatal(err)
		}

		wantEl := elementsByName(t, readDocument(t, repo, repomd, typ))
		gotEl := elementsByName(t, buf.Bytes())

		if !reflect.DeepEqual(wantEl, gotEl) {
			t.Errorf("%s.xml differs\ncreaterepo_c: %v\nwritten:      %v", typ, wantEl, gotEl)
		}
	}
}

func readPrimaryAll(t *testing.T, doc []byte) map[string]PrimaryPackage {
	t.Helper()

	out := make(map[string]PrimaryPackage)

	err := ReadPrimary(bytes.NewReader(doc), PrimaryLimits{}, func(p *PrimaryPackage) error {
		out[p.Name] = *p

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// elementsByName maps the package name to its serialized <package> element.
func elementsByName(t *testing.T, doc []byte) map[string]string {
	t.Helper()

	out := make(map[string]string)

	err := ScanPackages(bytes.NewReader(doc), true, func(info PackageInfo, el []byte) error {
		out[info.Name] = normalizeElement(string(el))

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// normalizeElement removes what carries no information: the indentation, which
// follows the layout of the document, and an explicit epoch of 0, which
// createrepo_c always writes and this package omits.
func normalizeElement(el string) string {
	el = strings.ReplaceAll(el, "&#xA;", "\n")
	el = whitespaceBetweenTags.ReplaceAllString(el, "><")

	return strings.ReplaceAll(strings.TrimSpace(el), ` epoch="0"`, "")
}

var whitespaceBetweenTags = regexp.MustCompile(`>\s+<`)

// TestRepositoryIsReadByCreaterepoTools writes a complete repository and has
// createrepo_c's own tools read it: sqliterepo_c parses repomd.xml and the
// three documents, whatever their compression, and fails on a malformed one.
func TestRepositoryIsReadByCreaterepoTools(t *testing.T) {
	if _, err := exec.LookPath("sqliterepo_c"); err != nil {
		t.Skip("sqliterepo_c is not installed")
	}

	var pkgs []rpm.Package

	for _, name := range groundTruthFixtures {
		data, err := os.ReadFile(filepath.Join("..", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}

		pkg, err := rpm.ReadPackage(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}

		sum := sha256.Sum256(data)
		pkg.SHA256 = hex.EncodeToString(sum[:])
		pkg.PackageSize = int64(len(data))
		pkgs = append(pkgs, *pkg)
	}

	for _, c := range []Compression{Gzip, Zstd, XZ} {
		t.Run(c.String(), func(t *testing.T) {
			dir := t.TempDir()
			repodata := filepath.Join(dir, "repodata")

			if err := os.Mkdir(repodata, 0o755); err != nil {
				t.Fatal(err)
			}

			var entries []RepomdData

			for typ, write := range map[string]func(io.Writer, []rpm.Package) error{
				"primary": WritePrimaryXML, "filelists": WriteFilelistsXML, "other": WriteOtherXML,
			} {
				cm, err := CompressMetadataStream(c, func(w io.Writer) error { return write(w, pkgs) })
				if err != nil {
					t.Fatal(err)
				}

				name := cm.SHA256 + "-" + typ + ".xml" + c.Extension()
				if err := os.WriteFile(filepath.Join(repodata, name), cm.Data, 0o600); err != nil {
					t.Fatal(err)
				}

				entries = append(entries, RepomdData{
					Type: typ, Location: "repodata/" + name,
					Checksum: cm.SHA256, ChecksumType: "sha256",
					OpenChecksum: cm.OpenSHA256, OpenChecksumType: "sha256",
					Timestamp: 1700000000, Size: cm.Size, OpenSize: cm.OpenSize,
				})
			}

			repomd, err := GenerateRepomdXML("1700000000", entries)
			if err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(filepath.Join(repodata, "repomd.xml"), repomd, 0o600); err != nil {
				t.Fatal(err)
			}

			if out, err := exec.Command("sqliterepo_c", "--force", dir).CombinedOutput(); err != nil {
				t.Fatalf("sqliterepo_c: %v\n%s", err, out)
			}

			matches, _ := filepath.Glob(filepath.Join(repodata, "*-primary.sqlite*"))
			if len(matches) == 0 {
				t.Error("sqliterepo_c did not produce a primary database")
			}
		})
	}
}
