package repodata

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm"
)

const compsContainerImage = "localhost/s3tools:latest"

// readRepomdFile parses the repomd.xml of the repository in dir.
func readRepomdFile(t *testing.T, dir string) *Repomd {
	t.Helper()

	f, err := os.Open(filepath.Join(dir, "repodata", "repomd.xml"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = f.Close() }()

	m, err := ParseRepomd(f)
	if err != nil {
		t.Fatal(err)
	}

	return m
}

// openRepoMetadata reads a metadata file of a repository whatever its
// compression.
func openRepoMetadata(t *testing.T, dir, location string) []byte {
	t.Helper()

	f, err := os.Open(filepath.Join(dir, filepath.FromSlash(location)))
	if err != nil {
		t.Fatal(err)
	}

	rc, err := OpenMetadata(f, path.Base(location), 1<<28)
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

// TestCompsFixturesAcceptedByCreaterepo has createrepo_c ingest each fixture,
// as it is and as this package writes it, with and without --compatibility, and checks that the comps file it
// publishes holds the same model.
func TestCompsFixturesAcceptedByCreaterepo(t *testing.T) {
	if _, err := exec.LookPath("createrepo_c"); err != nil {
		t.Skip("createrepo_c is not installed")
	}

	hello, err := os.ReadFile(filepath.Join("..", "testdata", "hello.rpm"))
	if err != nil {
		t.Fatal(err)
	}

	for _, fx := range compsFixtures {
		orig := readCompsFixture(t, fx.name)
		model := parseComps(t, orig)

		for _, variant := range []struct {
			name string
			data []byte
		}{{"original", orig}, {"written", writeComps(t, model)}} {
			for _, compat := range []bool{false, true} {
				name := fx.name + "/" + variant.name
				if compat {
					name += "/compatibility"
				}

				t.Run(name, func(t *testing.T) {
					dir := t.TempDir()
					compsPath := filepath.Join(dir, "comps.xml")

					if err := os.WriteFile(filepath.Join(dir, "hello.rpm"), hello, 0o600); err != nil {
						t.Fatal(err)
					}

					if err := os.WriteFile(compsPath, variant.data, 0o600); err != nil {
						t.Fatal(err)
					}

					args := []string{"--no-database", "-g", compsPath}
					if compat {
						args = append(args, "--compatibility")
					}

					out, err := exec.Command("createrepo_c", append(args, dir)...).CombinedOutput()
					if err != nil {
						t.Fatalf("createrepo_c: %v\n%s", err, out)
					}

					if strings.Contains(string(out), "arning") {
						t.Errorf("createrepo_c warns:\n%s", out)
					}

					m := readRepomdFile(t, dir)

					group, ok := m.Find("group")
					if !ok {
						t.Fatal("repomd.xml has no group entry")
					}

					// --compatibility keeps the comps file as it is; otherwise it is compressed.
					if plain := strings.HasSuffix(group.Location, ".xml"); plain != compat {
						t.Errorf("group location %s: uncompressed = %v, want %v", group.Location, plain, compat)
					}

					if got := parseComps(t, openRepoMetadata(t, dir, group.Location)); !reflect.DeepEqual(got, model) {
						t.Error("the comps file createrepo_c published holds another model")
					}
				})
			}
		}
	}
}

// compsRepository writes a repository to dir with this package alone: hello.rpm,
// the three documents and the given comps documents, registered as the
// "group" (plain) and "group_gz" (gzip) records of repomd.xml.
func compsRepository(t *testing.T, dir string, comps []byte, plain, gz bool) {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("..", "testdata", "hello.rpm"))
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

	rpmPath := filepath.Join(dir, filepath.FromSlash(PackageLocation(pkg)))
	repodata := filepath.Join(dir, "repodata")

	for _, d := range []string{filepath.Dir(rpmPath), repodata} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(rpmPath, data, 0o600); err != nil {
		t.Fatal(err)
	}

	const ts = 1700000000

	var entries []RepomdData

	for typ, write := range map[string]func(io.Writer, []rpm.Package) error{
		"primary": WritePrimaryXML, "filelists": WriteFilelistsXML, "other": WriteOtherXML,
	} {
		cm, err := CompressMetadataStream(Gzip, func(w io.Writer) error { return write(w, []rpm.Package{*pkg}) })
		if err != nil {
			t.Fatal(err)
		}

		name := cm.SHA256 + "-" + typ + ".xml.gz"
		if err := os.WriteFile(filepath.Join(repodata, name), cm.Data, 0o600); err != nil {
			t.Fatal(err)
		}

		entries = append(entries, cm.Entry(typ, name, ts))
	}

	if plain {
		sum := sha256.Sum256(comps)
		name := hex.EncodeToString(sum[:]) + "-comps.xml"

		if err := os.WriteFile(filepath.Join(repodata, name), comps, 0o600); err != nil {
			t.Fatal(err)
		}

		entries = append(entries, RepomdData{
			Type: "group", Location: "repodata/" + name,
			Checksum: hex.EncodeToString(sum[:]), ChecksumType: "sha256", Timestamp: ts, Size: int64(len(comps)),
		})
	}

	if gz {
		cm, err := CompressMetadataStream(Gzip, func(w io.Writer) error { _, err := w.Write(comps); return err })
		if err != nil {
			t.Fatal(err)
		}

		name := cm.SHA256 + "-comps.xml.gz"
		if err := os.WriteFile(filepath.Join(repodata, name), cm.Data, 0o600); err != nil {
			t.Fatal(err)
		}

		entries = append(entries, cm.Entry("group_gz", name, ts))
	}

	repomd, err := GenerateRepomdXML("1700000000", entries)
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(repodata, "repomd.xml"), repomd, 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireCompsContainer(t *testing.T) {
	t.Helper()

	if _, err := exec.LookPath("podman"); err != nil {
		t.Skip("podman is not installed")
	}

	if err := exec.Command("podman", "image", "exists", compsContainerImage).Run(); err != nil {
		t.Skipf("the image %s is not available", compsContainerImage)
	}
}

// runInCompsContainer runs script in the image with each of dirs mounted
// read-only at /<base name of the dir> and returns what it printed.
func runInCompsContainer(t *testing.T, script string, mounts map[string]string) string {
	t.Helper()

	scriptPath := filepath.Join(t.TempDir(), "check.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}

	args := []string{"run", "--rm", "-v", scriptPath + ":/check.sh:ro,z"}
	for host, guest := range mounts {
		args = append(args, "-v", host+":"+guest+":ro,z")
	}

	args = append(args, compsContainerImage, "sh", "/check.sh")

	out, err := exec.Command("podman", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("podman: %v\n%s", err, out)
	}

	return string(out)
}

// TestCompsReadByDnf has dnf read the comps of a repository this package wrote
// as a plain "group" record, as a "group_gz" record and as both, and list and
// describe the groups and the environments in it.
func TestCompsReadByDnf(t *testing.T) {
	requireCompsContainer(t)

	comps := writeComps(t, parseComps(t, readCompsFixture(t, "features.xml")))
	root := t.TempDir()

	variants := []struct {
		name      string
		plain, gz bool
	}{{"group", true, false}, {"group_gz", false, true}, {"both", true, true}}

	for _, v := range variants {
		compsRepository(t, filepath.Join(root, v.name), comps, v.plain, v.gz)
	}

	script := `
set -e
for repo in group group_gz both; do
  cat > /tmp/$repo.repo <<EOT
[$repo]
name=$repo
baseurl=file:///repos/$repo
gpgcheck=0
enabled=1
EOT
done
D="dnf --setopt=reposdir=/tmp --setopt=cachedir=/tmp/cache --setopt=install_weak_deps=0"
for repo in group group_gz both; do
  echo "##### $repo: group list"
  $D --repo=$repo group list --hidden
  echo "##### $repo: group info"
  $D --repo=$repo group info multilib-tools
  echo "##### $repo: environment list"
  $D --repo=$repo environment list
  echo "##### $repo: environment info"
  $D --repo=$repo environment info tools-environment
done
`

	out := runInCompsContainer(t, script, map[string]string{root: "/repos"})

	for _, repo := range []string{"group", "group_gz", "both"} {
		section := func(name string) string {
			_, after, ok := strings.Cut(out, "##### "+repo+": "+name+"\n")
			if !ok {
				t.Fatalf("%s: no %s section in:\n%s", repo, name, out)
			}

			before, _, _ := strings.Cut(after, "#####")

			return before
		}

		for name, wants := range map[string][]string{
			"group list":       {"multilib-tools", "Multilib Tools", "empty-group", "Groups: 2"},
			"group info":       {"Multilib Tools", "Tools for a system that runs two ABIs & more", "glibc-devel", "make", "strace"},
			"environment list": {"tools-environment", "Tools Environment"},
			"environment info": {"Tools Environment", "multilib-tools"},
		} {
			got := section(name)
			for _, want := range wants {
				if !strings.Contains(got, want) {
					t.Errorf("%s: %s lacks %q:\n%s", repo, name, want, got)
				}
			}
		}
	}
}

// TestCompsLocalizedByDnf4 has dnf 4 show the German names of a group and of a
// language group. It reads the translations through libcomps; it needs a
// compiled de_DE locale, which the host's localedef provides.
func TestCompsLocalizedByDnf4(t *testing.T) {
	requireCompsContainer(t)

	if _, err := exec.LookPath("localedef"); err != nil {
		t.Skip("localedef is not installed")
	}

	locales := t.TempDir()
	if out, err := exec.Command("localedef", "--no-archive", "-i", "de_DE", "-f", "UTF-8", filepath.Join(locales, "de_DE.UTF-8")).CombinedOutput(); err != nil {
		t.Skipf("localedef: %v\n%s", err, out)
	}

	repo := t.TempDir()
	compsRepository(t, repo, writeComps(t, parseComps(t, readCompsFixture(t, "features.xml"))), false, true)

	script := `
cat > /tmp/t.repo <<EOT
[t]
name=t
baseurl=file:///repo
gpgcheck=0
enabled=1
EOT
export LOCPATH=/locales LANG=de_DE.UTF-8 LC_ALL=de_DE.UTF-8
dnf4 --setopt=reposdir=/tmp --setopt=cachedir=/tmp/cache group info multilib-tools 2>&1
dnf4 --setopt=reposdir=/tmp --setopt=cachedir=/tmp/cache group list hidden 2>&1
`

	out := runInCompsContainer(t, script, map[string]string{repo: "/repo", locales: "/locales"})

	for _, want := range []string{"Group: Multilib-Werkzeuge", "Werkzeuge für ein System mit zwei ABIs", "Language: de", "Werkzeugumgebung"} {
		if !strings.Contains(out, want) {
			t.Errorf("dnf4 output lacks %q:\n%s", want, out)
		}
	}
}

// libcompsCheck loads each document with libcomps, prints what it understood
// of it and, for the second argument onwards, whether libcomps writes the
// same document as for the first.
const libcompsCheck = `
import sys
import libcomps

def load(path):
    c = libcomps.Comps()
    if c.fromxml_f(path) < 0 and c.get_last_errors():
        sys.exit("%s: %s" % (path, c.get_last_errors()))
    return c

def langs(d):
    return sorted(dict(d).items())[:4]

def dump(c):
    for g in c.groups:
        print("group", g.id, repr(g.name), langs(g.name_by_lang), repr(g.desc), langs(g.desc_by_lang),
              g.default, g.uservisible, g.biarchonly, g.display_order, g.lang_only,
              [(p.name, p.type, p.requires, p.basearchonly) for p in g.packages])
    for g in c.categories:
        print("category", g.id, repr(g.name), langs(g.name_by_lang), g.display_order, [(i.name, i.default) for i in g.group_ids])
    for g in c.environments:
        print("environment", g.id, repr(g.name), langs(g.name_by_lang), g.display_order,
              [(i.name, i.default) for i in g.group_ids], [(i.name, i.default) for i in g.option_ids])
    print("langpacks", sorted(dict(c.langpacks).items()))
    x = c.xml_str()
    print("blacklist", x.count("<package name="), "whiteout", x.count("<ignoredep "))

orig, written = load(sys.argv[1]), load(sys.argv[2])
dump(written)
print("SAME-MODEL" if orig.xml_str() == written.xml_str() else "DIFFERENT-MODEL")
`

// TestCompsReadByLibcomps has libcomps, the library dnf reads comps with, load
// the fixtures and the documents this package writes from them: it must see
// the same model in both, including the translations and every flag.
func TestCompsReadByLibcomps(t *testing.T) {
	requireCompsContainer(t)

	dir := t.TempDir()
	script := "set -e\n"

	for _, fx := range compsFixtures {
		written := writeComps(t, parseComps(t, readCompsFixture(t, fx.name)))
		if err := os.WriteFile(filepath.Join(dir, "written-"+fx.name), written, 0o600); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dir, fx.name), readCompsFixture(t, fx.name), 0o600); err != nil {
			t.Fatal(err)
		}

		script += "echo '##### " + fx.name + "'\npython3 /dir/check.py /dir/" + fx.name + " /dir/written-" + fx.name + "\n"
	}

	if err := os.WriteFile(filepath.Join(dir, "check.py"), []byte(libcompsCheck), 0o600); err != nil {
		t.Fatal(err)
	}

	out := runInCompsContainer(t, script, map[string]string{dir: "/dir"})

	sections := strings.Split(out, "##### ")[1:]
	if len(sections) != len(compsFixtures) {
		t.Fatalf("%d sections in:\n%s", len(sections), out)
	}

	for i, fx := range compsFixtures {
		sec := sections[i]
		if !strings.Contains(sec, "SAME-MODEL") {
			t.Errorf("%s: libcomps sees another model in the written file:\n%s", fx.name, sec)
		}
	}

	// The translations and the flags only a few documents carry (the package
	// types are libcomps' numbers: default 0, optional 1, conditional 2, mandatory 3).
	if features := sections[2]; !strings.Contains(features, "('fr', 'Outils multi-architecture')") ||
		!strings.Contains(features, "True False True 7 de") ||
		!strings.Contains(features, "('glibc-devel', 3, None, True)") ||
		!strings.Contains(features, "('glibc-static', 2, 'glibc-devel', None)") ||
		!strings.Contains(features, "('empty-group', True)") {
		t.Errorf("features.xml as libcomps reads it:\n%s", features)
	}
}
