package dnf_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/dnf"
	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// Serve a two-package repository, refresh it, resolve a dependency and
// download the result.
func Example() {
	files := map[string][]byte{}

	pkgs := []rpm.Package{
		{Name: "hello", Version: "1.0", Release: "1", Arch: "x86_64", Requires: []rpm.Dependency{{Name: "libgreet"}}},
		{Name: "libgreet", Version: "2.1", Release: "1", Arch: "x86_64"},
	}

	for i := range pkgs {
		body := []byte("rpm file of " + pkgs[i].Name)
		sum := sha256.Sum256(body)
		pkgs[i].SHA256 = hex.EncodeToString(sum[:])
		pkgs[i].PackageSize = int64(len(body))
		files["/"+repodata.PackageLocation(&pkgs[i])] = body
	}

	primary, err := repodata.CompressMetadataStream(repodata.Gzip, func(w io.Writer) error {
		return repodata.WritePrimaryXML(w, pkgs)
	})
	if err != nil {
		log.Fatal(err)
	}

	location := "repodata/" + primary.SHA256 + "-primary.xml.gz"
	files["/"+location] = primary.Data

	files["/repodata/repomd.xml"], err = repodata.GenerateRepomdXML("1", []repodata.RepomdData{{
		Type: "primary", Location: location, Checksum: primary.SHA256, ChecksumType: "sha256",
		Timestamp: 1, Size: primary.Size,
	}})
	if err != nil {
		log.Fatal(err)
	}

	// The repository lives under the $basearch its URL expands to.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if body, ok := files[strings.TrimPrefix(r.URL.Path, "/x86_64")]; ok {
			_, _ = w.Write(body)

			return
		}

		http.NotFound(w, r)
	}))
	defer srv.Close()

	// The client is configured with directories, not host paths.
	dir, err := os.MkdirTemp("", "dnf-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dir)

	repoDir := filepath.Join(dir, "repos")
	if err := os.Mkdir(repoDir, 0o755); err != nil {
		log.Fatal(err)
	}

	repoFile := fmt.Sprintf("[example]\nname=Example\nbaseurl=%s/$basearch\nenabled=1\n", srv.URL)
	if err := os.WriteFile(filepath.Join(repoDir, "example.repo"), []byte(repoFile), 0o644); err != nil {
		log.Fatal(err)
	}

	client := dnf.New(dnf.Options{
		RepoDir:  repoDir,
		CacheDir: filepath.Join(dir, "cache"),
		Arch:     "x86_64",
	})

	ctx := context.Background()

	if err := client.Update(ctx); err != nil {
		log.Fatal(err)
	}

	index, err := client.Load(ctx)
	if err != nil {
		log.Fatal(err)
	}

	res, err := index.Resolve(ctx, []string{"hello"})
	if err != nil {
		log.Fatal(err)
	}

	paths, err := client.DownloadAll(ctx, res.Packages, filepath.Join(dir, "rpms"))
	if err != nil {
		log.Fatal(err)
	}

	for i, p := range res.Packages {
		body, _ := os.ReadFile(paths[i])
		fmt.Println(p.Name, p.EVR(), filepath.Base(paths[i]), bytes.HasPrefix(body, []byte("rpm file of")))
	}

	fmt.Println("unresolved:", res.Unresolved)
	// Output:
	// libgreet 0:2.1-1 libgreet-2.1-1.x86_64.rpm true
	// hello 0:1.0-1 hello-1.0-1.x86_64.rpm true
	// unresolved: []
}
