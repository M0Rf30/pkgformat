package repodata

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const zckDNFImage = "localhost/s3tools:latest"

// A repository whose repomd.xml, written by Repomd.Marshal, lists the zchunk
// files and a gzip primary that is not served: dnf refreshes its metadata from
// the zchunk files alone, and when the repository changes it asks only for the
// ranges of the chunks that changed.
func TestZchunkDnfMakecache(t *testing.T) {
	if testing.Short() {
		t.Skip("runs a container")
	}

	podman := needTool(t, "podman")

	if exec.Command(podman, "image", "exists", zckDNFImage).Run() != nil {
		t.Skipf("image %s is not available", zckDNFImage)
	}

	oldPrimary, _ := readZchunk(t, zfixture(t, "createrepo-primary-old.xml.zck"), ZchunkReadOptions{})
	docs := map[string][]byte{
		"primary": goldenXML(t, "primary"), "filelists": goldenXML(t, "filelists"), "other": goldenXML(t, "other"),
	}

	type repo map[string][]byte // path under the root -> content

	var primaryName string

	build := func(revision string, primary []byte) repo {
		files := repo{}
		m := Repomd{Revision: revision}

		for _, typ := range []string{"primary", "filelists", "other"} {
			doc := docs[typ]
			if typ == "primary" {
				doc = primary
			}

			cm, err := CompressMetadataStream(Zchunk, func(w io.Writer) error { _, err := w.Write(doc); return err })
			if err != nil {
				t.Fatal(err)
			}

			name := cm.SHA256 + "-" + typ + ".xml.zck"
			files["/repodata/"+name] = cm.Data

			if typ == "primary" {
				primaryName = "/repodata/" + name
			}

			m.Data = append(m.Data, cm.Entry(typ+"_zck", name, 1700000000))
		}

		// The gzip primary of a repository that has both: not served here,
		// so a client that wants it fails.
		m.Data = append(m.Data, RepomdData{
			Type: "primary", Location: "repodata/primary.xml.gz", Checksum: strings.Repeat("0", 64), ChecksumType: "sha256",
			OpenChecksum: strings.Repeat("0", 64), OpenChecksumType: "sha256", Timestamp: 1700000000, Size: 1, OpenSize: 1,
		})

		xml, err := m.Marshal()
		if err != nil {
			t.Fatal(err)
		}

		files["/repodata/repomd.xml"] = xml

		return files
	}

	var (
		mu      sync.Mutex
		current repo
		log     []string
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		body, ok := current[r.URL.Path]
		log = append(log, fmt.Sprintf("%s %s %s", r.Method, r.URL.Path, r.Header.Get("Range")))
		mu.Unlock()

		if !ok {
			http.NotFound(w, r)

			return
		}

		http.ServeContent(w, r, r.URL.Path, timeZero, bytes.NewReader(body))
	}))
	defer srv.Close()

	cache := t.TempDir()

	makecache := func(files repo) (string, []string) {
		mu.Lock()
		current, log = files, nil
		mu.Unlock()

		cmd := exec.Command(podman, "run", "--rm", "--network=host", "-v", cache+":/cache", zckDNFImage,
			"dnf5", "--repofrompath=zck,"+srv.URL, "--repo=zck", "--setopt=zck.gpgcheck=0",
			"--setopt=cachedir=/cache", "--setopt=zck.zchunk=1", "makecache", "--refresh")

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("dnf5 makecache: %v\n%s", err, out)
		}

		mu.Lock()
		defer mu.Unlock()

		return string(out), slices.Clone(log)
	}

	oldRepo := build("1", oldPrimary)
	oldH, err := ReadZchunkHeader(bytes.NewReader(oldRepo[primaryName]), ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	oldName := primaryName

	_, first := makecache(oldRepo)

	// A first fetch: the header, then the rest of the file.
	wantFirst := []string{
		"GET /repodata/repomd.xml ",
		fmt.Sprintf("GET %s bytes=0-%d", oldName, oldH.Size-1),
		fmt.Sprintf("GET %s bytes=%d-%d", oldName, oldH.Size, oldH.FileSize()-1),
	}
	if !slices.Equal(first, wantFirst) {
		t.Errorf("first refresh requested\n%s\nwant\n%s", strings.Join(first, "\n"), strings.Join(wantFirst, "\n"))
	}

	newRepo := build("2", docs["primary"])
	newH, err := ReadZchunkHeader(bytes.NewReader(newRepo[primaryName]), ZchunkReadOptions{})
	if err != nil {
		t.Fatal(err)
	}

	_, second := makecache(newRepo)

	// The second: the new header, then exactly the ranges of the chunks the
	// cached file does not have, in one multi-range request.
	var ranges []string
	for _, r := range ByteRanges(newH.MissingChunks(oldH)) {
		ranges = append(ranges, strings.TrimPrefix(r.String(), "bytes="))
	}

	wantSecond := []string{
		"GET /repodata/repomd.xml ",
		fmt.Sprintf("GET %s bytes=0-%d", primaryName, newH.Size-1),
		fmt.Sprintf("GET %s bytes=%s", primaryName, strings.Join(ranges, ",")),
	}
	if !slices.Equal(second, wantSecond) {
		t.Errorf("second refresh requested\n%s\nwant\n%s", strings.Join(second, "\n"), strings.Join(wantSecond, "\n"))
	}
}

var timeZero = time.Unix(1700000000, 0)
