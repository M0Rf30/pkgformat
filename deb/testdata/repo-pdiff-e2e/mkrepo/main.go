// Command mkrepo publishes and serves a small Debian repository whose
// Packages.diff is maintained by deb.PDiffIndexBuilder. It exists for the
// apt end-to-end proof of this directory (see README.md).
//
//	mkrepo publish -repo DIR -step N [-merge]   publish version N of the repository
//	mkrepo serve   -repo DIR -addr ADDR -log F  serve it over HTTP, logging requests
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ulikunitz/xz"

	"github.com/M0Rf30/pkgformat/deb"
)

const (
	dist     = "e2e"
	indexDir = "dists/" + dist + "/main/binary-amd64"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	var err error

	switch os.Args[1] {
	case "publish":
		err = publish(os.Args[2:])
	case "serve":
		err = serve(os.Args[2:])
	default:
		usage()
	}

	if err != nil {
		log.Fatal(err)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: mkrepo publish|serve ...")
	os.Exit(2)
}

// packagesFor renders the Packages file of repository version step: a growing
// package list in which every step bumps the revision of about one package in
// eleven, the way a real archive changes between two publications.
func packagesFor(step int) []byte {
	var b bytes.Buffer

	for i := range 400 + step {
		rev := 0

		for t := 1; t <= step; t++ {
			if (t+i)%11 == 0 {
				rev = t
			}
		}

		fmt.Fprintf(&b, "Package: pkg%03d\nVersion: 1.0-%d\nArchitecture: amd64\nMaintainer: Test <test@example.org>\n"+
			"Installed-Size: %d\nFilename: pool/main/p/pkg%03d/pkg%03d_1.0-%d_amd64.deb\nSize: %d\n"+
			"Description: test package number %d\n\n", i, rev, 100+i, i, i, rev, 2000+i*10+rev, i)
	}

	return b.Bytes()
}

func xzBytes(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	w, err := xz.NewWriter(&buf)
	if err != nil {
		return nil, err
	}

	if _, err := w.Write(data); err != nil {
		return nil, err
	}

	if err := w.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func publish(args []string) error {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	repo := fs.String("repo", "", "repository directory")
	step := fs.Int("step", 1, "version of the repository to publish")
	merge := fs.Bool("merge", false, "publish merged patches")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *repo == "" {
		return fmt.Errorf("-repo is required")
	}

	dir, err := deb.NewPDiffDirFS(filepath.Join(*repo, indexDir))
	if err != nil {
		return err
	}

	defer dir.Close()

	builder, err := deb.NewPDiffIndexBuilder(dir, deb.PDiffBuilderOptions{Merge: *merge})
	if err != nil {
		return err
	}

	packages := packagesFor(*step)
	now := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(*step) * time.Hour)

	// The builder reads the Packages file about to be replaced, so it goes first.
	res, err := builder.Update(packages, now)
	if err != nil {
		return err
	}

	if res.Changed {
		fmt.Println("patch", res.Patch.Name)
	}

	packagesXZ, err := xzBytes(packages)
	if err != nil {
		return err
	}

	if err := dir.WriteFile("Packages", packages); err != nil {
		return err
	}

	if err := dir.WriteFile("Packages.xz", packagesXZ); err != nil {
		return err
	}

	rel := &deb.Release{
		Origin: "pkgformat e2e", Suite: dist, Codename: dist,
		Date:          now,
		Architectures: []string{"amd64"}, Components: []string{"main"},
	}

	rel.AddFile(deb.HashBytes("main/binary-amd64/Packages", packages))
	rel.AddFile(deb.HashBytes("main/binary-amd64/Packages.xz", packagesXZ))

	if res.IndexData != nil {
		rel.AddFile(deb.HashBytes("main/binary-amd64/Packages.diff/Index", res.IndexData))
	}

	releaseDir, err := deb.NewPDiffDirFS(filepath.Join(*repo, "dists", dist))
	if err != nil {
		return err
	}

	defer releaseDir.Close()

	if err := releaseDir.WriteFile("Release", rel.Marshal()); err != nil {
		return err
	}

	// apt asks for Release with If-Modified-Since. Publications made within one
	// second of each other would look unchanged, so each one's file time is the
	// publication time: later for every step.
	return os.Chtimes(filepath.Join(*repo, "dists", dist, "Release"), now, now)
}

type logWriter struct {
	mu sync.Mutex
	f  *os.File
}

func (l *logWriter) log(r *http.Request, status int) {
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Fprintf(l.f, "%s %d %s\n", r.Method, status, r.URL.Path)
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	repo := fs.String("repo", "", "repository directory")
	addr := fs.String("addr", "127.0.0.1:0", "listen address")
	logFile := fs.String("log", "", "request log file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}

	lw := &logWriter{f: f}
	files := http.FileServer(http.Dir(*repo))

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}

	fmt.Println("listening", ln.Addr())

	return (&http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			files.ServeHTTP(rec, r)
			lw.log(r, rec.status)
		}),
	}).Serve(ln)
}
