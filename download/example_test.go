package download_test

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"

	"github.com/M0Rf30/pkgformat/download"
)

func Example() {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "package payload")
	}))
	defer srv.Close()

	dir, _ := os.MkdirTemp("", "download-example")
	defer os.RemoveAll(dir)

	dest := filepath.Join(dir, "pkg.bin")
	sum := sha256.Sum256([]byte("package payload"))

	err := download.Download(context.Background(), download.Request{
		URL:      srv.URL,
		Dest:     dest,
		Checksum: &download.Checksum{New: sha256.New, Sum: sum[:]},
		Progress: func(done, total int64) {
			if done == total {
				fmt.Println("complete:", done)
			}
		},
	}, download.Options{})

	data, _ := os.ReadFile(dest)
	fmt.Println(string(data), err)

	// Output:
	// complete: 15
	// package payload <nil>
}
