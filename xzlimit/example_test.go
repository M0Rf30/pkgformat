package xzlimit_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io"

	"github.com/ulikunitz/xz"

	"github.com/M0Rf30/pkgformat/xzlimit"
)

func Example() {
	var packed bytes.Buffer

	w, _ := xz.NewWriter(&packed)
	_, _ = w.Write([]byte("Packages index"))
	_ = w.Close()

	r, err := xzlimit.NewReader(bufio.NewReader(&packed))
	if err != nil {
		fmt.Println(err)

		return
	}

	out, _ := io.ReadAll(r)
	fmt.Println(string(out))

	// Output: Packages index
}
