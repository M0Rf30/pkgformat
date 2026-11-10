package safepath_test

import (
	"errors"
	"fmt"

	"github.com/M0Rf30/pkgformat/safepath"
)

func Example() {
	dst, err := safepath.Join("/srv/root", "usr/bin/tool")
	fmt.Println(dst, err)

	_, err = safepath.Join("/srv/root", "../../etc/passwd")
	fmt.Println(errors.Is(err, safepath.ErrEscapesRoot))

	// Output:
	// /srv/root/usr/bin/tool <nil>
	// true
}
