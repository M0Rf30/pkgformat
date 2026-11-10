package tag_test

import (
	"fmt"

	"github.com/M0Rf30/pkgformat/rpm/tag"
)

func Example() {
	fmt.Println(tag.NAME, tag.RPM_STRING_TYPE)
	// The signature tags that overlap the general ones are offset, to be
	// addressed with the same functions. The offset is not part of the format.
	fmt.Println(tag.SIG_SIZE, tag.SIG_SIZE-tag.SIGHEADER_TAG_BASE)
	// Output:
	// 1000 6
	// 17384 1000
}
