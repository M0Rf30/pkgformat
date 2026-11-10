package rpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
)

// ReadHeaderBlob decodes the header of an installed package as the rpm
// database stores it: an immutable-region header image without the magic and
// reserved words a header has inside a package file, that is the number of
// index entries and the size of the data as two big endian 32 bit integers,
// the index, then the data.
//
// The signature header of a package is not part of the image, so the result
// answers the tags of the general header only. The blob is not retained. lim
// bounds the image as it does for [ReadHeaderLimits]; the zero value selects
// the defaults.
func ReadHeaderBlob(blob []byte, lim HeaderLimits) (*RpmHeader, error) {
	if len(blob) < 8 {
		return nil, fmt.Errorf("%w: header image of %d bytes", ErrInvalidHeader, len(blob))
	}

	// The image lacks the 8 bytes (magic and reserved) the file layout starts
	// with; readHeader expects them.
	var prefix [8]byte

	binary.BigEndian.PutUint32(prefix[:4], rpmhdr.IntroMagic)

	gen, err := readHeader(
		io.MultiReader(bytes.NewReader(prefix[:]), bytes.NewReader(blob)), "", 0, false, false, lim,
	)
	if err != nil {
		return nil, err
	}

	return &RpmHeader{
		sigHeader: &rpmHeader{entries: map[int]rpmhdr.Entry{}},
		genHeader: gen,
	}, nil
}

// InstalledPackage returns the metadata of a header that describes an
// installed package, as [RpmHeader.Package] does for a package file with two
// differences: the architecture may be missing (the gpg-pubkey pseudo packages
// of the rpm database have none), and [Package.InstallTime] is set.
func (hdr *RpmHeader) InstalledPackage(lim PackageLimits) (*Package, error) {
	return hdr.buildPackage(lim, false)
}
