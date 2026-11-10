package repodata

import (
	"bytes"
	"github.com/M0Rf30/pkgformat/rpm/tag"
	"io"

	pkgrpm "github.com/M0Rf30/pkgformat/rpm"
)

// renderXML runs one of the Write*XML streamers into memory.
func renderXML(write func(io.Writer, []pkgrpm.Package) error, pkgs []pkgrpm.Package) ([]byte, error) {
	var buf bytes.Buffer
	if err := write(&buf, pkgs); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// compressXML compresses an in-memory document through CompressMetadataStream.
func compressXML(data []byte) (*CompressedMetadata, error) {
	return CompressMetadataStream(Gzip, func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	})
}

const (
	senseLE = tag.RPMSENSE_LESS | tag.RPMSENSE_EQUAL
	senseGE = tag.RPMSENSE_GREATER | tag.RPMSENSE_EQUAL
)
