package dnf

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/M0Rf30/pkgformat/download"
)

// ErrMetalinkMismatch means a repomd.xml does not match the size or a hash the
// repository's metalink publishes for it.
var ErrMetalinkMismatch = errors.New("dnf: repomd.xml does not match its metalink")

// metalinkDoc is the part of a metalink (RFC 5854 as used by dnf) that matters
// here. Element names are matched without their namespace.
type metalinkDoc struct {
	Files []struct {
		Name   string `xml:"name,attr"`
		Size   int64  `xml:"size"`
		Hashes []struct {
			Type  string `xml:"type,attr"`
			Value string `xml:",chardata"`
		} `xml:"verification>hash"`
		URLs []string `xml:"resources>url"`
	} `xml:"files>file"`
}

// metalinkInfo is what a metalink says about repomd.xml.
type metalinkInfo struct {
	size   int64
	hashes []*download.Checksum
}

// parseMetalink reads a metalink document. It returns the mirror URLs of the
// repomd.xml entry (the first file when none is named so) and what the document
// states about it, or ok=false when body is not a metalink with any URL.
func parseMetalink(body string) (urls []string, info *metalinkInfo, ok bool) {
	var doc metalinkDoc

	dec := xml.NewDecoder(strings.NewReader(body))
	dec.Strict = false

	if err := dec.Decode(&doc); err != nil || len(doc.Files) == 0 {
		return nil, nil, false
	}

	idx := 0

	for i := range doc.Files {
		if doc.Files[i].Name == repomdName {
			idx = i

			break
		}
	}

	file := &doc.Files[idx]
	info = &metalinkInfo{size: file.Size}

	for _, h := range file.Hashes {
		if ck, err := download.ParseChecksum(h.Type, strings.TrimSpace(h.Value)); err == nil {
			info.hashes = append(info.hashes, ck)
		}
	}

	for _, u := range file.URLs {
		urls = append(urls, strings.TrimSpace(u))
	}

	return urls, info, len(urls) > 0
}

// verify checks repomd against the size and every hash the metalink gives.
// A metalink that states neither accepts anything.
func (m *metalinkInfo) verify(repomd []byte) error {
	if m == nil {
		return nil
	}

	if m.size > 0 && int64(len(repomd)) != m.size {
		return fmt.Errorf("%w: size %d, metalink says %d", ErrMetalinkMismatch, len(repomd), m.size)
	}

	for _, ck := range m.hashes {
		h := ck.New()
		_, _ = h.Write(repomd)

		if !bytes.Equal(h.Sum(nil), ck.Sum) {
			return fmt.Errorf("%w: hash differs", ErrMetalinkMismatch)
		}
	}

	return nil
}
