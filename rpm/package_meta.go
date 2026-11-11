package rpm

import (
	"crypto"
	_ "crypto/sha256" // payload digest algorithms
	_ "crypto/sha3"   // payload digest algorithms
	_ "crypto/sha512" // payload digest algorithms
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// Policy is an SELinux policy module that a package carries (the POLICY*
// tags).
type Policy struct {
	Name string `json:"name"`
	// Type is the kind of policy ("selinux").
	Type  string `json:"type,omitempty"`
	Flags uint32 `json:"flags,omitempty"`
}

// PayloadDigest is the digest of the payload of a package under one hash
// algorithm. A package carries digests of the compressed payload, and since
// rpm 4.14 also of the uncompressed one.
type PayloadDigest struct {
	// Algorithm is the lower-case name of the hash: "sha256", "sha512" or
	// "sha3-256".
	Algorithm string `json:"algorithm"`
	// Compressed is the hex digest of the payload as stored in the package
	// (PAYLOADDIGEST, PAYLOADSHA512, PAYLOADSHA3_256).
	Compressed string `json:"compressed,omitempty"`
	// Uncompressed is the hex digest of the payload after decompression, the
	// cpio archive (PAYLOADDIGESTALT and its SHA-512 and SHA3-256 siblings).
	Uncompressed string `json:"uncompressed,omitempty"`
}

// SourceFile is a source or a patch of a source package.
type SourceFile struct {
	// Name is the file name, for example "foo-1.0.tar.gz".
	Name string `json:"name"`
	// Number is the position in the list of sources (or patches) of the
	// package. The header does not store the number the spec file gave
	// ("Source5:"), so this is the number only when the spec numbers its
	// sources consecutively from 0, which is the usual case.
	Number int `json:"number"`
	// NoSource is true for a file that the spec marks %NoSource/%NoPatch:
	// listed by the package but not shipped in it.
	NoSource bool `json:"noSource,omitempty"`
}

// readSources reads the SOURCE or PATCH list. noTag is the tag of the numbers
// of the files that are not shipped (NOSOURCE, NOPATCH); a file is also
// recognised as not shipped when the file list of the package carries it as a
// %ghost entry, which is how rpm records it there.
func (hdr *rpmHeader) readSources(nameTag, noTag, limit int, ghosts map[string]bool) []SourceFile {
	names, _ := hdr.stringsPrefix(nameTag, limit)
	if len(names) == 0 {
		return nil
	}

	no, _ := hdr.numbersPrefix(noTag, limit)
	out := make([]SourceFile, len(names))

	for i, n := range names {
		out[i] = SourceFile{
			Name:     n,
			Number:   i,
			NoSource: ghosts[n] || slices.Contains(no, uint64(i)),
		}
	}

	return out
}

// payloadDigestSets lists the payload digest tags: the tags of the digest of
// the compressed payload and of the uncompressed one, per algorithm.
var payloadDigestSets = []struct {
	compressed, uncompr int
	algoTag             int // the tag that names the algorithm, 0 for a fixed one
	fixedAlgo           uint32
}{
	{tag.PAYLOADDIGEST, tag.PAYLOADSHA256ALT, tag.PAYLOADDIGESTALGO, tag.HASH_SHA256},
	{tag.PAYLOADSHA512, tag.PAYLOADSHA512ALT, 0, tag.HASH_SHA512},
	{tag.PAYLOADSHA3_256, tag.PAYLOADSHA3_256ALT, 0, tag.HASH_SHA3_256},
}

// DigestAlgorithmName returns the name of an OpenPGP/rpm digest algorithm
// number (the values of FILEDIGESTALGO and PAYLOADDIGESTALGO): "md5", "sha1",
// "sha256", "sha3-256" and so on, or "" for an unknown number.
func DigestAlgorithmName(algo uint32) string {
	switch algo {
	case tag.HASH_MD5:
		return "md5"
	case tag.HASH_SHA1:
		return "sha1"
	case tag.HASH_RIPEMD160:
		return "rmd160"
	case tag.HASH_MD2:
		return "md2"
	case tag.HASH_TIGER192:
		return "tgr192"
	case tag.HASH_HAVAL_5_160:
		return "haval5160"
	case tag.HASH_SHA256:
		return "sha256"
	case tag.HASH_SHA384:
		return "sha384"
	case tag.HASH_SHA512:
		return "sha512"
	case tag.HASH_SHA224:
		return "sha224"
	case tag.HASH_SHA3_256:
		return "sha3-256"
	case tag.HASH_SHA3_512:
		return "sha3-512"
	}

	return ""
}

// payloadDigests reads the digests of the payload. A digest that the header
// lists more than once keeps its first value, as rpm does.
func (hdr *rpmHeader) payloadDigests() []PayloadDigest {
	var out []PayloadDigest

	for _, set := range payloadDigestSets {
		comp := hdr.firstString(set.compressed)
		uncomp := hdr.firstString(set.uncompr)

		if comp == "" && uncomp == "" {
			continue
		}

		algo := set.fixedAlgo
		if set.algoTag != 0 {
			// RPM 6 omits the algorithm of the SHA-256 digest
			if v := hdr.firstNumber(set.algoTag); v != 0 {
				algo = uint32(v)
			}
		}

		out = append(out, PayloadDigest{Algorithm: DigestAlgorithmName(algo), Compressed: comp, Uncompressed: uncomp})
	}

	return out
}

// payloadHasher hashes the compressed payload as it is read.
type payloadHasher struct {
	r    io.Reader
	h    hash.Hash
	want string
}

// newPayloadHasher returns a hasher for the compressed payload digest of the
// header, or nil when the package records none.
func newPayloadHasher(hdr *RpmHeader, r io.Reader) (*payloadHasher, error) {
	for _, d := range hdr.genHeader.payloadDigests() {
		if d.Compressed == "" {
			continue
		}

		h, err := hashFor(d.Algorithm)
		if err != nil {
			return nil, err
		}

		if !h.Available() {
			return nil, fmt.Errorf("rpm: payload digest %s is not available", d.Algorithm)
		}

		return &payloadHasher{r: r, h: h.New(), want: strings.ToLower(d.Compressed)}, nil
	}

	return nil, nil
}

func (p *payloadHasher) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.h.Write(b[:n])

	return n, err
}

// finish drains what the decompressor left of the compressed stream and
// compares the digest.
func (p *payloadHasher) finish() error {
	if _, err := io.Copy(io.Discard, p); err != nil {
		return err
	}

	if hex.EncodeToString(p.h.Sum(nil)) != p.want {
		return ErrPayloadDigest
	}

	return nil
}

// digestCheckReader turns the end of the decompressed payload into the
// result of the payload digest comparison.
type digestCheckReader struct {
	r    io.Reader
	h    *payloadHasher
	done bool
	err  error
}

func (d *digestCheckReader) Read(b []byte) (int, error) {
	if d.done {
		return 0, d.err
	}

	n, err := d.r.Read(b)
	if errors.Is(err, io.EOF) {
		d.done = true
		d.err = io.EOF

		if ferr := d.h.finish(); ferr != nil {
			d.err = ferr
		}

		return n, d.err
	}

	return n, err
}

// verifyEnd reads the decompressed payload past the cpio trailer to its end
// and reports the digest comparison.
func (d *digestCheckReader) verifyEnd() error {
	if _, err := io.Copy(io.Discard, d); err != nil {
		return err
	}

	if errors.Is(d.err, io.EOF) {
		return nil
	}

	return d.err
}

func (d *digestCheckReader) Close() error {
	if c, ok := d.r.(io.Closer); ok {
		return c.Close()
	}

	return nil
}

// verifyPayloadEnd completes the payload digest check of a payload stream
// returned by uncompressedPayload; it does nothing when no check is enabled.
func verifyPayloadEnd(r io.Reader) error {
	if d, ok := r.(*digestCheckReader); ok {
		return d.verifyEnd()
	}

	return nil
}

// hashFor returns the crypto.Hash of a payload digest algorithm name.
func hashFor(algorithm string) (crypto.Hash, error) {
	switch algorithm {
	case "md5":
		return crypto.MD5, nil
	case "sha1":
		return crypto.SHA1, nil
	case "sha224":
		return crypto.SHA224, nil
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	case "sha3-256":
		return crypto.SHA3_256, nil
	case "sha3-512":
		return crypto.SHA3_512, nil
	}

	return 0, errors.New("unknown digest algorithm " + algorithm)
}

// policies reads the SELinux policy modules.
func (hdr *rpmHeader) policies(limit int) []Policy {
	names, _ := hdr.stringsPrefix(tag.POLICYNAMES, limit)
	if len(names) == 0 {
		return nil
	}

	types, _ := hdr.stringsPrefix(tag.POLICYTYPES, limit)
	typeIdx, _ := hdr.numbersPrefix(tag.POLICYTYPESINDEXES, len(names))
	flags, _ := hdr.numbersPrefix(tag.POLICYFLAGS, len(names))
	out := make([]Policy, len(names))

	for i, n := range names {
		out[i].Name = n

		if i < len(typeIdx) && typeIdx[i] < uint64(len(types)) {
			out[i].Type = types[typeIdx[i]]
		}

		if i < len(flags) {
			out[i].Flags = uint32(flags[i])
		}
	}

	return out
}
