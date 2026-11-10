package apk

import (
	"archive/tar"
	"bytes"
	stdgzip "compress/gzip"
	"fmt"
	"io"
	"time"

	"github.com/klauspost/compress/gzip"
)

// gzipOSUnix is the OS byte abuild's gzip writes.
const gzipOSUnix = 3

// newGzip makes the gzip writer of a segment. Packages and indexes are
// compressed by different implementations, each of which is byte-stable on
// its own: an index is served and signed as bytes, so its encoding is that of
// the standard library's compress/gzip at its default level.
type newGzip func(w io.Writer) (io.WriteCloser, error)

// packageGzip compresses the segments of a package.
func packageGzip(w io.Writer) (io.WriteCloser, error) {
	gw, err := gzip.NewWriterLevel(w, gzip.DefaultCompression)
	if err != nil {
		return nil, err
	}

	gw.OS = gzipOSUnix

	return gw, nil
}

// indexGzip compresses an index and its signature member.
func indexGzip(w io.Writer) (io.WriteCloser, error) {
	gw, err := stdgzip.NewWriterLevel(w, stdgzip.DefaultCompression)
	if err != nil {
		return nil, err
	}

	gw.OS = gzipOSUnix

	return gw, nil
}

type archiveFile struct {
	name string
	data []byte
	// mode is the permission bits; zero selects 0644.
	mode int64
}

// gzipTar returns the files as one gzip member holding a tar stream. The
// output is a function of the arguments alone: gzip mtime 0 and no name, tar
// entries with mtime 0, mode 0644, owner 0, plain ustar headers (never PAX).
// withEnd appends the end-of-archive blocks; without them the tar can be
// continued by the next member, which is how abuild writes signatures.
//
// The default level (6) is deliberate: on a real 8 MB community index level 9
// costs three times the CPU for an archive 3 % smaller.
func gzipTar(files []archiveFile, withEnd bool, compress newGzip) ([]byte, error) {
	var buf bytes.Buffer

	gw, err := compress(&buf)
	if err != nil {
		return nil, err
	}

	tw := tar.NewWriter(gw)

	for _, f := range files {
		mode := f.mode
		if mode == 0 {
			mode = 0o644
		}

		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     f.name,
			Size:     int64(len(f.data)),
			Mode:     mode,
			ModTime:  time.Unix(0, 0),
			Format:   tar.FormatUSTAR,
		}

		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}

		if _, err := tw.Write(f.data); err != nil {
			return nil, err
		}
	}

	if withEnd {
		err = tw.Close()
	} else {
		err = tw.Flush()
	}

	if err != nil {
		return nil, err
	}

	if err := gw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// BuildIndex builds a deterministic APKINDEX.tar.gz for pkgs: a gzip member
// with the tar entries DESCRIPTION and APKINDEX, ended like apk's own index
// tars. With a signer it is preceded by the signature member, a gzip member
// whose tar (no end-of-archive blocks, so that apk reads on into the next
// member) holds the entry .SIGN.RSA.<key name> or .SIGN.RSA256.<key name>,
// as the signer's [SigAlgorithm] says: the RSA PKCS#1 v1.5 signature of the
// complete bytes of the index member. Every package must be valid (see
// [Package]), carrying at least the Checksum; errors wrap [ErrInvalidIndex].
func BuildIndex(pkgs []Package, description string, s *Signer) ([]byte, error) {
	if len(description) > maxTextLen || !cleanText(description) {
		return nil, badIndex("description is longer than %d bytes or has control characters", maxTextLen)
	}

	for i := range pkgs {
		if err := pkgs[i].validate(); err != nil {
			return nil, badIndex("package %d: %v", i+1, err)
		}
	}

	index, err := gzipTar([]archiveFile{
		{name: descFileName, data: []byte(description)},
		{name: indexFileName, data: RenderIndex(pkgs)},
	}, true, indexGzip)
	if err != nil {
		return nil, fmt.Errorf("building the index: %w", err)
	}

	if s == nil {
		return index, nil
	}

	member, err := signatureMember(s, index, indexGzip)
	if err != nil {
		return nil, fmt.Errorf("signing the index: %w", err)
	}

	return append(member, index...), nil
}

// signatureMember returns the gzip member that holds the signature of signed,
// compressed by compress.
func signatureMember(s *Signer, signed []byte, compress newGzip) ([]byte, error) {
	sig, err := s.Sign(signed)
	if err != nil {
		return nil, err
	}

	return gzipTar([]archiveFile{{name: s.EntryName(), data: sig}}, false, compress)
}
