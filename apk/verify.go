package apk

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// ErrAlreadySigned is returned by [SignPackage] for a package that already
// starts with a signature segment.
var ErrAlreadySigned = errors.New("apk: package is already signed")

// VerifyPackage parses the .apk of size bytes like [ParsePackage] and checks
// that its signature segment holds a valid signature of the control segment by
// a key of opts.Keys, in a type of opts.Algorithms. The error is
// [ErrUnsigned] for a package without signature, [ErrUntrusted] when no
// signature is by a trusted key in an accepted type, [ErrBadSignature] when a
// trusted key's signature does not match; a malformed package wraps
// [ErrInvalidPackage].
func VerifyPackage(ra io.ReaderAt, size int64, opts VerifyOptions) (*Package, error) {
	if err := opts.check(); err != nil {
		return nil, err
	}

	pkg, sigs, err := inspectPackage(ra, size, defaultPackageLimits())
	if err != nil {
		return nil, err
	}

	control, err := io.ReadAll(io.NewSectionReader(ra, sigs.controlStart, sigs.ctrlEnd-sigs.controlStart))
	if err != nil {
		return nil, bad("reading the control segment: %v", err)
	}

	if err := verifySignatures(sigs.sigs, control, opts); err != nil {
		return nil, err
	}

	return pkg, nil
}

// VerifyIndex parses an APKINDEX.tar.gz like [ParseIndex] and checks that the
// signature member in front of the index member holds a valid signature of the
// index member by a key of opts.Keys, in a type of opts.Algorithms. The errors
// are those of [VerifyPackage]; plain APKINDEX text is [ErrUnsigned].
func VerifyIndex(data []byte, opts VerifyOptions) ([]Package, error) {
	if err := opts.check(); err != nil {
		return nil, err
	}

	scan, err := scanIndex(bytes.NewReader(data), defaultIndexLimits())
	if err != nil {
		return nil, err
	}

	if !scan.archive {
		return nil, ErrUnsigned
	}

	if err := verifySignatures(scan.sigs, data[scan.memberStart:scan.memberEnd], opts); err != nil {
		return nil, err
	}

	return scan.pkgs, nil
}

// SignPackage writes the unsigned .apk of size bytes to w with a signature
// segment of s in front of it: the signature covers the control segment, as
// abuild-sign does. A package that is already signed is [ErrAlreadySigned].
// The package is parsed first and must be valid.
func SignPackage(w io.Writer, ra io.ReaderAt, size int64, s *Signer) error {
	_, sigs, err := inspectPackage(ra, size, defaultPackageLimits())
	if err != nil {
		return err
	}

	if len(sigs.sigs) > 0 {
		return ErrAlreadySigned
	}

	control, err := io.ReadAll(io.NewSectionReader(ra, sigs.controlStart, sigs.ctrlEnd-sigs.controlStart))
	if err != nil {
		return fmt.Errorf("apk: reading the control segment: %w", err)
	}

	member, err := signatureMember(s, control, packageGzip)
	if err != nil {
		return fmt.Errorf("apk: signing the control segment: %w", err)
	}

	if _, err := w.Write(member); err != nil {
		return err
	}

	_, err = io.Copy(w, io.NewSectionReader(ra, 0, size))

	return err
}
