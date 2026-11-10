package rpm

import (
	"errors"
	"fmt"
	"io"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// ErrKeyNotSupported means the signer cannot expose a private key to sign
// packages with.
var ErrKeyNotSupported = errors.New("rpm: signer cannot sign packages")

// KeyHolder is implemented by signers that hold their private key locally,
// such as [gpg.LocalSigner].
type KeyHolder interface {
	SigningKey() (*packet.PrivateKey, error)
}

// Sign writes a copy of the package in src to dst with the header-only
// (RSAHEADER) and header-plus-payload (PGP) signatures of signer, or the
// OpenPGP signature of a format 6 package, replacing any signature the package
// already had. src is read from the start and must be seekable.
//
// Only the signature header is rewritten: the general header and the payload
// are copied byte for byte, so the result is a different file, with a
// different checksum, from the input. The signer must implement [KeyHolder].
func Sign(src io.ReadSeeker, dst io.Writer, signer gpg.Signer) error {
	holder, ok := signer.(KeyHolder)
	if !ok {
		return ErrKeyNotSupported
	}

	key, err := holder.SigningKey()
	if err != nil {
		return fmt.Errorf("rpm: signing key: %w", err)
	}

	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rpm: rewinding the package: %w", err)
	}

	header, err := SignRpmStream(src, key, nil)
	if err != nil {
		return fmt.Errorf("rpm: signing: %w", err)
	}

	// The dump holds the lead followed by the new signature header (without
	// the padding of the old one): everything after
	// OriginalSignatureHeaderSize is untouched.
	head, err := header.DumpSignatureHeader(false)
	if err != nil {
		return fmt.Errorf("rpm: encoding the signature header: %w", err)
	}

	if _, err := dst.Write(head); err != nil {
		return fmt.Errorf("rpm: writing the signature header: %w", err)
	}

	if _, err := src.Seek(int64(header.OriginalSignatureHeaderSize()), io.SeekStart); err != nil {
		return fmt.Errorf("rpm: skipping the old signature header: %w", err)
	}

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("rpm: copying the package body: %w", err)
	}

	return nil
}
