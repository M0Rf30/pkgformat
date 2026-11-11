package rpm

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

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
// different checksum, from the input.
//
// A signer implementing [KeyHolder] (such as [gpg.LocalSigner], including
// one made by [gpg.NewCryptoSigner] for an HSM or KMS key) signs with its key
// directly. Any other [gpg.Signer] (for example one that runs gpg-agent or a
// remote signing service) is asked for detached signatures of the general
// header through DetachedSign; the package then gets the header-only
// signature rpm 4.16 and later produce (RSAHEADER, or OPENPGP for format 6)
// and no header-plus-payload signature. The payload is still covered, through
// the payload digest of the signed header, which is checked before signing.
func Sign(src io.ReadSeeker, dst io.Writer, signer gpg.Signer) error {
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("rpm: rewinding the package: %w", err)
	}

	var (
		header *RpmHeader
		err    error
	)

	if holder, ok := signer.(KeyHolder); ok {
		key, kerr := holder.SigningKey()
		if kerr != nil {
			return fmt.Errorf("rpm: signing key: %w", kerr)
		}

		header, err = SignRpmStream(src, key, nil)
	} else {
		header, err = signHeaderOnly(src, signer)
	}

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

// signHeaderOnly signs the general header with an opaque signer.
func signHeaderOnly(stream io.Reader, signer gpg.Signer) (*RpmHeader, error) {
	lead, sigHeader, err := readSignatureHeader(stream, HeaderLimits{})
	if err != nil {
		return nil, err
	}

	genHeader, err := readGeneralHeader(stream, sigHeader, HeaderLimits{})
	if err != nil {
		return nil, err
	}

	if err := digestPayload(sigHeader, genHeader, stream, nil); err != nil {
		return nil, err
	}

	armored, err := signer.DetachedSign(bytes.NewReader(genHeader.orig))
	if err != nil {
		return nil, err
	}

	sig, err := dearmorSignature(armored)
	if err != nil {
		return nil, err
	}

	if isFormatV6(genHeader) {
		setOpenPGPSignature(sigHeader, sig)
	} else {
		insertSignature(sigHeader, tag.SIG_RSA, sig)
		delete(sigHeader.entries, tag.SIG_DSA)
		delete(sigHeader.entries, tag.SIG_PGP-tag.SIGHEADER_TAG_BASE)
		delete(sigHeader.entries, tag.SIG_GPG-tag.SIGHEADER_TAG_BASE)
	}

	return &RpmHeader{lead: lead, sigHeader: sigHeader, genHeader: genHeader, isSource: sigHeader.isSource}, nil
}

// dearmorSignature returns the binary packets of a detached signature that
// may be ASCII-armored.
func dearmorSignature(sig []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(sig)
	if !bytes.HasPrefix(trimmed, []byte("-----BEGIN")) {
		return sig, nil
	}

	block, err := armor.Decode(bytes.NewReader(trimmed))
	if err != nil {
		return nil, fmt.Errorf("decoding the armored signature: %w", err)
	}

	return io.ReadAll(block.Body)
}
