package rpm

import (
	"bytes"
	"crypto/md5" //nolint:gosec // G501: legacy RPM header+payload digest, verified for integrity only
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/M0Rf30/pkgformat/rpm/tag"
	_ "golang.org/x/crypto/sha3" // registers crypto.SHA3_256
)

var headerSigTags = []int{tag.SIG_RSA, tag.SIG_DSA}
var payloadSigTags = []int{
	tag.SIG_PGP - tag.SIGHEADER_TAG_BASE,
	tag.SIG_GPG - tag.SIGHEADER_TAG_BASE,
}

// Try to parse a PGP signature with the given tag and return its metadata and
// hash function.
func setupDigester(sigHeader *rpmHeader, id int, vf *verifier) (*Signature, error) {
	blob, err := sigHeader.GetBytes(id)
	if errors.As(err, &NoSuchTagError{}) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return parseSignature(blob, vf)
}

// Parse the RPM v6 OPENPGP signature array. Each element is a base64 encoded
// binary OpenPGP signature over the general header.
func setupOpenPGPDigesters(sigHeader, genHeader *rpmHeader, vf *verifier) ([]*Signature, []hash.Hash, error) {
	encoded, err := sigHeader.GetStrings(tag.SIG_OPENPGP)
	if err != nil {
		return nil, nil, err
	}
	var sigs []*Signature
	var hashes []hash.Hash
	for _, e := range encoded {
		blob, err := base64.StdEncoding.DecodeString(e)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid OpenPGP signature encoding: %w", err)
		}
		sig, err := parseSignature(blob, vf)
		if err != nil {
			return nil, nil, err
		}
		sig.HeaderOnly = true
		h, err := sig.newHash()
		if err != nil {
			return nil, nil, err
		}
		h.Write(genHeader.orig)
		sigs = append(sigs, sig)
		hashes = append(hashes, h)
	}
	return sigs, hashes, nil
}

// Parse signatures from the header and determine which hash functions are
// needed to digest the RPM. The caller must write the payload to the returned
// WriteCloser, then call Close to check if the payload digest matches.
func digestAndVerify(sigHeader, genHeader *rpmHeader, payloadReader io.Reader, vf *verifier) ([]*Signature, []hash.Hash, error) {
	var sigs []*Signature
	var hashes []hash.Hash
	// RPM v6 signatures: base64 OpenPGP packets over the general header alone.
	// When present they supersede the legacy signature tags.
	if sigHeader.HasTag(tag.SIG_OPENPGP) {
		var err error
		sigs, hashes, err = setupOpenPGPDigesters(sigHeader, genHeader, vf)
		if err != nil {
			return nil, nil, err
		}
		err = digestPayload(sigHeader, genHeader, payloadReader, nil)
		return sigs, hashes, err
	}
	// signatures over the general header alone
	for _, id := range headerSigTags {
		sig, err := setupDigester(sigHeader, id, vf)
		if err != nil {
			return nil, nil, err
		} else if sig == nil {
			continue
		}
		sig.HeaderOnly = true
		h, err := sig.newHash()
		if err != nil {
			return nil, nil, err
		}
		h.Write(genHeader.orig)
		sigs = append(sigs, sig)
		hashes = append(hashes, h)
	}
	// signatures over the general header + payload
	var payloadWriters []io.Writer
	for _, id := range payloadSigTags {
		sig, err := setupDigester(sigHeader, id, vf)
		if err != nil {
			return nil, nil, err
		} else if sig == nil {
			continue
		}
		sig.HeaderOnly = false
		h, err := sig.newHash()
		if err != nil {
			return nil, nil, err
		}
		h.Write(genHeader.orig)
		payloadWriters = append(payloadWriters, h)
		sigs = append(sigs, sig)
		hashes = append(hashes, h)
	}
	err := digestPayload(sigHeader, genHeader, payloadReader, payloadWriters)
	return sigs, hashes, err
}

func digestPayload(sigHeader, genHeader *rpmHeader, payloadReader io.Reader, payloadWriters []io.Writer) error {
	// Also compute a digest over the payload for integrity checking purposes
	if payloadValue, payloadType := getPayloadDigest(genHeader); payloadType != 0 {
		if !payloadType.Available() {
			return fmt.Errorf("unknown payload digest %s", payloadType)
		}
		payloadHasher := payloadType.New()
		// hash payload only
		payloadWriters = append(payloadWriters, payloadHasher)
		if _, err := io.Copy(io.MultiWriter(payloadWriters...), payloadReader); err != nil {
			return err
		}
		calculated := hex.EncodeToString(payloadHasher.Sum(nil))
		if calculated != payloadValue {
			return fmt.Errorf("payload %s digest mismatch", payloadType)
		}
		return nil
	}
	// Check legacy MD5 digest in sig header as a last resort. This is the only
	// digest found in the signature header that covers the payload, so for some
	// old RPMs that don't have a payload digest in the general header this is
	// the only integrity check we can use unless we're verifying the PGP
	// signatures.
	if sigmd5, _ := sigHeader.GetBytes(tag.SIG_MD5 - tag.SIGHEADER_TAG_BASE); len(sigmd5) != 0 {
		payloadHasher := md5.New() //nolint:gosec // G401: legacy RPM digest, see import
		// hash header + payload
		payloadHasher.Write(genHeader.orig)
		payloadWriters = append(payloadWriters, payloadHasher)
		if _, err := io.Copy(io.MultiWriter(payloadWriters...), payloadReader); err != nil {
			return err
		}
		calculated := payloadHasher.Sum(nil)
		if !bytes.Equal(calculated, sigmd5) {
			return errors.New("md5 digest mismatch")
		}
		return nil
	}
	return errors.New("no usable payload digest found")
}
