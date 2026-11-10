/*
 * Copyright (c) SAS Institute Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rpm

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/M0Rf30/pkgformat/rpm/internal/fileutil"
	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// SignatureOptions describes additional configuration for SignRpm methods
type SignatureOptions struct {
	// Hash algorithm for the signature. If not set, defaults to SHA-256
	Hash crypto.Hash
	// CreationTime for the signature. If not set, defaults to the current time
	CreationTime time.Time
	// Lifetime is how long the signature is valid for, counted from its
	// creation time and rounded down to whole seconds. Zero means it never
	// expires.
	Lifetime time.Duration
}

func (opts *SignatureOptions) hash() crypto.Hash {
	if opts != nil && opts.Hash != 0 {
		return opts.Hash
	}
	return crypto.SHA256
}

func (opts *SignatureOptions) creationTime() time.Time {
	if opts != nil && !opts.CreationTime.IsZero() {
		return opts.CreationTime
	}
	return time.Now()
}

func makeSignature(h hash.Hash, key *packet.PrivateKey, opts *SignatureOptions) ([]byte, error) {
	hashType := opts.hash()
	sig := &packet.Signature{
		SigType:      packet.SigTypeBinary,
		CreationTime: opts.creationTime(),
		PubKeyAlgo:   key.PubKeyAlgo,
		Hash:         hashType,
		IssuerKeyId:  &key.KeyId,
	}
	if opts != nil && opts.Lifetime >= time.Second {
		secs := uint32(min(opts.Lifetime/time.Second, math.MaxUint32))
		sig.SigLifetimeSecs = &secs
	}
	err := sig.Sign(h, key, nil)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	err = sig.Serialize(&buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func insertSignature(sigHeader *rpmHeader, id int, value []byte) {
	sigHeader.entries[id] = rpmhdr.Entry{
		Type:  tag.RPM_BIN_TYPE,
		Count: len(value),
		Data:  value,
	}
}

func insertSignatures(sigHeader *rpmHeader, sigPgp, sigRsa []byte) {
	insertSignature(sigHeader, tag.SIG_PGP-tag.SIGHEADER_TAG_BASE, sigPgp)
	insertSignature(sigHeader, tag.SIG_RSA, sigRsa)
	delete(sigHeader.entries, tag.SIG_GPG-tag.SIGHEADER_TAG_BASE)
	delete(sigHeader.entries, tag.SIG_DSA)
}

func getSha1(sigHeader *rpmHeader) string {
	vals, err := sigHeader.GetStrings(tag.SIG_SHA1)
	if err != nil || len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func getSha256(sigHeader *rpmHeader) string {
	vals, err := sigHeader.GetStrings(tag.SIG_SHA256)
	if err != nil || len(vals) == 0 {
		return ""
	}
	return vals[0]
}

func getSha3_256(sigHeader *rpmHeader) string {
	vals, err := sigHeader.GetStrings(tag.SIG_SHA3_256)
	if err != nil || len(vals) == 0 {
		return ""
	}
	return vals[0]
}

// readGeneralHeader reads the general header and checks it against the
// digests in the signature header. The strongest digest is checked while
// reading and, if both are present, the SHA256 digest is checked as well.
func readGeneralHeader(f io.Reader, sigHeader *rpmHeader, lim HeaderLimits) (*rpmHeader, error) {
	value, hashType := getHashAndType(sigHeader)
	genHeader, err := readHeader(f, value, hashType, sigHeader.isSource, false, lim)
	if err != nil {
		return nil, err
	}
	if hashType == crypto.SHA3_256 {
		if want := getSha256(sigHeader); want != "" {
			sum := sha256.Sum256(genHeader.orig)
			if hex.EncodeToString(sum[:]) != want {
				return nil, fmt.Errorf("%s mismatch in signature header", crypto.SHA256)
			}
		}
	}
	return genHeader, nil
}

func getHashAndType(sigHeader *rpmHeader) (string, crypto.Hash) {
	// RPM v6 added SHA3-256, prefer it over everything else
	if h := getSha3_256(sigHeader); h != "" {
		return h, crypto.SHA3_256
	}
	// RPM v4 introduced SHA256 header signatures, prefer them over the
	// previous SHA1
	if h := getSha256(sigHeader); h != "" {
		return h, crypto.SHA256
	}
	return getSha1(sigHeader), crypto.SHA1
}

func digestForSigning(sigHeader, genHeader *rpmHeader, payloadReader io.Reader, opts *SignatureOptions) (genHash, combinedHash hash.Hash, err error) {
	genHash, combinedHash = opts.hash().New(), opts.hash().New()
	// write header
	genHash.Write(genHeader.orig)
	combinedHash.Write(genHeader.orig)
	// write and verify payload
	err = digestPayload(sigHeader, genHeader, payloadReader, []io.Writer{combinedHash})
	return genHash, combinedHash, err
}

// SignRpmStream reads an RPM and signs it, returning the set of headers updated with the new signature.
func SignRpmStream(stream io.Reader, key *packet.PrivateKey, opts *SignatureOptions) (header *RpmHeader, err error) {
	lead, sigHeader, err := readSignatureHeader(stream, HeaderLimits{})
	if err != nil {
		return nil, err
	}
	// parse the general header
	genHeader, err := readGeneralHeader(stream, sigHeader, HeaderLimits{})
	if err != nil {
		return nil, err
	}
	if isFormatV6(genHeader) {
		if err := signV6(sigHeader, genHeader, stream, key, opts); err != nil {
			return nil, err
		}
		return &RpmHeader{
			lead:      lead,
			sigHeader: sigHeader,
			genHeader: genHeader,
			isSource:  sigHeader.isSource,
		}, nil
	}
	// hash and sign header
	genHash, combinedHash, err := digestForSigning(sigHeader, genHeader, stream, opts)
	if err != nil {
		return nil, err
	}
	// sign header and payload
	sigPgp, err := makeSignature(combinedHash, key, opts)
	if err != nil {
		return
	}
	sigRsa, err := makeSignature(genHash, key, opts)
	if err != nil {
		return nil, err
	}
	insertSignatures(sigHeader, sigPgp, sigRsa)
	return &RpmHeader{
		lead:      lead,
		sigHeader: sigHeader,
		genHeader: genHeader,
		isSource:  sigHeader.isSource,
	}, nil
}

// isFormatV6 reports whether the general header declares RPM package format 6
// or later.
func isFormatV6(genHeader *rpmHeader) bool {
	format, err := genHeader.GetUint32s(tag.RPMFORMAT)
	return err == nil && len(format) == 1 && format[0] >= 6
}

// signV6 signs an RPM v6 package the way rpmsign 6 does: one OpenPGP
// signature over the general header only, stored base64-encoded in the
// OPENPGP signature tag. The payload is covered through the payload digests
// of the (signed) header, which are checked here before signing. Existing
// signatures are replaced; legacy v4 signature tags are dropped because rpm
// ignores them once an OPENPGP signature is present.
func signV6(sigHeader, genHeader *rpmHeader, payload io.Reader, key *packet.PrivateKey, opts *SignatureOptions) error {
	if err := digestPayload(sigHeader, genHeader, payload, nil); err != nil {
		return err
	}
	h := opts.hash().New()
	h.Write(genHeader.orig)
	sig, err := makeSignature(h, key, opts)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(sig)
	sigHeader.entries[tag.SIG_OPENPGP] = rpmhdr.Entry{
		Type:  tag.RPM_STRING_ARRAY_TYPE,
		Count: 1,
		Data:  append([]byte(encoded), 0),
	}
	delete(sigHeader.entries, tag.SIG_RSA)
	delete(sigHeader.entries, tag.SIG_DSA)
	delete(sigHeader.entries, tag.SIG_PGP-tag.SIGHEADER_TAG_BASE)
	delete(sigHeader.entries, tag.SIG_GPG-tag.SIGHEADER_TAG_BASE)
	return nil
}

func getPayloadDigest(header *rpmHeader) (string, crypto.Hash) {
	// RPM v6 stores digests of the compressed payload in dedicated tags;
	// prefer the strongest one available.
	for _, c := range []struct {
		tag  int
		hash crypto.Hash
	}{
		{tag.PAYLOADSHA3_256, crypto.SHA3_256},
		{tag.PAYLOADSHA512, crypto.SHA512},
	} {
		if vals, err := header.GetStrings(c.tag); err == nil && len(vals) > 0 && vals[0] != "" {
			return vals[0], c.hash
		}
	}
	digests, err := header.GetStrings(tag.PAYLOADDIGEST)
	if err != nil || len(digests) == 0 {
		// no payload digest
		return "", 0
	}
	digest := digests[0]
	algos, err := header.GetUint32s(tag.PAYLOADDIGESTALGO)
	if err != nil {
		if errors.As(err, &NoSuchTagError{}) {
			// RPM v6 omits the algorithm tag, the digest is always SHA256
			return digest, crypto.SHA256
		}
		return "", 0
	} else if len(algos) == 0 {
		return "", 0
	}
	switch algos[0] {
	case tag.HASH_MD5:
		return digest, crypto.MD5
	case tag.HASH_SHA1:
		return digest, crypto.SHA1
	case tag.HASH_SHA256:
		return digest, crypto.SHA256
	case tag.HASH_SHA384:
		return digest, crypto.SHA384
	case tag.HASH_SHA512:
		return digest, crypto.SHA512
	case tag.HASH_SHA224:
		return digest, crypto.SHA224
	}
	return "", 0
}

func canOverwrite(ininfo, outinfo os.FileInfo) bool {
	if !outinfo.Mode().IsRegular() {
		return false
	}
	if !os.SameFile(ininfo, outinfo) {
		return false
	}
	if fileutil.HasLinks(outinfo) {
		return false
	}
	return true
}

// SignRpmFile signs infile and writes it to outpath, which may be the same file
func SignRpmFile(infile *os.File, outpath string, key *packet.PrivateKey, opts *SignatureOptions) (header *RpmHeader, err error) {
	header, err = SignRpmStream(infile, key, opts)
	if err != nil {
		return
	}
	return header, rewriteRpm(infile, outpath, header)
}

// RewriteWithSignatures inserts raw signatures into a RPM header.
//
// DEPRECATED: To perform a detached signature, use SignRpmStream and call
// DumpSignatureHeader to export the result.
func RewriteWithSignatures(infile *os.File, outpath string, sigPgp, sigRsa []byte) (*RpmHeader, error) {
	header, err := ReadHeader(infile)
	if err != nil {
		return nil, err
	}
	insertSignatures(header.sigHeader, sigPgp, sigRsa)
	err = rewriteRpm(infile, outpath, header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func rewriteRpm(infile *os.File, outpath string, header *RpmHeader) error {
	delete(header.sigHeader.entries, tag.SIG_RESERVEDSPACE-tag.SIGHEADER_TAG_BASE)
	ininfo, err := infile.Stat()
	if err != nil {
		return err
	}
	if outpath == "-" {
		return writeRpm(infile, os.Stdout, header.sigHeader)
	}
	outinfo, err := os.Lstat(outpath)
	if err == nil && canOverwrite(ininfo, outinfo) {
		ok, err := writeInPlace(outpath, header)
		if err != nil || ok {
			return err
		}
		// in-place didn't work; fallback to rewrite
	} else if err == nil && !outinfo.Mode().IsRegular() {
		// pipe or something else. open for writing.
		outfile, err := os.Create(outpath)
		if err != nil {
			return err
		}
		if err := writeRpm(infile, outfile, header.sigHeader); err != nil {
			_ = outfile.Close()
			return err
		}
		return outfile.Close()
	}
	return writeRpmAtomic(infile, outpath, header.sigHeader)
}

// writeRpmAtomic writes the RPM to a temporary file next to outpath and
// renames it into place only once it has been written completely, so that a
// failure never leaves a truncated file at outpath.
func writeRpmAtomic(infile io.ReadSeeker, outpath string, sigHeader *rpmHeader) error {
	tempfile, err := os.CreateTemp(filepath.Dir(outpath), filepath.Base(outpath))
	if err != nil {
		return err
	}
	if err := writeRpm(infile, tempfile, sigHeader); err != nil {
		_ = tempfile.Close()
		_ = os.Remove(tempfile.Name())
		return err
	}
	_ = tempfile.Chmod(0o644)
	if err := tempfile.Close(); err != nil {
		_ = os.Remove(tempfile.Name())
		return err
	}
	if err := os.Rename(tempfile.Name(), outpath); err != nil {
		_ = os.Remove(tempfile.Name())
		return err
	}
	return nil
}

func writeInPlace(path string, header *RpmHeader) (ok bool, err error) {
	blob, err := header.DumpSignatureHeader(true)
	if err != nil {
		return false, err
	}
	orig := header.OriginalSignatureHeaderSize()
	if orig != len(blob) {
		// size changed; can't rewrite in place
		return false, nil
	}
	outfile, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return
	}
	defer outfile.Close()
	n, err := outfile.Write(blob)
	if err != nil {
		return false, err
	} else if n != len(blob) {
		return false, io.ErrShortWrite
	}
	return true, nil
}

func writeRpm(infile io.ReadSeeker, outstream io.Writer, sigHeader *rpmHeader) error {
	if _, err := infile.Seek(0, 0); err != nil {
		return err
	}
	lead, err := readExact(infile, 96)
	if err != nil {
		return err
	}
	if _, err = outstream.Write(lead); err != nil {
		return err
	}
	if err = sigHeader.WriteTo(outstream, tag.RPMTAG_HEADERSIGNATURES); err != nil {
		return err
	}
	if _, err := infile.Seek(int64(len(lead)+len(sigHeader.orig)), 0); err != nil {
		return err
	}
	_, err = io.Copy(outstream, infile)
	return err
}
