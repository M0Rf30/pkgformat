package rpm

import (
	"bytes"
	"crypto"
	"crypto/dsa" //nolint:staticcheck // version 3 DSA signatures
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/stretchr/testify/require"
)

func imaBlob(hashAlgo byte, sig []byte) []byte {
	b := []byte{3, 2, hashAlgo, 1, 2, 3, 4, 0, 0}
	binary.BigEndian.PutUint16(b[7:], uint16(len(sig)))
	return append(b, sig...)
}

func TestVerifyIMASignatureECDSAAndErrors(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("contents"))
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)

	blob := imaBlob(4, sig)
	require.NoError(t, VerifyIMASignature(blob, digest[:], &key.PublicKey))
	require.NoError(t, VerifyIMASignature([]byte(hex.EncodeToString(blob)), digest[:], &key.PublicKey))

	other := sha256.Sum256([]byte("other"))
	require.ErrorIs(t, VerifyIMASignature(blob, other[:], &key.PublicKey), ErrFileSignature)
	require.ErrorIs(t, VerifyIMASignature(blob, digest[:8], &key.PublicKey), ErrFileSignature)

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	require.ErrorIs(t, VerifyIMASignature(blob, digest[:], edPub), ErrFileSignature)

	for _, bad := range [][]byte{nil, {3, 1, 4, 0, 0, 0, 0, 0, 0}, imaBlob(99, sig), imaBlob(4, sig)[:20]} {
		require.ErrorIs(t, VerifyIMASignature(bad, digest[:], &key.PublicKey), ErrFileSignature)
	}
}

// TestVerifyVerityOpenSSLSignatures checks signatures made by openssl cms,
// with signed attributes and both kinds of signer identifier.
func TestVerifyVerityOpenSSLSignatures(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}

	dir := t.TempDir()
	run := func(args ...string) {
		out, err := exec.Command("openssl", args...).CombinedOutput()
		require.NoError(t, err, string(out))
	}
	key, crt := filepath.Join(dir, "k.pem"), filepath.Join(dir, "c.pem")
	run("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
		"-keyout", key, "-out", crt, "-days", "2", "-subj", "/CN=t")

	raw, err := os.ReadFile(crt)
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("file"))
	formatted := append([]byte("FSVerity\x01\x00\x20\x00"), digest[:]...)
	in := filepath.Join(dir, "in")
	require.NoError(t, os.WriteFile(in, formatted, 0o600))

	for _, extra := range [][]string{nil, {"-keyid"}, {"-noattr"}} {
		out := filepath.Join(dir, "sig")
		run(append([]string{"cms", "-sign", "-binary", "-nocerts", "-in", in, "-signer", crt,
			"-inkey", key, "-md", "sha256", "-outform", "DER", "-out", out}, extra...)...)
		sig, err := os.ReadFile(out)
		require.NoError(t, err)

		require.NoError(t, VerifyVeritySignature(sig, digest[:], VeritySHA256, []*x509.Certificate{cert}), extra)
		bad := digest
		bad[3] ^= 1
		require.ErrorIs(t, VerifyVeritySignature(sig, bad[:], VeritySHA256, []*x509.Certificate{cert}), ErrFileSignature, extra)
	}

	require.ErrorIs(t, VerifyVeritySignature([]byte("not der"), digest[:], VeritySHA256, nil), ErrFileSignature)
	require.ErrorIs(t, VerifyVeritySignature(nil, digest[:4], VeritySHA256, nil), ErrFileSignature)
	require.ErrorIs(t, VerifyVeritySignature(nil, digest[:], 7, nil), ErrFileSignature)
}

// v3Packet builds a version 3 signature packet over data.
func v3Packet(t *testing.T, newFormat bool, algo packet.PublicKeyAlgorithm, data []byte, sign func([]byte) [][]byte) []byte {
	t.Helper()

	trailer := []byte{0x00, 0, 0, 0, 1}
	binary.BigEndian.PutUint32(trailer[1:], uint32(time.Date(2010, 1, 1, 0, 0, 0, 0, time.UTC).Unix()))
	h := sha256.New()
	h.Write(data)
	h.Write(trailer)
	digest := h.Sum(nil)

	body := []byte{3, 5}
	body = append(body, trailer...)
	body = append(body, 0, 0, 0, 0, 0, 0, 0, 7, byte(algo), 8, digest[0], digest[1])
	for _, m := range sign(digest) {
		var l [2]byte
		binary.BigEndian.PutUint16(l[:], uint16(len(m)*8))
		body = append(append(body, l[:]...), m...)
	}

	if newFormat {
		hdr := []byte{0xc2, 0xff, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(hdr[2:], uint32(len(body)))
		return append(hdr, body...)
	}

	hdr := []byte{0x89, 0, 0}
	binary.BigEndian.PutUint16(hdr[1:], uint16(len(body)))
	return append(hdr, body...)
}

func TestV3SignatureRSAAndDSA(t *testing.T) {
	data := []byte("signed header")

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaBlob := v3Packet(t, true, packet.PubKeyAlgoRSA, data, func(d []byte) [][]byte {
		s, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, d)
		require.NoError(t, err)
		return [][]byte{bytes.TrimLeft(s, "\x00")}
	})

	var params dsa.Parameters
	require.NoError(t, dsa.GenerateParameters(&params, rand.Reader, dsa.L2048N256))
	dsaKey := &dsa.PrivateKey{PublicKey: dsa.PublicKey{Parameters: params}}
	require.NoError(t, dsa.GenerateKey(dsaKey, rand.Reader))
	dsaBlob := v3Packet(t, false, packet.PubKeyAlgoDSA, data, func(d []byte) [][]byte {
		r, s, err := dsa.Sign(rand.Reader, dsaKey, d)
		require.NoError(t, err)
		return [][]byte{r.Bytes(), s.Bytes()}
	})

	now := time.Now()
	rsaPub := packet.NewRSAPublicKey(now, &rsaKey.PublicKey)
	dsaPub := packet.NewDSAPublicKey(now, &dsaKey.PublicKey)

	for _, c := range []struct {
		blob     []byte
		key, bad *packet.PublicKey
	}{{rsaBlob, rsaPub, dsaPub}, {dsaBlob, dsaPub, rsaPub}} {
		require.True(t, isV3Signature(c.blob))
		s, err := parseV3Signature(c.blob)
		require.NoError(t, err)
		require.Equal(t, uint64(7), s.keyID)

		h := sha256.New()
		h.Write(data)
		require.NoError(t, s.verify(h, c.key))

		h = sha256.New()
		h.Write(data)
		require.ErrorIs(t, s.verify(h, c.bad), ErrBadV3Signature)
	}

	// malformed packets
	for _, bad := range [][]byte{
		nil, {0x01, 0x02}, {0x88, 0}, {0x89, 0}, {0x8a, 0, 0, 0}, {0xc2, 0xe0, 0},
		{0xc2, 0xc0}, {0xc2, 0xff, 0}, {0xc4, 1, 3}, append(bytes.Clone(rsaBlob), 0),
		rsaBlob[:len(rsaBlob)-1],
	} {
		_, err := parseV3Signature(bad)
		require.Error(t, err, "%x", bad)
	}

	mut := func(i int, v byte) []byte {
		b := bytes.Clone(dsaBlob)
		b[3+i] = v
		return b
	}
	for _, b := range [][]byte{mut(0, 4), mut(16, 99), mut(15, 22)} {
		_, err := parseV3Signature(b)
		require.ErrorIs(t, err, ErrBadV3Signature)
	}

	// a two-byte new format length
	short := []byte{0xc2, 0xc0, 0x00}
	short = append(short, make([]byte, 192)...)
	short[3] = 3
	_, err = packetBody(short)
	require.NoError(t, err)
}
