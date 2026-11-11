package rpm

import (
	"bytes"
	"os"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

const v3Package = "testdata/v3sig/basesystem-10.0-7.el7.centos.noarch.rpm"

func TestVerifyV3Signatures(t *testing.T) {
	keyring, err := gpg.LoadKeyringFile("testdata/v3sig/RPM-GPG-KEY-CentOS-7")
	require.NoError(t, err)

	raw, err := os.ReadFile(v3Package)
	require.NoError(t, err)

	_, sigs, err := VerifyWithKeyring(bytes.NewReader(raw), keyring, &VerifyOptions{RequireSigned: true})
	require.NoError(t, err)
	require.Len(t, sigs, 2)

	for _, s := range sigs {
		require.Equal(t, uint64(0x24c6a8a7f4a80eb5), s.KeyId)
		require.Equal(t, 2014, s.CreationTime.Year())
		require.NotNil(t, s.Signer)
	}

	other, err := gpg.GenerateEntity("x", "", "x@example.com", gpg.AlgorithmED25519)
	require.NoError(t, err)

	_, _, err = VerifyWithOptions(bytes.NewReader(raw), openpgp.EntityList{other}, nil)
	require.ErrorAs(t, err, &KeyNotFoundError{})
}

func TestV3SignatureRejectsAlteredSignature(t *testing.T) {
	keyring, err := gpg.LoadKeyringFile("testdata/v3sig/RPM-GPG-KEY-CentOS-7")
	require.NoError(t, err)

	f, err := os.Open(v3Package)
	require.NoError(t, err)
	defer f.Close()

	hdr, err := ReadHeader(f)
	require.NoError(t, err)

	blob, err := hdr.sigHeader.GetBytes(tag.SIG_RSA)
	require.NoError(t, err)

	sig, err := parseV3Signature(blob)
	require.NoError(t, err)

	key := keyring.Entities()[0].PrimaryKey

	good := sig.hash.New()
	good.Write(hdr.genHeader.orig)
	require.NoError(t, sig.verify(good, key))

	sig.mpis[0] = bytes.Clone(sig.mpis[0])
	sig.mpis[0][10] ^= 0xff

	bad := sig.hash.New()
	bad.Write(hdr.genHeader.orig)
	require.ErrorIs(t, sig.verify(bad, key), ErrBadV3Signature)

	other := sig.hash.New()
	other.Write([]byte("other data"))
	require.ErrorIs(t, sig.verify(other, key), ErrBadV3Signature)
}

func FuzzParseV3Signature(f *testing.F) {
	h, err := os.Open(v3Package)
	require.NoError(f, err)

	hdr, err := ReadHeader(h)
	require.NoError(f, err)
	require.NoError(f, h.Close())

	blob, err := hdr.sigHeader.GetBytes(tag.SIG_RSA)
	require.NoError(f, err)

	f.Add(blob)
	f.Fuzz(func(_ *testing.T, data []byte) {
		if s, err := parseV3Signature(data); err == nil {
			_ = s.asSignature()
		}
	})
}
