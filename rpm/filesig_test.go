package rpm

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func readFixturePackage(t *testing.T, name string) *Package {
	t.Helper()

	f, err := os.Open("testdata/filesig/" + name)
	require.NoError(t, err)
	defer f.Close()

	pkg, err := ReadPackage(f)
	require.NoError(t, err)

	return pkg
}

func TestVerifyIMASignatures(t *testing.T) {
	der, err := os.ReadFile("testdata/filesig/ima.der")
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	for _, name := range []string{"ima-v4.rpm", "ima-v6.rpm"} {
		pkg := readFixturePackage(t, name)
		checked := 0

		for _, f := range pkg.Files {
			if f.IMASignature == "" {
				continue
			}

			digest, err := hex.DecodeString(f.Digest)
			require.NoError(t, err)
			require.NoError(t, VerifyIMASignature([]byte(f.IMASignature), digest, cert.PublicKey), f.Path)

			bad := bytes.Clone(digest)
			bad[0] ^= 1
			require.ErrorIs(t, VerifyIMASignature([]byte(f.IMASignature), bad, cert.PublicKey), ErrFileSignature)

			checked++
		}

		require.Positive(t, checked, name)
	}

	_, err = ParseIMASignature([]byte{3, 2, 4, 0, 0, 0, 0, 0, 5, 1})
	require.ErrorIs(t, err, ErrFileSignature)
}

func TestVerifyVeritySignatures(t *testing.T) {
	raw, err := os.ReadFile("testdata/filesig/verity.crt")
	require.NoError(t, err)
	block, _ := pem.Decode(raw)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)

	expected, err := os.ReadFile("testdata/filesig/expected.txt")
	require.NoError(t, err)

	checked := 0

	for _, line := range strings.Split(strings.TrimSpace(string(expected)), "\n") {
		fields := strings.Fields(line)
		pkg := readFixturePackage(t, fields[0])
		want, err := hex.DecodeString(strings.TrimPrefix(fields[1], "sha256:"))
		require.NoError(t, err)

		for _, f := range pkg.Files {
			if f.Path != fields[2] {
				continue
			}

			require.NoError(t, VerifyVeritySignature([]byte(f.VeritySignature), want, pkg.VeritySignatureAlgorithm, []*x509.Certificate{cert}))

			bad := bytes.Clone(want)
			bad[0] ^= 1
			require.ErrorIs(t, VerifyVeritySignature([]byte(f.VeritySignature), bad, pkg.VeritySignatureAlgorithm, []*x509.Certificate{cert}), ErrFileSignature)
			require.ErrorIs(t, VerifyVeritySignature([]byte(f.VeritySignature), want, pkg.VeritySignatureAlgorithm, nil), ErrFileSignature)

			checked++
		}
	}

	require.Equal(t, 2, checked)
}

func TestFSVerityDigestMatchesFsverity(t *testing.T) {
	f, err := os.Open("testdata/filesig/vectors.txt")
	require.NoError(t, err)
	defer f.Close()

	pattern := make([]byte, 251)
	for i := range pattern {
		pattern[i] = byte(i)
	}

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		n, err := strconv.Atoi(fields[0])
		require.NoError(t, err)

		data := bytes.Repeat(pattern, n/251+1)[:n]
		algo := uint32(VeritySHA256)
		if fields[1] == "sha512" {
			algo = VeritySHA512
		}

		got, err := FSVerityDigest(bytes.NewReader(data), algo)
		require.NoError(t, err)
		require.Equal(t, fields[2], fields[1]+":"+hex.EncodeToString(got), sc.Text())
	}

	require.NoError(t, sc.Err())

	_, err = FSVerityDigest(bytes.NewReader(nil), 9)
	require.ErrorIs(t, err, ErrFileSignature)
}

func FuzzFileSignatures(f *testing.F) {
	f.Add([]byte{3, 2, 4, 1, 2, 3, 4, 0, 1, 9})
	f.Add([]byte("MIIB"))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ParseIMASignature(data)
		_ = VerifyVeritySignature(data, make([]byte, 32), VeritySHA256, nil)
	})
}
