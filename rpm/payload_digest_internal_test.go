package rpm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDigestCheckReaderMismatch(t *testing.T) {
	// The header digest is protected by the header checksums, so a mismatch
	// can only come from a payload that differs from the signed one: model it
	// with a hasher expecting another digest.
	for _, want := range []struct {
		digest string
		err    error
	}{
		{"0000", ErrPayloadDigest},
		{"", nil},
	} {
		compressed := strings.NewReader("compressed bytes")
		h := &payloadHasher{r: compressed, h: sha256.New(), want: want.digest}

		if want.digest == "" {
			sum := sha256.Sum256([]byte("compressed bytes"))
			h.want = hex.EncodeToString(sum[:])
		}

		// The decompressor stops after "compressed"; the rest is drained.
		head := make([]byte, len("compressed"))
		_, err := io.ReadFull(h, head)
		require.NoError(t, err)

		d := &digestCheckReader{r: bytes.NewReader([]byte("cpio")), h: h}
		require.ErrorIs(t, verifyPayloadEnd(d), want.err)
	}
}
