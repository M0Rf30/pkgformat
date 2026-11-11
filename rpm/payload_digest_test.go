package rpm_test

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/M0Rf30/pkgformat/rpm"
)

func TestVerifyPayloadDigest(t *testing.T) {
	for _, name := range []string{"testdata/meta/meta-v4.rpm", "testdata/meta/meta-v6.rpm"} {
		raw, err := os.ReadFile(name)
		require.NoError(t, err)

		read := func(data []byte) error {
			r, err := rpm.ReadRpm(bytes.NewReader(data))
			require.NoError(t, err)
			r.SetVerifyPayloadDigest(true)

			pr, err := r.PayloadReaderExtended()
			if err != nil {
				return err
			}

			for {
				if _, err := pr.Next(); err != nil {
					if errors.Is(err, io.EOF) {
						return nil
					}

					return err
				}

				if _, err := io.Copy(io.Discard, pr); err != nil {
					return err
				}
			}
		}

		require.NoError(t, read(raw), name)

		pkg, err := rpm.ReadPackage(bytes.NewReader(raw))
		require.NoError(t, err)
		require.NotEmpty(t, pkg.PayloadDigests, name)
	}
}
