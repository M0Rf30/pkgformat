/*
 * Copyright (c) SAS Institute, Inc.
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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/M0Rf30/pkgformat/rpm/tag"
	"github.com/ProtonMail/go-crypto/openpgp"
)

// fuzzPayloadLimit bounds decompression output while fuzzing so that a
// generated decompression bomb cannot stall the fuzzer.
const fuzzPayloadLimit = 4 << 20

// addSeedRPMs seeds the corpus with every RPM under testdata.
func addSeedRPMs(f *testing.F) {
	f.Helper()
	for _, pattern := range []string{"testdata/*.rpm", "testdata/*/*.rpm"} {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			f.Fatal(err)
		}
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				f.Fatal(err)
			}
			f.Add(data)
		}
	}
}

// touchHeader calls every accessor that parses header contents.
func touchHeader(hdr *RpmHeader) {
	_, _ = hdr.GetNEVRA()
	_, _ = hdr.GetFiles()
	_, _ = hdr.PayloadSize()
	_, _ = hdr.InstalledSize()
	_ = hdr.Format()
	_ = hdr.GetRange()
	for _, id := range []int{tag.NAME, tag.EPOCH, tag.VERSION, tag.FILESIZES, tag.FILEMODES, tag.BASENAMES, tag.OLDFILENAMES, tag.PROVIDENAME, tag.SIG_SHA1, tag.SIG_SHA256, tag.SIG_RSA, tag.SIG_PGP, tag.SIG_PAYLOADSIZE} {
		_ = hdr.HasTag(id)
		_, _ = hdr.Get(id)
		_, _ = hdr.GetStrings(id)
		_, _ = hdr.GetInts(id)
		_, _ = hdr.GetUint32s(id)
		_, _ = hdr.GetUint64s(id)
		_, _ = hdr.GetBytes(id)
	}
	_, _ = hdr.DumpSignatureHeader(true)
	_, _ = hdr.DumpSignatureHeader(false)
}

func FuzzReadHeader(f *testing.F) {
	addSeedRPMs(f)
	f.Fuzz(func(_ *testing.T, data []byte) {
		hdr, err := ReadHeader(bytes.NewReader(data))
		if err != nil {
			return
		}
		touchHeader(hdr)
	})
}

func FuzzReadRpm(f *testing.F) {
	addSeedRPMs(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		rpm, err := ReadRpm(bytes.NewReader(data))
		if err != nil {
			return
		}
		touchHeader(rpm.Header)
		rpm.SetMaxPayloadSize(fuzzPayloadLimit)
		dest := removableTempDir(t)
		_ = rpm.ExpandPayload(dest)

		// the same package with every optional behaviour enabled
		rpm2, err := ReadRpm(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		rpm2.SetMaxPayloadSize(fuzzPayloadLimit)
		_ = rpm2.ExpandPayloadWithOptions(removableTempDir(t), &ExpandOptions{
			Umask: 07022, Chown: true, SpecialFiles: true, SkipDigests: true,
		})
	})
}

// removableTempDir is t.TempDir for trees whose directories may have been
// given modes that prevent removing them.
func removableTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(p, 0o755)
			}
			return nil
		})
	})
	return dir
}

func FuzzPayloadReaderExtended(f *testing.F) {
	addSeedRPMs(f)
	f.Fuzz(func(_ *testing.T, data []byte) {
		rpm, err := ReadRpm(bytes.NewReader(data))
		if err != nil {
			return
		}
		rpm.SetMaxPayloadSize(fuzzPayloadLimit)
		pr, err := rpm.PayloadReaderExtended()
		if err != nil {
			return
		}
		for {
			fi, err := pr.Next()
			if err != nil {
				return
			}
			_ = pr.IsLink()
			_, _ = fi.Name(), fi.Size()
			if _, err := io.Copy(io.Discard, pr); err != nil {
				return
			}
		}
	})
}

func FuzzVerify(f *testing.F) {
	keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewReader([]byte(testkey)))
	if err != nil {
		f.Fatal(err)
	}
	addSeedRPMs(f)
	// a signed package, so that the signature parsing paths are reached
	signed := func(path string) {
		in, err := os.Open(path)
		if err != nil {
			f.Fatal(err)
		}
		defer in.Close()
		h, err := SignRpmStream(in, keyring[0].PrivateKey, &SignatureOptions{})
		if err != nil {
			f.Fatal(err)
		}
		sigblob, err := h.DumpSignatureHeader(false)
		if err != nil {
			f.Fatal(err)
		}
		if _, err := in.Seek(int64(h.OriginalSignatureHeaderSize()), io.SeekStart); err != nil {
			f.Fatal(err)
		}
		rest, err := io.ReadAll(in)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(append(sigblob, rest...))
	}
	signed("testdata/simple-1.0.1-1.i386.rpm")
	signed("testdata/nfpm/test-1.0.0.x86_64.rpm")
	signed("testdata/v6/ref-v6.rpm")

	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _, _ = Verify(bytes.NewReader(data), keyring)
		_, _, _ = Verify(bytes.NewReader(data), nil)
	})
}
