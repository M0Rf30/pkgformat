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

package rpm_test

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/pack"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

func ExampleReadRpm() {
	f, err := os.Open("testdata/simple-1.0.1-1.i386.rpm")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pkg, err := rpm.ReadRpm(f)
	if err != nil {
		log.Fatal(err)
	}
	nevra, err := pkg.Header.GetNEVRA()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(nevra)

	// Bound what an untrusted package may expand to, then extract it.
	pkg.SetMaxPayloadSize(1 << 20)
	dest, err := os.MkdirTemp("", "rpm-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dest)
	if err := pkg.ExpandPayload(dest); err != nil {
		log.Fatal(err)
	}
	extracted, err := filepath.Glob(filepath.Join(dest, "*"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(len(extracted) > 0)
	// Output:
	// simple-0:1.0.1-1.i386.rpm
	// true
}

func ExampleRpm_ExpandPayloadWithOptions() {
	f, err := os.Open("testdata/extract/extract-v6.rpm")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	pkg, err := rpm.ReadRpm(f)
	if err != nil {
		log.Fatal(err)
	}
	dest, err := os.MkdirTemp("", "rpm-example")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(dest)
	defer func() { _ = os.Chmod(filepath.Join(dest, "opt/extract-test/ro"), 0o755) }()

	// Drop the set-uid, set-gid and sticky bits and group/other write access.
	if err := pkg.ExpandPayloadWithOptions(dest, &rpm.ExpandOptions{Umask: 07022}); err != nil {
		log.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dest, "opt/extract-test/bin/suid"))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(fi.Mode())
	// Output: -rwxr-xr-x
}

func ExampleVerify() {
	f, err := os.Open("testdata/v6/ref-v6s.rpm")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	// A nil keyring checks digests and exposes the key IDs only.
	_, sigs, err := rpm.Verify(f, nil)
	if err != nil {
		log.Fatal(err)
	}
	for _, sig := range sigs {
		fmt.Printf("%016X header-only=%v\n", sig.KeyId, sig.HeaderOnly)
	}
	// Output:
	// 1E66303A75B7A873 header-only=true
}

// A package written with the pack package can be read back with this one.
func Example_roundTrip() {
	w, err := pack.NewRPM(pack.RPMMetaData{Name: "example", Version: "3", Release: "1", Format: pack.FormatV6})
	if err != nil {
		log.Fatal(err)
	}
	w.AddFile(pack.RPMFile{Name: "/usr/share/example/hello", Body: []byte("hello"), Mode: 0o644, Owner: "root", Group: "root"})
	var buf bytes.Buffer
	if err := w.Write(&buf); err != nil {
		log.Fatal(err)
	}

	pkg, err := rpm.ReadRpm(&buf)
	if err != nil {
		log.Fatal(err)
	}
	files, err := pkg.Header.GetStrings(tag.BASENAMES)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("format", pkg.Header.Format(), files)
	// Output: format 6 [hello]
}

// SignRpmStream signs a package without rewriting it: the new lead and signature
// header replace the old ones, the rest of the package is copied.
func ExampleSignRpmStream() {
	pkg, err := os.ReadFile("testdata/empty-0.1-1.x86_64.rpm")
	if err != nil {
		log.Fatal(err)
	}
	key, err := openpgp.NewEntity("example", "", "example@example.com", nil)
	if err != nil {
		log.Fatal(err)
	}

	hdr, err := rpm.SignRpmStream(bytes.NewReader(pkg), key.PrivateKey, nil)
	if err != nil {
		log.Fatal(err)
	}
	head, err := hdr.DumpSignatureHeader(false)
	if err != nil {
		log.Fatal(err)
	}
	signed := append(head, pkg[hdr.OriginalSignatureHeaderSize():]...)

	_, sigs, err := rpm.Verify(bytes.NewReader(signed), openpgp.EntityList{key})
	if err != nil {
		log.Fatal(err)
	}
	// An unsigned package verifies with no signatures: check len(sigs).
	fmt.Println(len(sigs), "signatures")
	// Output: 2 signatures
}
