package apk

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/M0Rf30/pkgformat/apk/adb"
)

func TestParsePackageReadsV3(t *testing.T) {
	for _, name := range []string{"full.apk", "signed-rsa.apk", "tree-zstd3.apk", "tree-deflate9.apk", "tree-none.apk"} {
		raw, err := os.ReadFile("adb/testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}

		got, err := ParsePackage(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		want, err := adb.ParsePackage(bytes.NewReader(raw), adb.ReadOptions{})
		if err != nil {
			t.Fatal(err)
		}

		if got.Format != FormatV3 || got.Format.String() != "v3" || got.Name != want.Info.Name ||
			got.Version != want.Info.Version || got.Arch != want.Info.Arch ||
			got.Size != int64(len(raw)) || !bytes.Equal(got.Hashes, want.Info.Hashes) ||
			len(got.Depends) != len(want.Info.Depends) || len(got.Triggers) != len(want.Triggers) {
			t.Errorf("%s: %+v does not match %+v", name, got, want.Info)
		}
	}
}

func TestParsePackageV3Errors(t *testing.T) {
	raw, err := os.ReadFile("adb/testdata/full.apk")
	if err != nil {
		t.Fatal(err)
	}

	cut := raw[:len(raw)/2]
	if _, err := ParsePackage(bytes.NewReader(cut), int64(len(cut))); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("truncated v3 package: %v", err)
	}

	if isADB(bytes.NewReader([]byte("AD")), 2) || isADB(bytes.NewReader([]byte("ADBx")), 4) {
		t.Fatal("not ADB")
	}

	if FormatV2.String() != "v2" {
		t.Fatal(FormatV2.String())
	}
}
