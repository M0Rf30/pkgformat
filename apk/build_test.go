package apk

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sampleSpec() *Spec {
	return &Spec{
		Info: Info{
			Name: "hello", Version: "1.2.3-r0", Arch: "x86_64",
			Description: "Prints a greeting", URL: "https://example.org/hello", License: "MIT",
			Maintainer: "Test <test@example.org>", Packager: "Test <test@example.org>",
			Commit:    "0123456789abcdef0123456789abcdef01234567",
			BuildDate: time.Unix(1700000000, 0),
			Depends:   []string{"busybox>=1.36", "so:libc.musl-x86_64.so.1"},
			Provides:  []string{"cmd:hello=1.2.3-r0"}, Replaces: []string{"old-hello"},
			InstallIf: []string{"docs", "hello=1.2.3-r0"}, ProviderPriority: 10,
			Generator: "pkgformat-test",
		},
		Scripts: Scripts{
			PostInstall: "#!/bin/sh\necho post\n", PostUpgrade: "#!/bin/sh\necho post\n",
			PreDeinstall: "#!/bin/sh\necho bye\n",
		},
		Files: []File{
			{Name: "etc", Mode: fs.ModeDir | 0o755, Uname: "root", Gname: "root"},
			MemFile("etc/hello.conf", 0o644, []byte("x=1\n")),
			{Name: "usr", Mode: fs.ModeDir | 0o755, Uname: "root", Gname: "root"},
			{Name: "usr/bin", Mode: fs.ModeDir | 0o755, Uname: "root", Gname: "root"},
			MemFile("usr/bin/hello", fs.ModeSetuid|0o755, []byte("#!/bin/sh\necho hi\n")),
			{Name: "usr/bin/hi", Mode: fs.ModeSymlink | 0o777, LinkTarget: "hello"},
			{Name: "run-pipe", Mode: fs.ModeNamedPipe | 0o600},
			MemFile("empty", 0o644, nil),
		},
	}
}

func mustWrite(t *testing.T, spec *Spec, opts WriteOptions) ([]byte, *Package) {
	t.Helper()

	var buf bytes.Buffer

	pkg, err := WritePackage(&buf, spec, opts)
	if err != nil {
		t.Fatal(err)
	}

	return buf.Bytes(), pkg
}

func TestWritePackage_roundTrip(t *testing.T) {
	spec := sampleSpec()

	for _, tc := range []struct {
		name   string
		signer *Signer
	}{
		{"unsigned", nil},
		{"signed", testSigner(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, pkg := mustWrite(t, spec, WriteOptions{Signer: tc.signer, TempDir: t.TempDir()})

			got, err := ParsePackage(bytes.NewReader(raw), int64(len(raw)))
			if err != nil {
				t.Fatal(err)
			}

			if !reflect.DeepEqual(got, pkg) {
				t.Fatalf("parsed %+v\nreturned %+v", got, pkg)
			}

			want := Package{
				Name: "hello", Version: "1.2.3-r0", Arch: "x86_64", Description: "Prints a greeting",
				URL: "https://example.org/hello", License: "MIT", Origin: "hello",
				Maintainer: "Test <test@example.org>", Packager: "Test <test@example.org>",
				Commit: "0123456789abcdef0123456789abcdef01234567", BuildTime: 1700000000, InstalledSize: 22,
				Depends:  []string{"busybox>=1.36", "so:libc.musl-x86_64.so.1"},
				Provides: []string{"cmd:hello=1.2.3-r0"}, Replaces: []string{"old-hello"},
				InstallIf: []string{"docs", "hello=1.2.3-r0"}, ProviderPriority: 10,
				DataHash: got.DataHash, Checksum: got.Checksum, Size: int64(len(raw)), Signed: tc.signer != nil,
			}
			if !reflect.DeepEqual(*got, want) {
				t.Fatalf("got  %+v\nwant %+v", *got, want)
			}

			if tc.signer != nil {
				opts := VerifyOptions{Keys: keyringOf(t, tc.signer), Algorithms: []SigAlgorithm{tc.signer.Algorithm()}}
				if _, err := VerifyPackage(bytes.NewReader(raw), int64(len(raw)), opts); err != nil {
					t.Fatalf("verify: %v", err)
				}
			}
		})
	}
}

func keyringOf(t *testing.T, s *Signer) *Keyring {
	t.Helper()

	k := NewKeyring()
	if err := k.Add(s.KeyName(), s.PublicKey()); err != nil {
		t.Fatal(err)
	}

	return k
}

func TestWritePackage_deterministic(t *testing.T) {
	a, _ := mustWrite(t, sampleSpec(), WriteOptions{TempDir: t.TempDir()})
	b, _ := mustWrite(t, sampleSpec(), WriteOptions{TempDir: t.TempDir()})

	if !bytes.Equal(a, b) {
		t.Fatal("two writes of one spec differ")
	}
}

// segments splits a package into its gzip members with the stdlib reader as an
// independent decoder.
func segments(t *testing.T, raw []byte) [][]byte {
	t.Helper()

	var out [][]byte

	br := bytes.NewReader(raw)

	zr, err := gzip.NewReader(br)
	if err != nil {
		t.Fatal(err)
	}

	for {
		zr.Multistream(false)

		data, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}

		out = append(out, data)

		if err := zr.Reset(br); err != nil {
			if errors.Is(err, io.EOF) {
				return out
			}

			t.Fatal(err)
		}
	}
}

func TestWritePackage_layout(t *testing.T) {
	raw, pkg := mustWrite(t, sampleSpec(), WriteOptions{Signer: testSigner(t), TempDir: t.TempDir()})
	segs := segments(t, raw)

	if len(segs) != 3 {
		t.Fatalf("%d gzip members, want signature, control, data", len(segs))
	}

	names := func(b []byte) (out []string) {
		tr := tar.NewReader(bytes.NewReader(b))

		for {
			h, err := tr.Next()
			if err != nil {
				return out
			}

			out = append(out, h.Name)
		}
	}

	if got := names(segs[0]); len(got) != 1 || !strings.HasPrefix(got[0], ".SIGN.RSA256.") {
		t.Fatalf("signature member entries %q", got)
	}

	wantControl := []string{".PKGINFO", ".post-install", ".post-upgrade", ".pre-deinstall"}
	if got := names(segs[1]); !reflect.DeepEqual(got, wantControl) {
		t.Fatalf("control entries %q, want %q", got, wantControl)
	}

	if !bytes.HasPrefix(segs[1], []byte(".PKGINFO")) || bytes.HasSuffix(segs[1], make([]byte, 1024)) {
		t.Fatal("control tar must start with .PKGINFO and carry no end blocks")
	}

	if !bytes.HasSuffix(segs[2], make([]byte, 1024)) {
		t.Fatal("data tar has no end blocks")
	}

	sum := hexSHA256(raw[len(raw)-lenOfData(t, raw):])
	if sum != pkg.DataHash {
		t.Fatalf("datahash %s, hash of the data member %s", pkg.DataHash, sum)
	}

	if got := sha1Checksum(rawControl(t, raw)); got != pkg.Checksum {
		t.Fatalf("checksum %s, want %s", pkg.Checksum, got)
	}

	checkDataTar(t, segs[2])
}

// lenOfData returns the size of the last gzip member of raw.
func lenOfData(t *testing.T, raw []byte) int {
	t.Helper()

	members := memberOffsets(t, raw)

	return len(raw) - members[len(members)-1]
}

// memberOffsets returns where each gzip member of raw starts.
func memberOffsets(t *testing.T, raw []byte) []int {
	t.Helper()

	var offs []int

	pos := 0

	for pos < len(raw) {
		offs = append(offs, pos)

		br := bytes.NewReader(raw[pos:])

		zr, err := gzip.NewReader(br)
		if err != nil {
			t.Fatal(err)
		}

		zr.Multistream(false)

		if _, err := io.Copy(io.Discard, zr); err != nil {
			t.Fatal(err)
		}

		pos += len(raw[pos:]) - br.Len()
	}

	return offs
}

// rawControl returns the compressed control member (the second of three).
func rawControl(t *testing.T, raw []byte) []byte {
	t.Helper()

	offs := memberOffsets(t, raw)

	return raw[offs[1]:offs[2]]
}

func checkDataTar(t *testing.T, data []byte) {
	t.Helper()

	tr := tar.NewReader(bytes.NewReader(data))

	type entry struct {
		typ  byte
		mode int64
		link string
		sha1 string
	}

	got := map[string]entry{}

	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			t.Fatal(err)
		}

		if h.Typeflag == tar.TypeReg && h.Format != tar.FormatPAX {
			t.Errorf("%s: format %v, want PAX", h.Name, h.Format)
		}

		got[h.Name] = entry{h.Typeflag, h.Mode, h.Linkname, h.PAXRecords["APK-TOOLS.checksum.SHA1"]}

		if h.Uname != "" && h.Uname != "root" {
			t.Errorf("%s: uname %q", h.Name, h.Uname)
		}
	}

	hello := sha1.Sum([]byte("#!/bin/sh\necho hi\n"))
	empty := sha1.Sum(nil)
	linkSum := sha1.Sum([]byte("hello"))

	want := map[string]entry{
		"etc/":           {tar.TypeDir, 0o755, "", ""},
		"usr/":           {tar.TypeDir, 0o755, "", ""},
		"usr/bin/":       {tar.TypeDir, 0o755, "", ""},
		"usr/bin/hello":  {tar.TypeReg, 0o4755, "", hex.EncodeToString(hello[:])},
		"usr/bin/hi":     {tar.TypeSymlink, 0o777, "hello", hex.EncodeToString(linkSum[:])},
		"run-pipe":       {tar.TypeFifo, 0o600, "", ""},
		"empty":          {tar.TypeReg, 0o644, "", hex.EncodeToString(empty[:])},
		"etc/hello.conf": {tar.TypeReg, 0o644, "", got["etc/hello.conf"].sha1},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("data entries\ngot  %+v\nwant %+v", got, want)
	}

	if len(got["etc/hello.conf"].sha1) != 40 {
		t.Fatalf("missing the SHA-1 record of etc/hello.conf")
	}
}

func TestWritePackage_scripts(t *testing.T) {
	raw, _ := mustWrite(t, sampleSpec(), WriteOptions{TempDir: t.TempDir()})
	tr := tar.NewReader(bytes.NewReader(segments(t, raw)[0]))

	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}

	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}

	body, _ := io.ReadAll(tr)
	if h.Name != ".post-install" || h.Mode != 0o755 || string(body) != "#!/bin/sh\necho post\n" {
		t.Fatalf("%s mode %o body %q", h.Name, h.Mode, body)
	}
}

func TestWritePackage_infoDefaults(t *testing.T) {
	spec := &Spec{Info: Info{Name: "bare", Version: "1-r0", Arch: "noarch"}}
	raw, pkg := mustWrite(t, spec, WriteOptions{TempDir: t.TempDir()})

	if pkg.Origin != "bare" || pkg.BuildTime != 0 || pkg.InstalledSize != 0 {
		t.Fatalf("defaults: %+v", pkg)
	}

	ctl := segments(t, raw)[0]
	tr := tar.NewReader(bytes.NewReader(ctl))

	if _, err := tr.Next(); err != nil {
		t.Fatal(err)
	}

	text, _ := io.ReadAll(tr)

	for _, absent := range []string{"builddate", "size =", "pkgdesc", "license", "depend", "# Generated"} {
		if strings.Contains(string(text), absent) {
			t.Errorf(".PKGINFO has %q:\n%s", absent, text)
		}
	}

	if !strings.HasPrefix(string(text), "pkgname = bare\npkgver = 1-r0\n") {
		t.Fatalf("unexpected .PKGINFO:\n%s", text)
	}
}

func TestWritePackage_invalid(t *testing.T) {
	for name, mutate := range map[string]func(*Spec){
		"no name":        func(s *Spec) { s.Info.Name = "" },
		"bad name":       func(s *Spec) { s.Info.Name = "a b" },
		"epoch":          func(s *Spec) { s.Info.Version = "1:2.0-r0" },
		"no arch":        func(s *Spec) { s.Info.Arch = "" },
		"newline in url": func(s *Spec) { s.Info.URL = "x\ny" },
		"neg size":       func(s *Spec) { s.Info.InstalledSize = -1 },
		"bad generator":  func(s *Spec) { s.Info.Generator = "a\nb" },
		"dotdot":         func(s *Spec) { s.Files = append(s.Files, MemFile("../x", 0o644, nil)) },
		"absolute":       func(s *Spec) { s.Files = append(s.Files, MemFile("/x", 0o644, nil)) },
		"unclean":        func(s *Spec) { s.Files = append(s.Files, MemFile("usr//x", 0o644, nil)) },
		"control name":   func(s *Spec) { s.Files = append(s.Files, MemFile(".PKGINFO", 0o644, nil)) },
		"script name":    func(s *Spec) { s.Files = append(s.Files, MemFile(".post-install", 0o644, nil)) },
		"duplicate":      func(s *Spec) { s.Files = append(s.Files, MemFile("empty", 0o644, nil)) },
		"socket":         func(s *Spec) { s.Files = append(s.Files, File{Name: "sock", Mode: fs.ModeSocket | 0o600}) },
		"empty link":     func(s *Spec) { s.Files = append(s.Files, File{Name: "l", Mode: fs.ModeSymlink | 0o777}) },
		"neg file size":  func(s *Spec) { s.Files = append(s.Files, File{Name: "n", Mode: 0o644, Size: -1}) },
	} {
		t.Run(name, func(t *testing.T) {
			spec := sampleSpec()
			mutate(spec)

			_, err := WritePackage(io.Discard, spec, WriteOptions{TempDir: t.TempDir()})
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("got %v, want ErrInvalidSpec", err)
			}
		})
	}
}

func TestWritePackage_contentLength(t *testing.T) {
	for name, size := range map[string]int64{"short": 10, "long": 2} {
		t.Run(name, func(t *testing.T) {
			f := MemFile("f", 0o644, []byte("hello"))
			f.Size = size

			spec := &Spec{Info: sampleSpec().Info, Files: []File{f}}

			_, err := WritePackage(io.Discard, spec, WriteOptions{TempDir: t.TempDir()})
			if !errors.Is(err, ErrInvalidSpec) {
				t.Fatalf("got %v, want ErrInvalidSpec", err)
			}
		})
	}
}

func TestWritePackage_openFails(t *testing.T) {
	boom := errors.New("boom")
	f := File{Name: "f", Mode: 0o644, Size: 3, Open: func() (io.ReadCloser, error) { return nil, boom }}

	_, err := WritePackage(io.Discard, &Spec{Info: sampleSpec().Info, Files: []File{f}}, WriteOptions{TempDir: t.TempDir()})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

func TestWritePackage_badTempDir(t *testing.T) {
	_, err := WritePackage(io.Discard, sampleSpec(), WriteOptions{TempDir: filepath.Join(t.TempDir(), "missing")})
	if err == nil {
		t.Fatal("no error for a missing temp dir")
	}
}

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}

	f.after -= len(p)

	return len(p), nil
}

func TestWritePackage_writerFails(t *testing.T) {
	for _, after := range []int{0, 200, 600} {
		if _, err := WritePackage(&failWriter{after}, sampleSpec(), WriteOptions{Signer: testSigner(t), TempDir: t.TempDir()}); err == nil {
			t.Fatalf("after %d bytes: no error", after)
		}
	}
}

func TestWritePackage_modTimeAndOwner(t *testing.T) {
	f := MemFile("f", 0o644, []byte("x"))
	f.ModTime = time.Unix(1234567890, 999)
	f.UID, f.GID, f.Uname, f.Gname = 12, 34, "u", "g"

	raw, _ := mustWrite(t, &Spec{Info: sampleSpec().Info, Files: []File{f}}, WriteOptions{TempDir: t.TempDir()})
	tr := tar.NewReader(bytes.NewReader(segments(t, raw)[1]))

	h, err := tr.Next()
	if err != nil {
		t.Fatal(err)
	}

	if h.ModTime.Unix() != 1234567890 || h.Uid != 12 || h.Gid != 34 || h.Uname != "u" || h.Gname != "g" {
		t.Fatalf("header %+v", h)
	}
}

func TestFilesFromDir(t *testing.T) {
	dir := t.TempDir()

	for _, d := range []string{"usr/bin", "etc"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.WriteFile(filepath.Join(dir, "usr/bin/tool"), []byte("tool"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink("tool", filepath.Join(dir, "usr/bin/alias")); err != nil {
		t.Fatal(err)
	}

	files, err := FilesFromDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}

	if want := []string{"etc", "usr", "usr/bin", "usr/bin/alias", "usr/bin/tool"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("names %q, want %q", names, want)
	}

	raw, pkg := mustWrite(t, &Spec{Info: sampleSpec().Info, Files: files}, WriteOptions{TempDir: t.TempDir()})
	if pkg.InstalledSize != 4 {
		t.Fatalf("size %d", pkg.InstalledSize)
	}

	if _, err := ParsePackage(bytes.NewReader(raw), int64(len(raw))); err != nil {
		t.Fatal(err)
	}

	if _, err := FilesFromDir(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing dir accepted")
	}
}

func TestSignPackage(t *testing.T) {
	s := testSigner(t)
	unsigned, _ := mustWrite(t, sampleSpec(), WriteOptions{TempDir: t.TempDir()})

	var out bytes.Buffer
	if err := SignPackage(&out, bytes.NewReader(unsigned), int64(len(unsigned)), s); err != nil {
		t.Fatal(err)
	}

	direct, _ := mustWrite(t, sampleSpec(), WriteOptions{Signer: s, TempDir: t.TempDir()})
	if !bytes.Equal(out.Bytes(), direct) {
		t.Fatal("SignPackage differs from writing signed")
	}

	if err := SignPackage(io.Discard, bytes.NewReader(direct), int64(len(direct)), s); !errors.Is(err, ErrAlreadySigned) {
		t.Fatalf("got %v, want ErrAlreadySigned", err)
	}

	if err := SignPackage(io.Discard, bytes.NewReader([]byte("junk")), 4, s); !errors.Is(err, ErrInvalidPackage) {
		t.Fatalf("got %v, want ErrInvalidPackage", err)
	}
}

// TestWritePackage_apkTools checks the writer against the real apk tool when
// the host has it.
func TestWritePackage_apkTools(t *testing.T) {
	bin, err := exec.LookPath("apk")
	if err != nil {
		t.Skip("apk is not installed")
	}

	for _, alg := range []SigAlgorithm{SigRSASHA1, SigRSASHA256} {
		t.Run(alg.String(), func(t *testing.T) {
			key := testKey(t)

			s, err := NewSigner("pkgformat-test.rsa.pub", key, alg)
			if err != nil {
				t.Fatal(err)
			}

			dir := t.TempDir()
			keys := filepath.Join(dir, "keys")

			if err := os.Mkdir(keys, 0o755); err != nil {
				t.Fatal(err)
			}

			pemKey, err := s.PublicKeyPEM()
			if err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(filepath.Join(keys, s.KeyName()), pemKey, 0o644); err != nil {
				t.Fatal(err)
			}

			spec := sampleSpec()
			spec.Info.Depends = nil

			raw, pkg := mustWrite(t, spec, WriteOptions{Signer: s, TempDir: dir})
			file := filepath.Join(dir, "hello-1.2.3-r0.apk")

			if err := os.WriteFile(file, raw, 0o644); err != nil {
				t.Fatal(err)
			}

			run := func(args ...string) string {
				t.Helper()

				out, err := exec.Command(bin, args...).CombinedOutput()
				if err != nil {
					t.Fatalf("apk %v: %v\n%s", args, err, out)
				}

				return string(out)
			}

			run("--keys-dir", keys, "verify", file)

			// The index apk computes for the package must be the one we render.
			indexTar := filepath.Join(dir, "index.tar.gz")
			run("--allow-untrusted", "index", "-o", indexTar, file)

			f, err := os.Open(indexTar)
			if err != nil {
				t.Fatal(err)
			}

			defer func() { _ = f.Close() }()

			theirs, err := ParseIndex(f)
			if err != nil {
				t.Fatal(err)
			}

			if len(theirs) != 1 {
				t.Fatalf("apk indexed %d packages", len(theirs))
			}

			want := *pkg
			// apk's index does not carry these.
			want.Packager, want.Replaces, want.DataHash, want.Signed = "", nil, "", false
			theirs[0].DataHash, theirs[0].Signed = "", false

			if !reflect.DeepEqual(theirs[0], want) {
				t.Fatalf("apk index entry\n%+v\nours\n%+v", theirs[0], want)
			}
		})
	}
}
