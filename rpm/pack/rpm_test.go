package pack

import (
	"bytes"
	"errors"
	"io"
	"math"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
	"github.com/klauspost/compress/zstd"
	gzip "github.com/klauspost/pgzip"
	"github.com/ulikunitz/xz"
	"github.com/ulikunitz/xz/lzma"
)

func TestFileOwner(t *testing.T) {
	r, err := NewRPM(RPMMetaData{})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}
	group := "testGroup"
	user := "testUser"

	r.AddFile(RPMFile{
		Name:  "/usr/local/hello",
		Body:  []byte("content of the file"),
		Group: group,
		Owner: user,
	})

	if err := r.Write(io.Discard); err != nil {
		t.Errorf("NewRPM returned error %v", err)
	}
	if entriesOf(t, r)[0].Owner != user {
		t.Errorf("File owner shoud be %s but is %s", user, entriesOf(t, r)[0].Owner)
	}
	if entriesOf(t, r)[0].Group != group {
		t.Errorf("File owner shoud be %s but is %s", group, entriesOf(t, r)[0].Group)
	}
}

// Test100644 checks that a mode that carries the regular file type bits is accepted.
func Test100644(t *testing.T) {
	r, err := NewRPM(RPMMetaData{})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}
	r.AddFile(RPMFile{
		Name: "/usr/local/hello",
		Body: []byte("content of the file"),
		Mode: 0100644,
	})

	if err := r.Write(io.Discard); err != nil {
		t.Errorf("Write returned error %v", err)
	}
	if entriesOf(t, r)[0].Mode != 0100644 {
		t.Errorf("file mode want 0100644, got %o", entriesOf(t, r)[0].Mode)
	}
	if e := entriesOf(t, r)[0]; e.isLink() || e.Body != nil && false {
		t.Errorf("%q must not be a symlink", e.Name)
	}
}

func TestCompression(t *testing.T) {
	testCases := []struct {
		Type           string
		Compressors    []string
		ExpectedWriter io.Writer
	}{
		{
			Type: "gzip",
			Compressors: []string{
				"", "gzip", "gzip:1", "gzip:2", "gzip:3",
				"gzip:4", "gzip:5", "gzip:6", "gzip:7", "gzip:8", "gzip:9",
			},
			ExpectedWriter: &gzip.Writer{},
		},
		{
			Type:           "gzip",
			Compressors:    []string{"gzip:fast", "gzip:10"},
			ExpectedWriter: nil, // gzip requires an integer level from -2 to 9
		},
		{
			Type:           "lzma",
			Compressors:    []string{"lzma"},
			ExpectedWriter: &lzma.Writer{},
		},
		{
			Type:           "lzma",
			Compressors:    []string{"lzma:fast", "lzma:1"},
			ExpectedWriter: nil, // lzma does not support specifying the compression level
		},
		{
			Type:           "xz",
			Compressors:    []string{"xz"},
			ExpectedWriter: &xz.Writer{},
		},
		{
			Type:           "xz",
			Compressors:    []string{"xz:fast", "xz:1"},
			ExpectedWriter: nil, // xz does not support specifying the compression level
		},
		{
			Type: "zstd",
			Compressors: []string{
				"zstd", "zstd:fastest", "zstd:default", "zstd:better",
				"zstd:best", "zstd:BeSt", "zstd:0", "zstd:4", "zstd:8", "zstd:15",
			},
			ExpectedWriter: &zstd.Encoder{},
		},
		{
			Type:           "zstd",
			Compressors:    []string{"xz:worst"},
			ExpectedWriter: nil, // only integers levels or one of the pre-defined string values
		},
	}

	for _, testCase := range testCases {
		for _, compressor := range testCase.Compressors {
			t.Run(compressor, func(t *testing.T) {
				r, err := NewRPM(RPMMetaData{
					Compressor: compressor,
				})
				if err != nil {
					if testCase.ExpectedWriter == nil {
						return // an error is expected
					}

					t.Fatalf("NewRPM returned error %v", err)
				}

				if testCase.ExpectedWriter == nil {
					t.Fatalf("compressor %q should have produced an error", compressor)
				}

				if r.Compressor != testCase.Type {
					t.Fatalf("expected compressor %q, got %q", compressor,
						r.Compressor)
				}

				expectedWriterType := reflect.Indirect(reflect.ValueOf(
					testCase.ExpectedWriter)).String()
				actualWriterType := reflect.Indirect(reflect.ValueOf(
					compressorWriter(t, r))).String()

				if expectedWriterType != actualWriterType {
					t.Fatalf("expected writer to be %T, got %T instead",
						testCase.ExpectedWriter, compressorWriter(t, r))
				}
			})
		}
	}
}

func TestAllowListDirs(t *testing.T) {
	r, err := NewRPM(RPMMetaData{})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}

	r.AddFile(RPMFile{
		Name: "/usr/local/dir1",
		Mode: 040000,
	})
	r.AddFile(RPMFile{
		Name: "/usr/local/dir2",
		Mode: 040000,
	})

	r.AllowListDirs(map[string]bool{"/usr/local/dir1": true})

	if err := r.Write(io.Discard); err != nil {
		t.Errorf("NewRPM returned error %v", err)
	}
	expected := map[string]RPMFile{"/usr/local/dir1": {Name: "/usr/local/dir1", Mode: 040000}}
	if d := cmp.Diff(expected, r.files); d != "" {
		t.Errorf("Expected dirs differs (want->got):\n%v", d)
	}
}

func TestMinimalSpec(t *testing.T) {
	r, err := NewRPM(RPMMetaData{
		Name:        "test",
		Version:     "1.0",
		Release:     "1",
		Summary:     "test summary",
		Description: "test description",
		Licence:     "test license",
	})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}

	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Errorf("Write returned error %v", err)
	}
}

func TestChangelog(t *testing.T) {
	r, err := NewRPM(RPMMetaData{
		Name:    "test",
		Version: "1.0",
		Release: "1",
		Changelog: []ChangelogEntry{
			{Time: time.Unix(1700000000, 0), Author: "Test User <test@example.com>", Text: "- Initial release"},
			{Time: time.Unix(1699000000, 0), Author: "Test User <test@example.com>", Text: "- Pre-release"},
		},
	})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}

	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Errorf("Write returned error %v", err)
	}
}

func TestEnhancesSupplements(t *testing.T) {
	r, err := NewRPM(RPMMetaData{
		Name:    "test",
		Version: "1.0",
		Release: "1",
	})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}

	r.Enhances = append(r.Enhances, &Relation{
		Name:  "enhanced-package",
		Sense: SenseEqual,
	})
	r.Supplements = append(r.Supplements, &Relation{
		Name:  "supplemented-package",
		Sense: SenseEqual,
	})

	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Errorf("Write returned error %v", err)
	}
}

func TestDistributionBugURL(t *testing.T) {
	r, err := NewRPM(RPMMetaData{
		Name:         "test",
		Version:      "1.0",
		Release:      "1",
		Distribution: "Fedora",
		BugURL:       "https://bugzilla.example.com",
	})
	if err != nil {
		t.Fatalf("NewRPM returned error %v", err)
	}

	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Errorf("Write returned error %v", err)
	}
}

func TestWriteTwice(t *testing.T) {
	r, err := NewRPM(RPMMetaData{Name: "twice", Version: "1"})
	if err != nil {
		t.Fatal(err)
	}
	r.AddFile(RPMFile{Name: "/a", Body: []byte("a"), Mode: 0644})
	if err := r.Write(io.Discard); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if err := r.Write(io.Discard); !errors.Is(err, ErrWriteAfterClose) {
		t.Errorf("second Write error = %v, want ErrWriteAfterClose", err)
	}
}

func TestWriteRejectsInvalidFile(t *testing.T) {
	big := func() []byte {
		if strconv.IntSize < 64 {
			t.Skip("needs a 4 GiB slice")
		}
		// The pages are never touched, so this only reserves address space.
		return make([]byte, maxV4FileSize+1)
	}
	testCases := []struct {
		name   string
		file   func() RPMFile
		format int
		wantOK bool
	}{
		{name: "relative", file: func() RPMFile { return RPMFile{Name: "usr/bin/x"} }},
		{name: "empty", file: func() RPMFile { return RPMFile{Name: ""} }},
		{name: "dotdot", file: func() RPMFile { return RPMFile{Name: "/usr/../etc/passwd"} }},
		{name: "dot", file: func() RPMFile { return RPMFile{Name: "/usr/./bin"} }},
		{name: "double slash", file: func() RPMFile { return RPMFile{Name: "/usr//bin"} }},
		{name: "trailing slash", file: func() RPMFile { return RPMFile{Name: "/usr/bin/", Mode: 040755} }},
		{name: "NUL in name", file: func() RPMFile { return RPMFile{Name: "/usr/bin/x\x00y"} }},
		{name: "NUL in owner", file: func() RPMFile { return RPMFile{Name: "/x", Owner: "ro\x00ot"} }},
		{name: "NUL in group", file: func() RPMFile { return RPMFile{Name: "/x", Group: "ro\x00ot"} }},
		{name: "NUL in symlink target", file: func() RPMFile {
			return RPMFile{Name: "/x", Mode: 0120777, Body: []byte("a\x00b")}
		}},
		{name: "empty symlink target", file: func() RPMFile { return RPMFile{Name: "/x", Mode: 0120777} }},
		{name: "bad file type", file: func() RPMFile { return RPMFile{Name: "/x", Mode: 030644} }},
		{name: "fifo", wantOK: true, file: func() RPMFile { return RPMFile{Name: "/x", Mode: 010644} }},
		{name: "mode over 16 bits", file: func() RPMFile { return RPMFile{Name: "/x", Mode: 1 << 16} }},
		{name: "v4 file over 4 GiB", file: func() RPMFile { return RPMFile{Name: "/x", Mode: 0644, Body: big()} }},
		{name: "v4 ghost over 4 GiB", file: func() RPMFile {
			return RPMFile{Name: "/x", Mode: 0644, Body: big(), Type: GhostFile}
		}},
		{name: "v6 file over 4 GiB is allowed", format: FormatV6, wantOK: true, file: func() RPMFile {
			return RPMFile{Name: "/x", Mode: 0644, Body: big()}
		}},
		{name: "clean absolute", wantOK: true, file: func() RPMFile { return RPMFile{Name: "/usr/bin/x", Mode: 0755} }},
		{name: "NUL in regular file body is fine", wantOK: true, file: func() RPMFile {
			return RPMFile{Name: "/x", Mode: 0644, Body: []byte("a\x00b")}
		}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRPM(RPMMetaData{Name: "x", Version: "1", Format: tc.format})
			if err != nil {
				t.Fatal(err)
			}
			f := tc.file()
			r.AddFile(f)
			err = r.validateFile(f)
			if tc.wantOK {
				if err != nil {
					t.Errorf("validateFile: %v", err)
				}
				return
			}
			if !errors.Is(err, ErrInvalidFile) {
				t.Fatalf("validateFile error = %v, want ErrInvalidFile", err)
			}
			if err := r.Write(io.Discard); !errors.Is(err, ErrInvalidFile) {
				t.Errorf("Write error = %v, want ErrInvalidFile", err)
			}
			// A failed validation must not consume the rpm.
			delete(r.files, f.Name)
			if err := r.Write(io.Discard); err != nil {
				t.Errorf("Write after removing the invalid file: %v", err)
			}
		})
	}
}

func TestWriteRejectsInvalidMetadata(t *testing.T) {
	testCases := []struct {
		name string
		edit func(r *RPM)
	}{
		{name: "NUL in name", edit: func(r *RPM) { r.Name = "a\x00b" }},
		{name: "NUL in summary", edit: func(r *RPM) { r.Summary = "a\x00b" }},
		{name: "NUL in prefix", edit: func(r *RPM) { r.Prefixes = []string{"/a\x00b"} }},
		{name: "NUL in scriptlet", edit: func(r *RPM) { r.AddPostin("a\x00b") }},
		{name: "NUL in changelog", edit: func(r *RPM) {
			r.Changelog = []ChangelogEntry{{Time: time.Unix(1, 0), Author: "a", Text: "b\x00"}}
		}},
		{name: "NUL in relation", edit: func(r *RPM) { r.Requires = Relations{{Name: "a\x00b"}} }},
		{name: "nil relation", edit: func(r *RPM) { r.Conflicts = Relations{nil} }},
		{name: "build time before 1970", edit: func(r *RPM) { r.BuildTime = time.Unix(-1, 0) }},
		{name: "build time after 2106", edit: func(r *RPM) { r.BuildTime = time.Unix(math.MaxUint32+1, 0) }},
		{name: "changelog time before 1970", edit: func(r *RPM) {
			r.Changelog = []ChangelogEntry{{Time: time.Unix(-1, 0)}}
		}},
		{name: "zero changelog time", edit: func(r *RPM) { r.Changelog = []ChangelogEntry{{}} }},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := NewRPM(RPMMetaData{Name: "x", Version: "1"})
			if err != nil {
				t.Fatal(err)
			}
			tc.edit(r)
			if err := r.Write(io.Discard); !errors.Is(err, ErrInvalidMetadata) {
				t.Errorf("Write error = %v, want ErrInvalidMetadata", err)
			}
		})
	}
}

// Times past 2038 do not fit a signed 32 bit time, but rpm reads them as unsigned.
func TestWriteTimesPast2038(t *testing.T) {
	const ts = int64(1) << 31 // 2038-01-19
	r, err := NewRPM(RPMMetaData{
		Name: "x", Version: "1", BuildTime: time.Unix(ts, 0),
		Changelog: []ChangelogEntry{{Time: time.Unix(ts+1, 0), Author: "a", Text: "b"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := r.Write(&b); err != nil {
		t.Fatal(err)
	}
	p := parseRPM(t, b.Bytes())
	if got := p.main.ints(t, tag.BUILDTIME, tag.RPM_INT32_TYPE); len(got) != 1 || got[0] != uint64(ts) {
		t.Errorf("build time = %v, want %d", got, ts)
	}
	if got := p.main.ints(t, tag.CHANGELOGTIME, tag.RPM_INT32_TYPE); len(got) != 1 || got[0] != uint64(ts+1) {
		t.Errorf("changelog time = %v, want %d", got, ts+1)
	}
}

func TestAddInstalledSize(t *testing.T) {
	for _, tc := range []struct {
		size  uint64
		short bool
	}{{1 << 20, true}, {3 << 30, true}, {math.MaxUint32, true}, {5 << 30, false}} {
		h := rpmhdr.NewIndex(tag.RPMTAG_HEADERIMMUTABLE)
		addInstalledSize(h, tc.size)
		_, hasSize := h.Entries[tag.SIZE]
		_, hasLong := h.Entries[tag.LONGSIZE]
		if hasSize != tc.short || hasLong == tc.short {
			t.Errorf("size %d: SIZE=%v LONGSIZE=%v, want the 32 bit tag: %v", tc.size, hasSize, hasLong, tc.short)
		}
	}
}

func TestAddSignatureSizes(t *testing.T) {
	s := rpmhdr.NewIndex(tag.RPMTAG_HEADERSIGNATURES)
	addSignatureSizes(s, math.MaxUint32+1, math.MaxUint32)
	if _, ok := s.Entries[tag.SIG_LONGSIGSIZE]; !ok {
		t.Error("want LONGSIGSIZE for a size over 4 GiB")
	}
	if _, ok := s.Entries[(tag.SIG_SIZE - tag.SIGHEADER_TAG_BASE)]; ok {
		t.Error("SIG_SIZE must not be set along with LONGSIGSIZE")
	}
	if _, ok := s.Entries[(tag.SIG_PAYLOADSIZE - tag.SIGHEADER_TAG_BASE)]; !ok {
		t.Error("want SIG_PAYLOADSIZE for a size of 4 GiB - 1")
	}
}
