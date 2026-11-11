package repodata

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	helloSHA = "48131ebba95c88df0e452931707a42dfdfd0c3c2832522c1c686a82449d45dab"
	filesSHA = "9ce47f4720a1d2348899eb9d6baf4f4f89fbb2d69d800bfc030046f28f497481"
)

func utc(y int, m time.Month, d, h, mi, s int) time.Time {
	return time.Date(y, m, d, h, mi, s, 0, time.UTC)
}

// modelAdvisories are the advisories testdata/updateinfo/ground_truth.py
// feeds to createrepo_c's writer to produce testdata/updateinfo/model.xml.
func modelAdvisories() []Advisory {
	return []Advisory{{
		ID: "FEDORA-2026-1f3a9c0b52", Title: "hello-test-1.0.0-1.fc45", Type: "security", Severity: "Important",
		Status: "stable", Version: "2.0", From: "updates@fedoraproject.org",
		Issued: utc(2026, 3, 13, 21, 14, 55), Updated: utc(2026, 3, 22, 0, 52, 45),
		Release: "Fedora 45", Rights: "Copyright (C) 2026 Red Hat, Inc. and others.",
		Summary: "hello-test-1.0.0-1.fc45 security update",
		Description: "Fix a heap overflow in the greeting parser (CVE-2026-0001).\n\n" +
			"The parser trusted the length of a <greeting> & wrote past the buffer.",
		RebootSuggested: true,
		References: []AdvisoryReference{
			{
				Href: "https://bugzilla.redhat.com/show_bug.cgi?id=2400001", ID: "2400001", Type: "bugzilla",
				Title: "CVE-2026-0001 hello-test: heap overflow in the greeting parser",
			},
			{
				Href: "https://bodhi.fedoraproject.org/updates/FEDORA-2026-1f3a9c0b52",
				ID:   "FEDORA-2026-1f3a9c0b52", Type: "self", Title: "FEDORA-2026-1f3a9c0b52",
			},
		},
		Collections: []AdvisoryCollection{{
			Short: "F45", Name: "Fedora 45",
			Packages: []AdvisoryPackage{{
				Name: "hello-test", Version: "1.0.0", Release: "1", Epoch: "0", Arch: "noarch",
				Src:      "https://download.fedoraproject.org/pub/fedora/linux/updates/45/SRPMS/h/hello-test-1.0.0-1.fc45.src.rpm",
				Filename: "hello-test-1.0.0-1.noarch.rpm", Sum: AdvisorySum{Type: "sha256", Value: helloSHA},
				RebootSuggested: true, RestartSuggested: true, ReloginSuggested: true,
			}},
		}},
	}, {
		ID: "RLBA-2026:0001", Title: "files-test and weakdep-test bug fix update", Type: "bugfix", Severity: "None",
		Status: "final", Version: "2", From: "releng@rockylinux.org",
		Issued: utc(2026, 1, 20, 9, 30, 0), Updated: utc(2026, 2, 2, 12, 0, 0),
		Release: "Rocky Linux 9", Rights: "Copyright 2026 Rocky Enterprise Software Foundation. © Red Hat, Inc.",
		Summary: "An update is available for files-test and weakdep-test.",
		Description: "Both packages were rebuilt with the new macros.\n" +
			"  * files-test ships the missing directory\n  * weakdep-test keeps its weak dependencies",
		Solution: "Update the packages with dnf update.", PushCount: "1",
		References: []AdvisoryReference{{
			Href: "https://errata.rockylinux.org/RLBA-2026:0001", ID: "RLBA-2026:0001", Type: "self", Title: "RLBA-2026:0001",
		}},
		Collections: []AdvisoryCollection{{
			Short: "rocky-linux-9-x86-64-baseos-rpms", Name: "rocky-linux-9-x86-64-baseos-rpms",
			Packages: []AdvisoryPackage{{
				Name: "files-test", Version: "2.1", Release: "3", Epoch: "0", Arch: "noarch",
				Src: "files-test-2.1-3.src.rpm", Filename: "files-test-2.1-3.noarch.rpm",
				Sum: AdvisorySum{Type: "sha256", Value: filesSHA},
			}, {
				Name: "weakdep-test", Version: "1.0", Release: "1", Epoch: "1", Arch: "noarch",
				Src: "weakdep-test-1.0-1.src.rpm", Filename: "weakdep-test-1.0-1.noarch.rpm",
			}},
		}},
	}, {
		ID: "RLSA-2026:0002", Title: "Moderate: nodejs:20 security update", Type: "security", Severity: "Moderate",
		Status: "final", Version: "2", From: "releng@rockylinux.org",
		Issued:  utc(2026, 4, 1, 8, 0, 0),
		Release: "Rocky Linux 9", Rights: "Copyright 2026 Rocky Enterprise Software Foundation.",
		Summary:     "An update for the nodejs:20 module is available.",
		Description: "Security fix for the nodejs:20 module stream.", PushCount: "2",
		References: []AdvisoryReference{{
			Href: "https://access.redhat.com/security/cve/CVE-2026-0002", ID: "CVE-2026-0002", Type: "cve", Title: "CVE-2026-0002",
		}},
		Collections: []AdvisoryCollection{{
			Short: "rocky-linux-9-x86-64-appstream-rpms", Name: "rocky-linux-9-x86-64-appstream-rpms",
			Module: &AdvisoryModule{Name: "nodejs", Stream: "20", Version: 9060020260401080000, Context: "rhel9", Arch: "x86_64"},
			Packages: []AdvisoryPackage{{
				Name: "nodejs", Version: "20.11.1", Release: "1.module+el9.6.0+1+abcdef01", Epoch: "1", Arch: "x86_64",
				Src:      "nodejs-20.11.1-1.module+el9.6.0+1+abcdef01.src.rpm",
				Filename: "nodejs-20.11.1-1.module+el9.6.0+1+abcdef01.x86_64.rpm",
			}},
		}, {
			Short: "empty", Name: "A collection without packages",
		}},
	}, {
		ID: "BARE-1",
	}}
}

func readUpdateinfoFile(t *testing.T, path string) []Advisory {
	t.Helper()

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}

	defer f.Close()

	return collectAdvisories(t, f, UpdateinfoLimits{})
}

func collectAdvisories(t *testing.T, r io.Reader, lim UpdateinfoLimits) []Advisory {
	t.Helper()

	var out []Advisory

	err := ReadUpdateinfo(r, lim, func(a *Advisory) error {
		out = append(out, *a)

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return out
}

func renderUpdateinfo(t *testing.T, advisories []Advisory) []byte {
	t.Helper()

	var buf bytes.Buffer
	if err := WriteUpdateinfoXML(&buf, advisories); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

// TestWriteUpdateinfoMatchesCreaterepo compares the writer with the bytes
// createrepo_c's own writer produced for the same advisories.
func TestWriteUpdateinfoMatchesCreaterepo(t *testing.T) {
	want, err := os.ReadFile(filepath.Join("testdata", "updateinfo", "model.xml"))
	if err != nil {
		t.Fatal(err)
	}

	if got := renderUpdateinfo(t, modelAdvisories()); !bytes.Equal(got, want) {
		t.Errorf("updateinfo.xml differs from createrepo_c's:\n--- got\n%s\n--- want\n%s", got, want)
	}
}

// TestWriteUpdateinfoLiveCreaterepo regenerates model.xml with the installed
// createrepo_c python binding and compares it with the writer.
func TestWriteUpdateinfoLiveCreaterepo(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}

	if err := exec.Command(python, "-c", "import createrepo_c").Run(); err != nil {
		t.Skip("the createrepo_c python binding is not installed")
	}

	out := t.TempDir()

	if msg, err := exec.Command(python, filepath.Join("testdata", "updateinfo", "ground_truth.py"), out).CombinedOutput(); err != nil {
		t.Fatalf("ground_truth.py: %v\n%s", err, msg)
	}

	for name, advisories := range map[string][]Advisory{"model.xml": modelAdvisories(), "dnf.xml": dnfAdvisories()} {
		want, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}

		if got := renderUpdateinfo(t, advisories); !bytes.Equal(got, want) {
			t.Errorf("%s differs from the createrepo_c library's:\n--- got\n%s\n--- want\n%s", name, got, want)
		}
	}
}

func TestReadUpdateinfoModel(t *testing.T) {
	got := readUpdateinfoFile(t, filepath.Join("testdata", "updateinfo", "model.xml"))

	if want := modelAdvisories(); !reflect.DeepEqual(got, want) {
		t.Errorf("advisories = %+v\nwant %+v", got, want)
	}
}

// TestRealAdvisories reads advisories trimmed from the repositories of Rocky
// Linux and Fedora, and writes them back.
func TestRealAdvisories(t *testing.T) {
	tests := []struct {
		file       string
		ids        []string
		byteExact  bool
		checkFirst func(t *testing.T, a *Advisory)
	}{
		{
			file: "rocky9-baseos.xml", ids: []string{"RLBA-2022:7404", "RLSA-2022:6602"},
			checkFirst: func(t *testing.T, a *Advisory) {
				t.Helper()

				if a.Type != "bugfix" || a.Status != "final" || a.PushCount != "1" || a.Severity != "None" ||
					a.Issued != utc(2022, 11, 3, 9, 19, 42) || a.Updated != utc(2023, 2, 2, 12, 53, 50) ||
					a.Solution != "" || len(a.References) != 3 || a.References[1].Type != "vendor" ||
					!strings.Contains(a.Rights, "© Red Hat") || len(a.Collections[0].Packages) != 2 ||
					a.Collections[0].Packages[0].Sum.Type != "sha256" {
					t.Errorf("RLBA-2022:7404 = %+v", a)
				}
			},
		},
		{
			file: "rocky8-appstream.xml", ids: []string{"RLSA-2019:2512", "RLBA-2019:3522"},
			checkFirst: func(t *testing.T, a *Advisory) {
				t.Helper()

				m := a.Collections[0].Module
				if m == nil || m.Name == "" || m.Stream == "" || m.Version < 1e15 || m.Context == "" || m.Arch != "x86_64" {
					t.Errorf("RLSA-2019:2512 module = %+v", m)
				}
			},
		},
		{
			file: "fedora43-updates.xml", ids: []string{"FEDORA-2026-727b73bfa0", "FEDORA-2025-5efdb69e46", "FEDORA-2026-eb2fc8e93d"},
			byteExact: true,
			checkFirst: func(t *testing.T, a *Advisory) {
				t.Helper()

				if a.Type != "security" || a.Severity != "Important" || a.Version != "2.0" || a.From != "updates@fedoraproject.org" ||
					!a.Collections[0].Packages[0].RebootSuggested {
					t.Errorf("FEDORA-2026-727b73bfa0 = %+v", a)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			path := filepath.Join("testdata", "updateinfo", "real", tt.file)
			got := readUpdateinfoFile(t, path)

			var ids []string
			for i := range got {
				ids = append(ids, got[i].ID)
			}

			if !reflect.DeepEqual(ids, tt.ids) {
				t.Fatalf("ids = %v, want %v", ids, tt.ids)
			}

			tt.checkFirst(t, &got[0])

			written := renderUpdateinfo(t, got)

			if tt.byteExact {
				orig, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}

				// createrepo_c ends the document without a newline.
				if want := strings.TrimSuffix(string(orig), "\n"); string(written) != want {
					t.Errorf("rewritten document differs from the original:\n%s\n--- want\n%s", written, want)
				}
			}

			if again := collectAdvisories(t, bytes.NewReader(written), UpdateinfoLimits{}); !reflect.DeepEqual(again, got) {
				t.Errorf("write and read changed the advisories:\n%+v\n%+v", again, got)
			}
		})
	}
}

func TestReadUpdateinfoDates(t *testing.T) {
	tests := map[string]time.Time{
		"2024-03-01 09:30:00":       utc(2024, 3, 1, 9, 30, 0),
		"2024-03-01 09:30":          utc(2024, 3, 1, 9, 30, 0),
		"2024-03-01":                utc(2024, 3, 1, 0, 0, 0),
		"2024-03-01T09:30:00Z":      utc(2024, 3, 1, 9, 30, 0),
		"2024-03-01T11:30:00+02:00": utc(2024, 3, 1, 9, 30, 0),
		"2024-03-01T09:30:00":       utc(2024, 3, 1, 9, 30, 0),
		"1709285400":                utc(2024, 3, 1, 9, 30, 0),
		"":                          {},
	}

	for date, want := range tests {
		doc := fmt.Sprintf(`<updates><update><id>x</id><issued date="%s"/></update></updates>`, date)

		got := collectAdvisories(t, strings.NewReader(doc), UpdateinfoLimits{})
		if len(got) != 1 || !got[0].Issued.Equal(want) {
			t.Errorf("date %q = %v, want %v", date, got, want)
		}
	}
}

func TestReadUpdateinfoSemantics(t *testing.T) {
	const doc = `<?xml version="1.0"?>
<updates>
  <update from="a@b" status="stable" type="bugfix" version="1">
    <id> X-1 </id>
    <title>t</title>
    <unknown><deeper a="1">ignored</deeper></unknown>
    <message type="info">hello</message>
    <reboot_suggested>true</reboot_suggested>
    <pkglist>
      <collection short="s">
        <name>n</name>
        <package name="p" version="1" release="2" epoch="3" arch="noarch" src="p.src.rpm">
          <filename> p.rpm </filename>
          <sum type="sha1"> abc </sum>
          <reboot_suggested>False</reboot_suggested>
          <relogin_suggested>1</relogin_suggested>
          <restart_suggested>Yes</restart_suggested>
          <future>x</future>
        </package>
      </collection>
    </pkglist>
  </update>
  <update><title>no id</title></update>
  <other><update><id>nested</id></update></other>
</updates>`

	got := collectAdvisories(t, strings.NewReader(doc), UpdateinfoLimits{})
	if len(got) != 2 || got[0].ID != "X-1" || got[1].ID != "nested" {
		t.Fatalf("advisories = %+v", got)
	}

	a := got[0]
	if a.From != "a@b" || a.Status != "stable" || a.Type != "bugfix" || a.Version != "1" || !a.RebootSuggested || a.Title != "t" {
		t.Errorf("advisory = %+v", a)
	}

	p := a.Collections[0].Packages[0]
	want := AdvisoryPackage{
		Name: "p", Version: "1", Release: "2", Epoch: "3", Arch: "noarch", Src: "p.src.rpm", Filename: "p.rpm",
		Sum: AdvisorySum{Type: "sha1", Value: "abc"}, ReloginSuggested: true, RestartSuggested: true,
	}

	if p != want {
		t.Errorf("package = %+v, want %+v", p, want)
	}
}

func TestReadUpdateinfoErrors(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		lim  UpdateinfoLimits
		want error // nil: any error
	}{
		{"bad date", `<updates><update><id>x</id><issued date="yesterday"/></update></updates>`, UpdateinfoLimits{}, ErrInvalidUpdateinfo},
		{"bad updated date", `<updates><update><id>x</id><updated date="2024-13-45"/></update></updates>`, UpdateinfoLimits{}, ErrInvalidUpdateinfo},
		{
			"bad module version",
			`<updates><update><id>x</id><pkglist><collection><module version="x1"/></collection></pkglist></update></updates>`,
			UpdateinfoLimits{}, ErrInvalidUpdateinfo,
		},
		{"truncated", `<updates><update><id>x</id>`, UpdateinfoLimits{}, nil},
		{"mismatched", `<updates><update><id>x</id></updates>`, UpdateinfoLimits{}, nil},
		{"updates", `<updates><update><id>a</id></update><update><id>b</id></update></updates>`, UpdateinfoLimits{MaxUpdates: 1}, ErrTooLarge},
		{
			"references",
			`<updates><update><id>a</id><references><reference/><reference/></references></update></updates>`,
			UpdateinfoLimits{MaxReferences: 1}, ErrTooLarge,
		},
		{
			"collections",
			`<updates><update><id>a</id><pkglist><collection/><collection/></pkglist></update></updates>`,
			UpdateinfoLimits{MaxCollections: 1}, ErrTooLarge,
		},
		{
			"packages",
			`<updates><update><id>a</id><pkglist><collection><package/></collection><collection><package/></collection></pkglist></update></updates>`,
			UpdateinfoLimits{MaxPackages: 1}, ErrTooLarge,
		},
		{"field", `<updates><update><id>a</id><description>` + strings.Repeat("x", 100) + `</description></update></updates>`, UpdateinfoLimits{MaxFieldBytes: 50}, ErrTooLarge},
		{"depth", `<updates><update><id>a</id>` + strings.Repeat("<a>", 40) + strings.Repeat("</a>", 40) + `</update></updates>`, UpdateinfoLimits{}, ErrTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ReadUpdateinfo(strings.NewReader(tt.doc), tt.lim, func(*Advisory) error { return nil })
			if err == nil {
				t.Fatal("no error")
			}

			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestReadUpdateinfoCallbackError(t *testing.T) {
	stop := errors.New("stop")

	err := ReadUpdateinfo(strings.NewReader(`<updates><update><id>a</id></update><update><id>b</id></update></updates>`),
		UpdateinfoLimits{}, func(*Advisory) error { return stop })
	if !errors.Is(err, stop) {
		t.Errorf("error = %v, want %v", err, stop)
	}
}

func TestReadUpdateinfoEmpty(t *testing.T) {
	for _, doc := range []string{"", "<updates/>", "<updates></updates>"} {
		if got := collectAdvisories(t, strings.NewReader(doc), UpdateinfoLimits{}); len(got) != 0 {
			t.Errorf("%q: advisories = %+v", doc, got)
		}
	}
}

func TestWriteUpdateinfoEscaping(t *testing.T) {
	in := []Advisory{{
		ID: `a<b>&"c'`, Title: "t & <t>", Description: "tab\there\r\nline\x01end",
		References:  []AdvisoryReference{{Href: "https://x/?a=1&b=\"2\"", ID: "x\ny"}},
		Collections: []AdvisoryCollection{{Short: `s"1`, Name: "<n>"}},
	}}

	doc := renderUpdateinfo(t, in)
	if !strings.Contains(string(doc), "&#13;") || strings.Contains(string(doc), "\x01") {
		t.Errorf("control characters not escaped:\n%s", doc)
	}

	got := collectAdvisories(t, bytes.NewReader(doc), UpdateinfoLimits{})
	// A carriage return survives as one and an invalid character is replaced.
	in[0].Description = "tab\there\r\nline\uFFFDend"
	// The line feed of an attribute is normalised to a space by XML readers
	// unless it is written as a character reference, which libxml2 does.
	if !reflect.DeepEqual(got, in) {
		t.Errorf("round trip:\n%+v\nwant\n%+v", got, in)
	}
}

func TestWriteUpdateinfoInvalid(t *testing.T) {
	var buf bytes.Buffer

	err := WriteUpdateinfoXML(&buf, []Advisory{{ID: "ok"}, {Title: "no id"}})
	if !errors.Is(err, ErrInvalidUpdateinfo) {
		t.Errorf("no id: error = %v", err)
	}

	err = WriteUpdateinfoXML(&buf, []Advisory{{
		ID:          "x",
		Collections: []AdvisoryCollection{{Packages: []AdvisoryPackage{{Name: "p", Sum: AdvisorySum{Value: "abc"}}}}},
	}})
	if !errors.Is(err, ErrInvalidUpdateinfo) {
		t.Errorf("sum without type: error = %v", err)
	}
}

type failWriter struct{ after int }

func (f *failWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, errors.New("disk full")
	}

	f.after--

	return len(p), nil
}

func TestUpdateinfoWriterStreaming(t *testing.T) {
	var buf bytes.Buffer

	w := NewUpdateinfoWriter(&buf)
	desc := strings.Repeat("d", 1<<10)

	for i := range 200 {
		if err := w.Add(&Advisory{ID: fmt.Sprintf("A-%d", i), Description: desc}); err != nil {
			t.Fatal(err)
		}
	}

	if buf.Len() == 0 {
		t.Error("nothing was flushed before Close")
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	if got := collectAdvisories(t, &buf, UpdateinfoLimits{}); len(got) != 200 || got[199].ID != "A-199" {
		t.Errorf("read back %d advisories", len(got))
	}
}

func TestUpdateinfoWriterWriteError(t *testing.T) {
	w := NewUpdateinfoWriter(&failWriter{})
	desc := strings.Repeat("d", 1<<10)

	var addErr error

	for i := 0; i < 200 && addErr == nil; i++ {
		addErr = w.Add(&Advisory{ID: "A", Description: desc})
	}

	if addErr == nil {
		t.Error("Add did not report the write error")
	}

	if err := w.Close(); err == nil {
		t.Error("Close did not report the write error")
	}
}

func TestMergeAdvisories(t *testing.T) {
	adv := func(id, title string, issued, updated time.Time) Advisory {
		return Advisory{ID: id, Title: title, Issued: issued, Updated: updated}
	}

	d := func(day int) time.Time { return utc(2026, 1, day, 0, 0, 0) }

	a := []Advisory{adv("A", "a-old", d(1), d(2)), adv("B", "b-first", d(1), time.Time{}), adv("C", "c-only", d(1), d(1))}
	b := []Advisory{adv("B", "b-never-updated-newer-issue", d(5), time.Time{}), adv("A", "a-new", d(1), d(9)), adv("D", "d-only", d(3), time.Time{})}
	c := []Advisory{adv("A", "a-tie", d(1), d(9)), adv("C", "c-older", d(1), d(1))}

	got := MergeAdvisories(a, b, c)

	var titles []string
	for i := range got {
		titles = append(titles, got[i].Title)
	}

	want := []string{"a-new", "b-never-updated-newer-issue", "c-only", "d-only"}
	if !reflect.DeepEqual(titles, want) {
		t.Errorf("merged = %v, want %v", titles, want)
	}

	if got := MergeAdvisories(); len(got) != 0 {
		t.Errorf("merging nothing = %v", got)
	}
}

func TestMergeUpdateinfo(t *testing.T) {
	older := renderUpdateinfo(t, []Advisory{
		{ID: "A", Title: "old", Updated: utc(2026, 1, 1, 0, 0, 0)},
		{ID: "B", Title: "b"},
	})
	newer := renderUpdateinfo(t, []Advisory{
		{ID: "C", Title: "c"},
		{ID: "A", Title: "new", Updated: utc(2026, 2, 1, 0, 0, 0)},
	})

	var out bytes.Buffer

	n, err := MergeUpdateinfo(&out, []io.Reader{bytes.NewReader(older), bytes.NewReader(newer)}, UpdateinfoLimits{})
	if err != nil {
		t.Fatal(err)
	}

	got := collectAdvisories(t, &out, UpdateinfoLimits{})
	if n != 3 || len(got) != 3 || got[0].ID != "A" || got[0].Title != "new" || got[1].ID != "B" || got[2].ID != "C" {
		t.Errorf("merged %d advisories: %+v", n, got)
	}
}

func TestMergeUpdateinfoErrors(t *testing.T) {
	good := renderUpdateinfo(t, []Advisory{{ID: "A"}, {ID: "B"}})

	var out bytes.Buffer

	_, err := MergeUpdateinfo(&out, []io.Reader{bytes.NewReader(good), strings.NewReader("<updates><update>")}, UpdateinfoLimits{})
	if err == nil {
		t.Error("a malformed source must fail the merge")
	}

	if out.Len() != 0 {
		t.Error("a failed merge wrote output")
	}

	other := renderUpdateinfo(t, []Advisory{{ID: "C"}})

	_, err = MergeUpdateinfo(&out, []io.Reader{bytes.NewReader(good), bytes.NewReader(other)}, UpdateinfoLimits{MaxUpdates: 2})
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("distinct advisories over the limit: error = %v", err)
	}

	noType := `<updates><update><id>A</id><pkglist><collection><package name="p"><sum>abc</sum></package></collection></pkglist></update></updates>`

	out.Reset()

	_, err = MergeUpdateinfo(&out, []io.Reader{strings.NewReader(noType)}, UpdateinfoLimits{})
	if !errors.Is(err, ErrInvalidUpdateinfo) || out.Len() != 0 {
		t.Errorf("checksum without type: error = %v, %d bytes written", err, out.Len())
	}
}
