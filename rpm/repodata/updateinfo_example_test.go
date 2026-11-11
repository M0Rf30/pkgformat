package repodata_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"time"

	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// Write an advisory, register the document in repomd.xml, and read it back the
// way a client does.
func ExampleWriteUpdateinfoXML() {
	advisory := repodata.Advisory{
		ID: "FEDORA-2026-c3b1d2e4f5", Title: "bash-5.3.99-1.fc45", Type: "security", Severity: "Important",
		Status: "stable", From: "updates@fedoraproject.org",
		Issued:      time.Date(2026, 10, 2, 11, 43, 19, 0, time.UTC),
		Release:     "Fedora 45",
		Summary:     "bash-5.3.99-1.fc45 security update",
		Description: "Fixes an out-of-bounds read in the history expansion code.",
		References: []repodata.AdvisoryReference{{
			Href: "https://bugzilla.redhat.com/show_bug.cgi?id=2410101", ID: "2410101", Type: "bugzilla",
			Title: "CVE-2026-0101 bash: out-of-bounds read in history expansion",
		}},
		Collections: []repodata.AdvisoryCollection{{
			Short: "F45", Name: "Fedora 45",
			Packages: []repodata.AdvisoryPackage{{
				Name: "bash", Version: "5.3.99", Release: "1.fc45", Epoch: "0", Arch: "x86_64",
				Filename: "bash-5.3.99-1.fc45.x86_64.rpm",
				Sum:      repodata.AdvisorySum{Type: "sha256", Value: "0f1e2d3c"},
			}},
		}},
	}

	doc, err := repodata.CompressMetadataStream(repodata.Zstd, func(w io.Writer) error {
		return repodata.WriteUpdateinfoXML(w, []repodata.Advisory{advisory})
	})
	if err != nil {
		log.Fatal(err)
	}

	repomd := &repodata.Repomd{Revision: "1"}
	repomd.Data = append(repomd.Data, doc.Entry("updateinfo", "updateinfo.xml"+repodata.Zstd.Extension(), 1))

	index, err := repomd.Marshal()
	if err != nil {
		log.Fatal(err)
	}

	// Client side.
	parsed, err := repodata.ParseRepomd(bytes.NewReader(index))
	if err != nil {
		log.Fatal(err)
	}

	entry, _ := parsed.Find("updateinfo")

	rc, err := repodata.OpenMetadata(io.NopCloser(bytes.NewReader(doc.Data)), entry.Location, 0)
	if err != nil {
		log.Fatal(err)
	}
	defer rc.Close()

	err = repodata.ReadUpdateinfo(rc, repodata.UpdateinfoLimits{}, func(a *repodata.Advisory) error {
		fmt.Println(a.ID, a.Type, a.Severity, a.Issued.Format(time.DateOnly), a.Collections[0].Packages[0].Filename)

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	// Output: FEDORA-2026-c3b1d2e4f5 security Important 2026-10-02 bash-5.3.99-1.fc45.x86_64.rpm
}

// Merge the advisories of two repositories: the newest version of each id wins
// and the ids keep the order they first appear in.
func ExampleMergeUpdateinfo() {
	render := func(advisories ...repodata.Advisory) io.Reader {
		var buf bytes.Buffer
		if err := repodata.WriteUpdateinfoXML(&buf, advisories); err != nil {
			log.Fatal(err)
		}

		return &buf
	}

	day := func(d int) time.Time { return time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }

	var merged bytes.Buffer

	n, err := repodata.MergeUpdateinfo(&merged, []io.Reader{
		render(repodata.Advisory{ID: "A-1", Title: "first draft", Updated: day(1)}, repodata.Advisory{ID: "A-2", Title: "only here"}),
		render(repodata.Advisory{ID: "A-1", Title: "corrected", Updated: day(9)}),
	}, repodata.UpdateinfoLimits{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(n, "advisories")

	err = repodata.ReadUpdateinfo(&merged, repodata.UpdateinfoLimits{}, func(a *repodata.Advisory) error {
		fmt.Println(a.ID, a.Title)

		return nil
	})
	if err != nil {
		log.Fatal(err)
	}
	// Output:
	// 2 advisories
	// A-1 corrected
	// A-2 only here
}
