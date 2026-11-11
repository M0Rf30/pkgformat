package repodata_test

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// Describe the groups of a distribution in a model and write them as
// comps.xml; dnf and yum read it from the "group" record of repomd.xml.
func ExampleWriteCompsXML() {
	comps := &repodata.Comps{
		Groups: []repodata.CompsGroup{{
			ID: "editors", Name: "Editors", Description: "Text editors",
			NameLocalized: map[string]string{"de": "Editoren"},
			UserVisible:   true,
			Packages: []repodata.CompsPackage{
				{Name: "vim", Type: repodata.CompsMandatory},
				{Name: "nano", Type: repodata.CompsDefault},
				{Name: "vim-spell", Type: repodata.CompsConditional, Requires: "vim"},
			},
		}},
		Categories: []repodata.CompsCategory{{
			ID: "applications", Name: "Applications",
			Groups: []repodata.CompsGroupRef{{ID: "editors"}},
		}},
	}

	if err := repodata.WriteCompsXML(os.Stdout, comps); err != nil {
		log.Fatal(err)
	}

	// Output:
	// <?xml version="1.0" encoding="UTF-8"?>
	// <!DOCTYPE comps PUBLIC "-//Red Hat, Inc.//DTD Comps info//EN" "comps.dtd">
	// <comps>
	//   <group>
	//     <id>editors</id>
	//     <name>Editors</name>
	//     <name xml:lang="de">Editoren</name>
	//     <description>Text editors</description>
	//     <default>false</default>
	//     <uservisible>true</uservisible>
	//     <packagelist>
	//       <packagereq type="mandatory">vim</packagereq>
	//       <packagereq type="default">nano</packagereq>
	//       <packagereq requires="vim" type="conditional">vim-spell</packagereq>
	//     </packagelist>
	//   </group>
	//   <category>
	//     <id>applications</id>
	//     <name>Applications</name>
	//     <grouplist>
	//       <groupid>editors</groupid>
	//     </grouplist>
	//   </category>
	// </comps>
}

// Read the groups of a comps.xml one at a time, without holding the document
// in memory: the visitor sees each group as soon as it is parsed.
func ExampleReadComps() {
	const doc = `<comps>
  <group><id>core</id><name>Core</name><packagelist>
    <packagereq type="mandatory">bash</packagereq>
    <packagereq type="optional">vim</packagereq>
  </packagelist></group>
  <group><id>editors</id><name>Editors</name></group>
</comps>`

	err := repodata.ReadComps(strings.NewReader(doc), repodata.CompsLimits{}, repodata.CompsVisitor{
		Group: func(g *repodata.CompsGroup) error {
			fmt.Println(g.ID, g.Name, len(g.Packages), "packages")

			return nil
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Output:
	// core Core 2 packages
	// editors Editors 0 packages
}

// Merge the groups of several documents into one comps.xml as they are read.
func ExampleCompsWriter() {
	docs := []string{
		`<comps><group><id>a</id></group></comps>`,
		`<comps><group><id>b</id></group><langpacks><match name="x" install="x-%s"/></langpacks></comps>`,
	}

	var out bytes.Buffer

	cw := repodata.NewCompsWriter(&out)

	var langpacks []repodata.CompsLangpack

	for _, doc := range docs {
		err := repodata.ReadComps(strings.NewReader(doc), repodata.CompsLimits{}, repodata.CompsVisitor{
			Group: cw.Group,
			Langpack: func(l repodata.CompsLangpack) error {
				langpacks = append(langpacks, l)

				return nil
			},
		})
		if err != nil {
			log.Fatal(err)
		}
	}

	if err := cw.Langpacks(langpacks); err != nil {
		log.Fatal(err)
	}

	if err := cw.Close(); err != nil {
		log.Fatal(err)
	}

	merged, err := repodata.ParseComps(&out, repodata.CompsLimits{})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(len(merged.Groups), "groups,", len(merged.Langpacks), "langpack")

	// Output:
	// 2 groups, 1 langpack
}
