package repodata_test

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm/repodata"
)

// Read the modules.yaml of a repository and list what it offers, then write a
// stream of your own the way libmodulemd would.
func ExampleParseModulemd() {
	const modulesYAML = `---
document: modulemd-defaults
version: 1
data:
  module: nginx
  stream: "1.24"
  profiles:
    "1.24": [common]
...
---
document: modulemd
version: 2
data:
  name: nginx
  stream: "1.24"
  version: 9040020240101000000
  context: 9
  arch: x86_64
  summary: nginx webserver
  description: >-
    nginx 1.24 webserver module
  license:
    module:
    - MIT
  dependencies:
  - buildrequires:
      platform: [el9.4.0]
    requires:
      platform: [el9]
  profiles:
    common:
      rpms:
      - nginx
  artifacts:
    rpms:
    - nginx-1:1.24.0-1.module+el9.4.0+1+deadbeef.x86_64
...
`

	set, err := repodata.ParseModulemd(strings.NewReader(modulesYAML), repodata.ModulemdLimits{})
	if err != nil {
		log.Fatal(err)
	}

	for _, d := range set.Defaults {
		fmt.Printf("default of %s: %s %v\n", d.Module, d.Stream, d.Profiles[d.Stream])
	}

	for _, s := range set.Streams {
		fmt.Println(s.NSVCA(), "requires", s.Dependencies[0].Requires["platform"], "installs", s.Profiles["common"].RPMs)
	}

	// Output:
	// default of nginx: 1.24 [common]
	// nginx:1.24:9040020240101000000:9:x86_64 requires [el9] installs [nginx]
}

// Write a modules.yaml: documents come out in libmodulemd's order and layout.
func ExampleWriteModules() {
	set := &repodata.ModuleSet{
		Defaults: []*repodata.ModuleDefaults{{Module: "tools", Stream: "2.0", Profiles: map[string][]string{"2.0": {"default"}}}},
		Streams: []*repodata.ModuleStream{{
			Name: "tools", Stream: "2.0", Version: 1, Context: "abc", Arch: "noarch",
			Summary: "Tools", Description: "A set of tools.",
			License:  repodata.ModuleLicense{Module: []string{"MIT"}},
			Profiles: map[string]repodata.ModuleProfile{"default": {RPMs: []string{"tool-b", "tool-a"}}},
		}},
	}

	if err := repodata.WriteModules(os.Stdout, set); err != nil {
		log.Fatal(err)
	}

	// Output:
	// ---
	// document: modulemd-defaults
	// version: 1
	// data:
	//   module: tools
	//   stream: "2.0"
	//   profiles:
	//     "2.0": [default]
	// ...
	// ---
	// document: modulemd
	// version: 2
	// data:
	//   name: tools
	//   stream: "2.0"
	//   version: 1
	//   context: abc
	//   arch: noarch
	//   summary: Tools
	//   description: >-
	//     A set of tools.
	//   license:
	//     module:
	//     - MIT
	//   profiles:
	//     default:
	//       rpms:
	//       - tool-a
	//       - tool-b
	// ...
}
