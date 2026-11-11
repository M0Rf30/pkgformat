package apt_test

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/M0Rf30/pkgformat/deb/apt"
)

// Plan predicts what apt-get would do: here installing mta-a removes the
// installed mta-b it conflicts with, and upgrades nothing else.
func ExampleCache_Plan() {
	dir, err := os.MkdirTemp("", "plan")
	if err != nil {
		fmt.Println(err)

		return
	}

	defer os.RemoveAll(dir)

	index := "Package: mta-a\nVersion: 1\nArchitecture: amd64\nConflicts: mta-b\n\n"
	status := "Package: mta-b\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n"

	list := filepath.Join(dir, "example.org_dists_stable_main_binary-amd64_Packages")
	statusFile := filepath.Join(dir, "status")

	if err := os.WriteFile(list, []byte(index), 0o600); err != nil {
		fmt.Println(err)

		return
	}

	if err := os.WriteFile(statusFile, []byte(status), 0o600); err != nil {
		fmt.Println(err)

		return
	}

	cache, err := apt.Load(apt.LoadOptions{ListsDir: dir, StatusFile: statusFile, HostArch: "amd64"})
	if err != nil {
		fmt.Println(err)

		return
	}

	plan, err := cache.Plan(apt.PlanRequest{Install: []string{"mta-a"}}, apt.PlanOptions{})
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, ch := range plan.Changes {
		fmt.Println(ch.Kind, ch.Package.Name, "-", ch.Reason.Kind)
	}

	// Output:
	// remove mta-b - conflict
	// install mta-a - requested
}
