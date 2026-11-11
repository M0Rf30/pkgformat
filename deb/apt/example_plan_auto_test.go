package apt_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/M0Rf30/pkgformat/deb/apt"
)

// exampleCache loads an index, a dpkg status file and an apt extended states
// file written to a scratch directory.
func exampleCache(index, status, states string) (*apt.Cache, error) {
	dir, err := os.MkdirTemp("", "plan")
	if err != nil {
		return nil, err
	}

	defer os.RemoveAll(dir)

	files := map[string]string{
		"example.org_dists_stable_main_binary-amd64_Packages": index,
		"status":          status,
		"extended_states": states,
	}

	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			return nil, err
		}
	}

	return apt.Load(apt.LoadOptions{
		ListsDir:           dir,
		StatusFile:         filepath.Join(dir, "status"),
		ExtendedStatesFile: filepath.Join(dir, "extended_states"),
		HostArch:           "amd64",
	})
}

func printPlan(plan *apt.Plan) {
	for _, ch := range plan.Changes {
		fmt.Println(ch.Kind, ch.Package.Name, "-", ch.Reason.Kind)
	}
}

// With apt's default, Install-Recommends, a new package brings its
// Recommends along when they can be installed; InstallRecommends turns that
// off, as --no-install-recommends does.
func ExamplePlanOptions_installRecommends() {
	cache, err := exampleCache("Package: app\nVersion: 1\nArchitecture: amd64\nRecommends: extra, absent\n\n"+
		"Package: extra\nVersion: 1\nArchitecture: amd64\n\n", "", "")
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, recommends := range []bool{true, false} {
		plan, err := cache.Plan(apt.PlanRequest{Install: []string{"app"}}, apt.PlanOptions{InstallRecommends: &recommends})
		if err != nil {
			fmt.Println(err)

			return
		}

		fmt.Println("recommends:", recommends)
		printPlan(plan)
	}

	// Output:
	// recommends: true
	// install app - requested
	// install extra - recommends
	// recommends: false
	// install app - requested
}

// A package that was installed automatically and that nothing installed needs
// any more is what "apt-get autoremove" removes; the marks come from apt's
// extended states file.
func ExamplePlanRequest_autoRemove() {
	index := ""
	status := "Package: app\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\nDepends: lib\n\n" +
		"Package: lib\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n" +
		"Package: old\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n"
	states := "Package: lib\nArchitecture: amd64\nAuto-Installed: 1\n\n" +
		"Package: old\nArchitecture: amd64\nAuto-Installed: 1\n"

	cache, err := exampleCache(index, status, states)
	if err != nil {
		fmt.Println(err)

		return
	}

	plan, err := cache.Plan(apt.PlanRequest{AutoRemove: true}, apt.PlanOptions{})
	if err != nil {
		fmt.Println(err)

		return
	}

	printPlan(plan)

	// Output:
	// remove old - auto-remove
}

// Packages dpkg holds are neither upgraded nor removed, however the request
// is made; PlanOptions.Held adds holds the status database does not know.
func ExamplePackageInfo_held() {
	index := "Package: kept\nVersion: 2\nArchitecture: amd64\n\nPackage: moved\nVersion: 2\nArchitecture: amd64\n\n"
	status := "Package: kept\nStatus: hold ok installed\nVersion: 1\nArchitecture: amd64\n\n" +
		"Package: moved\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n\n"

	cache, err := exampleCache(index, status, "")
	if err != nil {
		fmt.Println(err)

		return
	}

	plan, err := cache.Plan(apt.PlanRequest{Upgrade: apt.UpgradeSafe}, apt.PlanOptions{})
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, ch := range plan.Changes {
		fmt.Println(ch.Kind, ch.Package.Name, ch.From.Version, "->", ch.Package.Version)
	}

	for _, h := range plan.Held {
		fmt.Println("held:", h.Name)
	}

	// Output:
	// upgrade moved 1 -> 2
	// held: kept
}

// Two packages that Pre-Depend on each other cannot be configured. The plan
// fails as apt-get does, with an error that carries the cycle.
func ExampleOrderError() {
	cache, err := exampleCache("Package: a\nVersion: 1\nArchitecture: amd64\nPre-Depends: b\n\n"+
		"Package: b\nVersion: 1\nArchitecture: amd64\nPre-Depends: a\n\n", "", "")
	if err != nil {
		fmt.Println(err)

		return
	}

	_, err = cache.Plan(apt.PlanRequest{Install: []string{"a"}}, apt.PlanOptions{})

	var oe *apt.OrderError

	fmt.Println(errors.Is(err, apt.ErrOrderLoop), errors.As(err, &oe))
	fmt.Println(oe.Kind, oe.Cycle)

	// Output:
	// true true
	// loop [a:amd64 b:amd64 a:amd64]
}
