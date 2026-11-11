package pacman_test

import (
	"fmt"

	"github.com/M0Rf30/pkgformat/pacman"
)

func resolveExampleIndex() *pacman.Index {
	x := &pacman.Index{}

	_ = x.Add("core", []pacman.DBEntry{
		{Name: "glibc", Version: "2.40-1", Groups: []string{"base"}},
		{Name: "bash", Version: "5.2-1", Depends: []string{"glibc"}, Provides: []string{"sh"}, Groups: []string{"base"}},
		{Name: "app", Version: "2-1", Depends: []string{"sh", "glibc>=2.40"}, OptDepends: []string{"nice: prettier output"}, Conflicts: []string{"app-git"}},
		{Name: "nice", Version: "1-1"},
		{Name: "newname", Version: "1-1", Replaces: []string{"oldname"}},
	})

	return x
}

// Install resolves what pacman -S would install, with libalpm's choices.
func ExampleIndex_Install() {
	x := resolveExampleIndex()

	tx, err := x.Install([]string{"app"}, pacman.ResolveOptions{
		Local: []*pacman.InstalledPackage{{Name: "glibc", Version: "2.39-1"}},
	})
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, p := range tx.Packages {
		fmt.Println(p.Name, p.Version)
	}

	for _, u := range tx.Upgrades {
		fmt.Println("upgrades", u.Installed.Name, u.Installed.Version, "->", u.Package.Version)
	}

	// Output:
	// glibc 2.40-1
	// bash 5.2-1
	// app 2-1
	// upgrades glibc 2.39-1 -> 2.40-1
}

// A conflict with an installed package is an error that names both.
func ExampleConflictError() {
	x := resolveExampleIndex()

	_, err := x.Install([]string{"app"}, pacman.ResolveOptions{
		Local: []*pacman.InstalledPackage{{Name: "app-git", Version: "1-1"}, {Name: "glibc", Version: "2.40-1"}},
	})
	fmt.Println(err)

	// Output:
	// pacman: conflicting packages: app and app-git (installed) conflict (app-git)
}

// Sysupgrade upgrades what has a newer version and applies replaces.
func ExampleIndex_Sysupgrade() {
	x := resolveExampleIndex()

	tx, err := x.Sysupgrade([]*pacman.InstalledPackage{
		{Name: "glibc", Version: "2.39-1"},
		{Name: "oldname", Version: "1-1"},
	}, pacman.ResolveOptions{IgnorePkg: []string{"nothing"}})
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, u := range tx.Upgrades {
		fmt.Println("upgrade", u.Package.Name, u.Package.Version)
	}

	for _, r := range tx.Replacements {
		fmt.Println(r.Package.Name, "replaces", r.Installed.Name)
	}

	for _, r := range tx.Removals {
		fmt.Println("remove", r.Name)
	}

	// Output:
	// upgrade glibc 2.40-1
	// newname replaces oldname
	// remove oldname
}

// A group name stands for its members.
func ExampleIndex_Group() {
	for _, p := range resolveExampleIndex().Group("base") {
		fmt.Println(p.Name)
	}

	// Output:
	// bash
	// glibc
}

// Optional dependencies are listed, not installed.
func ExampleIndex_OptionalDeps() {
	x := resolveExampleIndex()
	app, _ := x.Lookup("app")

	opts, _ := x.OptionalDeps(app)
	for _, o := range opts {
		fmt.Printf("%s (%s) from %s\n", o.Name, o.Description, o.Package.Repo)
	}

	// Output:
	// nice (prettier output) from core
}

func ExampleParseOptionalDep() {
	o, _ := pacman.ParseOptionalDep("python>=3: scripting support")
	fmt.Println(o.Name, o.Op, o.Version, "-", o.Description)

	// Output:
	// python >= 3 - scripting support
}
