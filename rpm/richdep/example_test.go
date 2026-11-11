package richdep_test

import (
	"fmt"

	"github.com/M0Rf30/pkgformat/rpm/richdep"
)

// A rich dependency is parsed into a tree, written back in canonical form and
// evaluated against what the installed packages provide.
func Example() {
	_, err := richdep.Parse("(glibc-langpack-en or glibc-all-langpacks) if glibc")
	fmt.Println(err != nil) // the outer parentheses are required

	dep, err := richdep.Parse("((glibc-langpack-en or glibc-all-langpacks) if glibc)")
	if err != nil {
		fmt.Println(err)

		return
	}

	fmt.Println(dep)

	installed := map[string][]string{"glibc": {"glibc-2.40"}, "glibc-all-langpacks": {"glibc-all-langpacks-2.40"}}
	oracle := richdep.OracleFunc(func(a richdep.Atom) []string { return installed[a.Name] })

	fmt.Println(richdep.Eval(dep, oracle))

	delete(installed, "glibc-all-langpacks")
	fmt.Println(richdep.Eval(dep, oracle))

	// Output:
	// true
	// ((glibc-langpack-en or glibc-all-langpacks) if glibc)
	// true
	// false
}

// An Atom decides whether a provide meets a requirement the way rpm does.
func ExampleAtom_Overlaps() {
	provides := richdep.Atom{Name: "libfoo", Cmp: richdep.Equal, Version: "2.1-3"}
	requires := richdep.Atom{Name: "libfoo", Cmp: richdep.Greater | richdep.Equal, Version: "2.0"}

	fmt.Println(provides.Overlaps(requires))
	fmt.Println(provides.Overlaps(richdep.Atom{Name: "libfoo", Cmp: richdep.Greater, Version: "2.1-3"}))

	// Output:
	// true
	// false
}
