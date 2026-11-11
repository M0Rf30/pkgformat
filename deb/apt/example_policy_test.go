package apt_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/M0Rf30/pkgformat/deb/apt"
)

func ExampleParsePreferences() {
	prefs, err := apt.ParsePreferences(`Explanation: prefer the stable release, take a few packages from testing
Package: *
Pin: release a=stable
Pin-Priority: 700

Package: hello libhello*
Pin: release a=testing
Pin-Priority: 900

Package: nonfree-driver
Pin: version 535.*
Pin-Priority: 1001
`)
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, pin := range prefs.Pins {
		fmt.Println(pin.Packages, pin.Type, pin.Data, pin.Priority)
	}

	// Output:
	// [] release a=stable 700
	// [hello libhello*] release a=testing 900
	// [nonfree-driver] version 535.* 1001
}

func ExampleParsePreferences_error() {
	_, err := apt.ParsePreferences("Package: hello\nPin: release a=stable\nPin-Priority: never\n")

	fmt.Println(err)
	fmt.Println(errors.Is(err, apt.ErrNeverPin))

	// Output:
	// apt: preferences record 1 (Package: hello): apt: Pin-Priority never needs Package: *: "never"
	// true
}

func ExampleNewPolicy() {
	prefs, _ := apt.ParsePreferences(`Package: hello
Pin: release a=testing
Pin-Priority: 900
`)

	stable := &apt.ReleaseInfo{Suite: "stable", Codename: "bookworm"}
	testing := &apt.ReleaseInfo{Suite: "testing", Codename: "trixie"}
	backports := &apt.ReleaseInfo{Suite: "bookworm-backports", NotAutomatic: true, ButAutomaticUpgrades: true}

	versions := []*apt.PackageInfo{
		{Name: "hello", Architecture: "amd64", Version: "2.10-4", Releases: []*apt.ReleaseInfo{testing}},
		{Name: "hello", Architecture: "amd64", Version: "2.10-3~bpo12+1", Releases: []*apt.ReleaseInfo{backports}},
		{Name: "hello", Architecture: "amd64", Version: "2.10-2", Releases: []*apt.ReleaseInfo{stable}},
	}

	policy := apt.NewPolicy(prefs, apt.PolicyOptions{NativeArch: "amd64", DefaultRelease: "stable"})

	for _, v := range versions {
		fmt.Println(v.Version, policy.Priority(v))
	}

	fmt.Println("candidate:", policy.Candidate(versions, nil).Version)

	// Output:
	// 2.10-4 900
	// 2.10-3~bpo12+1 100
	// 2.10-2 990
	// candidate: 2.10-2
}

func ExamplePolicy_Candidate() {
	stable := &apt.ReleaseInfo{Suite: "stable"}

	newer := &apt.PackageInfo{Name: "tool", Architecture: "amd64", Version: "2.0", Releases: []*apt.ReleaseInfo{stable}}
	older := &apt.PackageInfo{Name: "tool", Architecture: "amd64", Version: "1.0", Releases: []*apt.ReleaseInfo{stable}}
	installed := &apt.PackageInfo{Name: "tool", Architecture: "amd64", Version: "3.0", Installed: true}

	policy := apt.NewPolicy(nil, apt.PolicyOptions{NativeArch: "amd64"})

	// Without a pin of 1000 or more, apt never installs a version older than
	// the installed one: the installed one stays.
	fmt.Println(policy.Candidate([]*apt.PackageInfo{installed, newer, older}, installed).Version)

	pinned, _ := apt.ParsePreferences("Package: tool\nPin: version 1.0\nPin-Priority: 1001\n")
	fmt.Println(apt.NewPolicy(pinned, apt.PolicyOptions{NativeArch: "amd64"}).Candidate([]*apt.PackageInfo{installed, newer, older}, installed).Version)

	// Output:
	// 3.0
	// 1.0
}

func ExamplePolicy_Phased() {
	percentage := 20

	installed := &apt.PackageInfo{Name: "tool", Architecture: "amd64", Version: "1.0", Installed: true}
	update := &apt.PackageInfo{Name: "tool", Architecture: "amd64", Version: "1.1", PhasedUpdatePercentage: &percentage}

	// The draw only depends on the source package, its version and the machine.
	fmt.Println("draw:", apt.PhasedDraw("tool", "1.1", "3e6a1d7dbd3a4b7b9d3c0f3a2b6c9f10", apt.PhasedCurrent))

	for _, id := range []string{"3e6a1d7dbd3a4b7b9d3c0f3a2b6c9f10", "0000000000000000000000000000000b", ""} {
		policy := apt.NewPolicy(nil, apt.PolicyOptions{MachineID: id, NativeArch: "amd64"})
		fmt.Printf("%q held back: %v\n", id, policy.Phased(update, installed))
	}

	// Output:
	// draw: 89
	// "3e6a1d7dbd3a4b7b9d3c0f3a2b6c9f10" held back: true
	// "0000000000000000000000000000000b" held back: false
	// "" held back: false
}

func ExampleLoadPreferences() {
	dir, err := os.MkdirTemp("", "apt-")
	if err != nil {
		fmt.Println(err)

		return
	}

	defer func() { _ = os.RemoveAll(dir) }()

	_ = os.WriteFile(filepath.Join(dir, "preferences"), []byte("Package: *\nPin: release a=stable\nPin-Priority: 700\n"), 0o600)
	_ = os.MkdirAll(filepath.Join(dir, "preferences.d"), 0o750)
	_ = os.WriteFile(filepath.Join(dir, "preferences.d", "backports.pref"), []byte("Package: hello\nPin: release a=bookworm-backports\nPin-Priority: 800\n"), 0o600)
	// Files with other extensions are not read, as in apt.
	_ = os.WriteFile(filepath.Join(dir, "preferences.d", "notes.txt"), []byte("not a preferences file"), 0o600)

	prefs, err := apt.LoadPreferences(filepath.Join(dir, "preferences"), filepath.Join(dir, "preferences.d"))
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, pin := range prefs.Pins {
		fmt.Println(pin.Packages, pin.Data, pin.Priority)
	}

	// Output:
	// [] a=stable 700
	// [hello] a=bookworm-backports 800
}
