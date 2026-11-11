package pacman_test

import (
	"fmt"
	"strings"
	"testing/fstest"

	"github.com/M0Rf30/pkgformat/pacman"
)

// A pacman.conf is parsed into typed options and repositories.
func ExampleParseConfig() {
	cfg, err := pacman.ParseConfig(strings.NewReader(`
[options]
HoldPkg = pacman glibc
IgnorePkg = linux*
ParallelDownloads = 5
Color

[core]
SigLevel = Required DatabaseOptional
Server = https://mirror.example/$repo/os/$arch
`), pacman.ParseOptions{})
	if err != nil {
		fmt.Println(err)

		return
	}

	core := cfg.Repos[0]

	fmt.Println(cfg.ParallelDownloads, cfg.Color, cfg.IsHeld("glibc"), cfg.IsIgnored("linux-lts"))
	fmt.Println(core.Name, core.SigLevel)
	// Output:
	// 5 true true true
	// core PackageRequired PackageTrustedOnly DatabaseOptional DatabaseTrustedOnly
}

// ParseConfigFS reads a configuration and everything it includes from any
// fs.FS, here an in-memory one; ParseConfigFile does the same on disk.
func ExampleParseConfigFS() {
	fsys := fstest.MapFS{
		"etc/pacman.conf":         {Data: []byte("[core]\nInclude = /etc/pacman.d/mirrorlist\n")},
		"etc/pacman.d/mirrorlist": {Data: []byte("Server = https://a.example/$repo/os/$arch\nServer = https://b.example/$repo/os/$arch\n")},
	}

	cfg, err := pacman.ParseConfigFS(fsys, "etc/pacman.conf", pacman.ParseOptions{})
	if err != nil {
		fmt.Println(err)

		return
	}

	for _, s := range cfg.Repos[0].Servers {
		fmt.Println(pacman.ExpandServer(s, "core", pacman.ArchFromGOARCH("amd64")))
	}
	// Output:
	// https://a.example/core/os/x86_64
	// https://b.example/core/os/x86_64
}

// SigLevel directives apply left to right, as in pacman: a bare level sets
// the package and the database policy, a Package or Database prefix only one.
func ExampleParseSigLevel() {
	level, err := pacman.ParseSigLevel("Required DatabaseOptional")
	if err != nil {
		fmt.Println(err)

		return
	}

	fmt.Println(level.Package.Check == pacman.SigRequired, level.Database.Check == pacman.SigOptional)
	fmt.Println(level.Database.VerifyMode() == pacman.VerifyIfPresent)
	fmt.Println(level)
	// Output:
	// true true
	// true
	// PackageRequired PackageTrustedOnly DatabaseOptional DatabaseTrustedOnly
}

// Architecture = auto is replaced by the running machine's architecture.
func ExampleConfig_AllowedArchitectures() {
	cfg, _ := pacman.ParseConfig(strings.NewReader("[options]\nArchitecture = auto x86_64_v3\n"), pacman.ParseOptions{})

	fmt.Println(cfg.AllowedArchitectures("amd64"))
	fmt.Println(cfg.Arch("arm64"))
	// Output:
	// [x86_64 x86_64_v3]
	// aarch64
}

// A repository's Usage tells which operations may use it.
func ExampleConfig_ReposFor() {
	cfg, _ := pacman.ParseConfig(strings.NewReader(`
[core]
Server = https://m.example/$repo
[testing]
Usage = Sync Search
Server = https://m.example/$repo
`), pacman.ParseOptions{})

	for _, r := range cfg.ReposFor(pacman.UsageInstall) {
		fmt.Println(r.Name)
	}
	// Output:
	// core
}
