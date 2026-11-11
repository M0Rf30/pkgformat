package dnf

import (
	"context"
	"errors"
	"log/slog"
	"runtime"
	"strings"

	"github.com/M0Rf30/pkgformat/gpg"
	"github.com/M0Rf30/pkgformat/httpclient"
	"github.com/M0Rf30/pkgformat/rpm"
)

// Errors of the client. Test with errors.Is.
var (
	// ErrNoMirror means a repository has no usable base URL: none configured,
	// or its mirror list holds no http(s) mirror.
	ErrNoMirror = errors.New("dnf: no usable mirror")
	// ErrNoPrimary means a repomd.xml lists no primary metadata.
	ErrNoPrimary = errors.New("dnf: repomd.xml has no primary data")
	// ErrUnverifiable means a file cannot be checked: the repository gives no
	// SHA-256 or SHA-512 checksum for it. Such a file is never downloaded.
	ErrUnverifiable = errors.New("dnf: no usable checksum to verify the download")
	// ErrUnsafeLocation means a location in repository metadata would leave
	// the repository or the destination directory.
	ErrUnsafeLocation = errors.New("dnf: unsafe location in repository metadata")
	// ErrNoCacheDir means an operation that needs Options.CacheDir ran
	// without one.
	ErrNoCacheDir = errors.New("dnf: no cache directory configured")
)

// Default limits, applied where an Options field is zero.
const (
	// DefaultMaxMetadataBytes bounds a downloaded metadata file (compressed).
	DefaultMaxMetadataBytes int64 = 512 << 20
	// DefaultMaxPackageBytes bounds a downloaded package.
	DefaultMaxPackageBytes int64 = 2 << 30
	// DefaultMaxDocumentBytes bounds a metadata document once decompressed.
	DefaultMaxDocumentBytes int64 = 4 << 30
	// maxMirrors caps the candidate mirrors tried per repository. The first
	// healthy one wins; more only delays the failure report of a repository
	// that is truly unreachable.
	maxMirrors = 5
	// maxRepoFileBytes bounds one .repo file.
	maxRepoFileBytes = 1 << 20
	// maxMirrorListBytes bounds a mirror list or metalink answer.
	maxMirrorListBytes = 16 << 20
	// maxRepomdBytes bounds the repomd.xml of a repository.
	maxRepomdBytes = 4 << 20
	// maxVarBytes bounds the value of a variable file.
	maxVarBytes = 4 << 10
)

// Installed tells the resolver what the host already has, so that it neither
// reinstalls it nor pulls an alternative provider in, and so that a package it
// installs is checked against what is there: the host's package database is
// the caller's to give, over rpm, a database reader ([rpmdb.DB]) or a fixed
// list.
type Installed interface {
	// InstalledPackages returns the installed packages with their
	// dependencies, and their files where the resolution looks a file
	// dependency up. The result is not modified.
	InstalledPackages(ctx context.Context) ([]*rpm.Package, error)
}

// Options configures a [Client]. The zero value is usable for operations that
// need no directory; set RepoDir and CacheDir for the rest. No host path is
// assumed: the usual /etc/yum.repos.d, /var/cache/dnf, /etc/dnf/dnf.conf and
// /etc/dnf/vars are the caller's to pass.
type Options struct {
	// RepoDir holds the *.repo files.
	RepoDir string
	// ConfigFile is the dnf.conf whose [main] section gives the defaults of
	// the repository options and the settings of a resolution; see [Config].
	// Optional: without it dnf's defaults apply. Config, when set, is used
	// instead of reading the file.
	ConfigFile string
	Config     *Config
	// CacheDir is where metadata is stored: <CacheDir>/<repo id>/repodata for
	// the metadata and <CacheDir>/<repo id>/.baseurl for the mirror that
	// served it. A directory laid out by dnf (<repo id>-<hash>) is read too.
	CacheDir string
	// PersistDir is where state that outlives the cache is kept
	// (dnf's /var/lib/dnf): <PersistDir>/repos/<repo id>/countme is the
	// cookie of countme=1. Optional: without it no repository is counted.
	PersistDir string
	// MachineIDFile is the machine-id (/etc/machine-id) whose modification
	// time dates the installation of the system, for the age bucket countme
	// reports. Optional: without it the system is as old as the first count.
	MachineIDFile string
	// VarsDirs hold one file per variable (dnf's /etc/dnf/vars and
	// /etc/yum/vars), for $infra, $contentdir and the like; the first
	// directory that has the file wins. Optional: the varsdir of the
	// dnf.conf is used when this is empty.
	VarsDirs []string
	// Vars are variables substituted in repository URLs, taking precedence
	// over VarsDirs. $basearch, $arch, $releasever, $releasever_major and
	// $releasever_minor are always defined from Arch and Releasever.
	Vars map[string]string
	// Releasever is the value of $releasever. It also drives the retry of a
	// mirror list that does not know the minor release (8.10 becomes 8).
	Releasever string
	// Arch is the architecture packages are chosen for, such as "x86_64"; it
	// defaults to that of the running program. BaseArch is the value of
	// $basearch and defaults to the base architecture of Arch.
	Arch     string
	BaseArch string
	// Installed reports what the host has installed. Optional: nil means
	// nothing is installed.
	Installed Installed
	// LocalKeys are the keys [Client.VerifyLocal] trusts besides the gpgkey
	// of every enabled repository. Optional.
	LocalKeys *gpg.Keyring
	// HTTP carries every request; nil builds a client with the default
	// timeouts and retry policy.
	HTTP *httpclient.Client
	// Logger receives progress and warnings; nil is silent.
	Logger *slog.Logger
	// Concurrency bounds the repositories fetched or parsed at once and the
	// packages downloaded at once; zero selects a default of at most 8.
	Concurrency int
	// MaxMetadataBytes, MaxPackageBytes and MaxDocumentBytes override the
	// limits of the same names above.
	MaxMetadataBytes int64
	MaxPackageBytes  int64
	MaxDocumentBytes int64
}

func (o *Options) normalize() {
	if o.Arch == "" {
		o.Arch = goArchToRPM()
	}

	if o.BaseArch == "" {
		o.BaseArch = baseArch(o.Arch)
	}

	if o.HTTP == nil {
		o.HTTP = httpclient.New(httpclient.Options{})
	}

	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}

	if o.Concurrency <= 0 {
		o.Concurrency = min(runtime.GOMAXPROCS(0)*2, 8)
	}

	if o.MaxMetadataBytes <= 0 {
		o.MaxMetadataBytes = DefaultMaxMetadataBytes
	}

	if o.MaxPackageBytes <= 0 {
		o.MaxPackageBytes = DefaultMaxPackageBytes
	}

	if o.MaxDocumentBytes <= 0 {
		o.MaxDocumentBytes = DefaultMaxDocumentBytes
	}
}

// goArchToRPM maps GOARCH to the architecture name of RPM.
func goArchToRPM() string { return rpmArch(runtime.GOARCH) }

// rpmArch maps a GOARCH value to the architecture name of RPM.
func rpmArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	case "386":
		return "i686"
	case "arm":
		return "armv7hl"
	default:
		return goarch
	}
}

// baseArch maps an RPM architecture to the $basearch of repository URLs.
func baseArch(arch string) string {
	switch {
	case len(arch) == 4 && arch[0] == 'i' && arch[2:] == "86":
		return "i386"
	case strings.HasPrefix(arch, "armv"):
		return "armhfp"
	default:
		return arch
	}
}
