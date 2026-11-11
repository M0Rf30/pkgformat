package source

import (
	"bytes"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

// Format is the Format field of a .dsc: the layout of the source package.
type Format string

// The source formats.
const (
	// Format10 is the original layout: an orig.tar.gz and a .diff.gz, or a
	// single .tar.gz for a native package.
	Format10 Format = "1.0"
	// FormatQuilt is "3.0 (quilt)": orig tarballs, a debian tarball and the
	// patches of debian/patches/series.
	FormatQuilt Format = "3.0 (quilt)"
	// FormatNative is "3.0 (native)": one tarball.
	FormatNative Format = "3.0 (native)"
	// FormatGit is "3.0 (git)": a git repository bundle. It is parsed and
	// written but cannot be unpacked here.
	FormatGit Format = "3.0 (git)"
	// FormatCustom is "3.0 (custom)": files chosen by the packager.
	FormatCustom Format = "3.0 (custom)"
)

// Known reports whether f is one of the formats dpkg-source knows.
func (f Format) Known() bool {
	switch f {
	case Format10, FormatQuilt, FormatNative, FormatGit, FormatCustom, "2.0":
		return true
	}

	return false
}

// PackageListEntry is one line of the Package-List field: a binary package the
// source builds.
type PackageListEntry struct {
	Name     string
	Type     string // "deb", "udeb", ...
	Section  string
	Priority string
	// Options are the key=value words after the priority: "arch=any",
	// "essential=yes", "profile=!noudeb".
	Options []string
}

// String renders the entry as a Package-List line, without the leading space.
func (e PackageListEntry) String() string {
	words := append([]string{e.Name, e.Type, e.Section, e.Priority}, e.Options...)

	return strings.Join(words, " ")
}

// DSC is a Debian source control file.
type DSC struct {
	Format Format
	// Source is the source package name.
	Source string
	// Binary lists the binary packages the source builds.
	Binary []string
	// Architecture lists the architecture words ("any", "all", "amd64").
	Architecture []string
	// Version is the full version, with epoch and Debian revision.
	Version string

	Origin           string
	Maintainer       string
	Uploaders        string
	Homepage         string
	StandardsVersion string

	// Vcs holds the Vcs-Browser, Vcs-Git, ... fields by canonical name.
	Vcs map[string]string

	// Testsuite is the comma separated Testsuite field.
	Testsuite         string
	TestsuiteTriggers string
	// Dgit is the Dgit field a dgit upload adds.
	Dgit string

	// The build relationship fields as written; Relations parses them.
	BuildDepends        string
	BuildDependsArch    string
	BuildDependsIndep   string
	BuildConflicts      string
	BuildConflictsArch  string
	BuildConflictsIndep string

	PackageList []PackageListEntry

	// Files lists the files of the source package, with every digest the
	// document carries (Files, Checksums-Sha1, Checksums-Sha256,
	// Checksums-Sha512).
	Files []FileRef

	// Extra holds the fields not modelled above, in document order.
	Extra []Field
}

// vcsFields is the order dpkg writes the Vcs fields in.
var vcsFields = []string{
	"Vcs-Browser", "Vcs-Arch", "Vcs-Bzr", "Vcs-Cvs", "Vcs-Darcs", "Vcs-Git", "Vcs-Hg", "Vcs-Mtn", "Vcs-Svn",
}

var dscKnown = nameSet(
	"Format", "Source", "Binary", "Architecture", "Version", "Origin", "Maintainer", "Uploaders",
	"Homepage", "Standards-Version", "Testsuite", "Testsuite-Triggers", "Dgit",
	"Build-Depends", "Build-Depends-Arch", "Build-Depends-Indep",
	"Build-Conflicts", "Build-Conflicts-Arch", "Build-Conflicts-Indep",
	"Package-List", "Files", "Checksums-Sha1", "Checksums-Sha256", "Checksums-Sha512",
	"Vcs-Browser", "Vcs-Arch", "Vcs-Bzr", "Vcs-Cvs", "Vcs-Darcs", "Vcs-Git", "Vcs-Hg", "Vcs-Mtn", "Vcs-Svn",
)

// dscFileLists is how a .dsc lists its files: the strong hashes first, the MD5
// list ("Files") last.
var dscFileLists = fileListSpec{
	kinds:    []int{hashSHA1, hashSHA256, hashSHA512, hashMD5},
	md5Field: "Files",
}

var sourceNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)

// ParseDSC parses a .dsc, clear-signed or not. A signature is not verified:
// use [ParseSignedDSC] for that.
func ParseDSC(data []byte) (*DSC, error) {
	cf, _, err := openDocument(data)
	if err != nil {
		return nil, err
	}

	return dscFromControl(cf, false)
}

// ReadDSC reads and parses a .dsc from r, reading at most [MaxDocumentBytes].
func ReadDSC(r io.Reader) (*DSC, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return nil, err
	}

	return ParseDSC(data)
}

// ParseSignedDSC verifies the clear-signed .dsc against kr and parses it. The
// error wraps a [gpg] sentinel for a bad or unknown signature and is
// [ErrNotSigned] for an unsigned file.
func ParseSignedDSC(data []byte, kr *gpg.Keyring) (*DSC, gpg.Verified, error) {
	cf, who, err := openVerified(data, kr)
	if err != nil {
		return nil, gpg.Verified{}, err
	}

	d, err := dscFromControl(cf, false)
	if err != nil {
		return nil, gpg.Verified{}, err
	}

	return d, who, nil
}

// dscFromControl reads a .dsc paragraph, or with index a stanza of a Sources
// index, which names the source "Package" and may lack the Format.
func dscFromControl(cf *deb.ControlFile, index bool) (*DSC, error) {
	known, sourceField := dscKnown, "Source"
	if index {
		known, sourceField = indexKnown, "Package"
	}

	d := &DSC{
		Format:              Format(strings.TrimSpace(cf.Get("Format"))),
		Source:              strings.TrimSpace(cf.Get(sourceField)),
		Binary:              splitList(cf.Get("Binary")),
		Architecture:        splitWords(cf.Get("Architecture")),
		Version:             strings.TrimSpace(cf.Get("Version")),
		Origin:              cf.Get("Origin"),
		Maintainer:          cf.Get("Maintainer"),
		Uploaders:           cf.Get("Uploaders"),
		Homepage:            cf.Get("Homepage"),
		StandardsVersion:    cf.Get("Standards-Version"),
		Testsuite:           cf.Get("Testsuite"),
		TestsuiteTriggers:   cf.Get("Testsuite-Triggers"),
		Dgit:                cf.Get("Dgit"),
		BuildDepends:        cf.Get("Build-Depends"),
		BuildDependsArch:    cf.Get("Build-Depends-Arch"),
		BuildDependsIndep:   cf.Get("Build-Depends-Indep"),
		BuildConflicts:      cf.Get("Build-Conflicts"),
		BuildConflictsArch:  cf.Get("Build-Conflicts-Arch"),
		BuildConflictsIndep: cf.Get("Build-Conflicts-Indep"),
		Extra:               unknownFields(cf, known),
	}

	for _, name := range vcsFields {
		if v, ok := cf.Lookup(name); ok {
			if d.Vcs == nil {
				d.Vcs = map[string]string{}
			}

			d.Vcs[name] = v
		}
	}

	if d.Format == "" && index {
		d.Format = Format10
	}

	if d.Format == "" {
		return nil, fmt.Errorf("%w: .dsc has no Format field", ErrInvalid)
	}

	if !sourceNameRE.MatchString(d.Source) {
		return nil, fmt.Errorf("%w: .dsc Source %q", ErrInvalid, d.Source)
	}

	if d.Version == "" || !deb.ValidVersion(d.Version) {
		return nil, fmt.Errorf("%w: .dsc Version %q", ErrInvalid, d.Version)
	}

	for _, line := range strings.Split(cf.Get("Package-List"), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}

		w := strings.Fields(line)
		if len(w) < 4 {
			return nil, fmt.Errorf("%w: Package-List line %q", ErrInvalid, line)
		}

		d.PackageList = append(d.PackageList, PackageListEntry{
			Name: w[0], Type: w[1], Section: w[2], Priority: w[3], Options: w[4:],
		})
	}

	files, err := parseFileLists(cf, 0, "Files")
	if err != nil {
		return nil, err
	}

	d.Files = files

	return d, nil
}

// Control renders the .dsc as a deb822 paragraph in the order dpkg-source
// writes the fields: the Files field comes last, preceded by the Checksums
// fields. A checksum field is written for every hash that a file carries.
func (d *DSC) Control() *deb.ControlFile {
	p := newParagraph()
	p.add("Format", string(d.Format))
	p.add("Source", d.Source)
	p.add("Binary", strings.Join(d.Binary, ", "))
	p.add("Architecture", strings.Join(d.Architecture, " "))
	p.add("Version", d.Version)
	p.add("Origin", d.Origin)
	p.add("Maintainer", d.Maintainer)
	p.add("Uploaders", d.Uploaders)
	p.add("Homepage", d.Homepage)
	p.add("Standards-Version", d.StandardsVersion)

	for _, name := range vcsFields {
		p.add(name, d.Vcs[name])
	}

	p.add("Testsuite", d.Testsuite)
	p.add("Testsuite-Triggers", d.TestsuiteTriggers)
	p.add("Build-Depends", d.BuildDepends)
	p.add("Build-Depends-Arch", d.BuildDependsArch)
	p.add("Build-Depends-Indep", d.BuildDependsIndep)
	p.add("Build-Conflicts", d.BuildConflicts)
	p.add("Build-Conflicts-Arch", d.BuildConflictsArch)
	p.add("Build-Conflicts-Indep", d.BuildConflictsIndep)

	if len(d.PackageList) > 0 {
		var sb strings.Builder
		for _, e := range d.PackageList {
			sb.WriteString("\n")
			sb.WriteString(e.String())
		}

		p.add("Package-List", sb.String())
	}

	p.addFiles(d.Files, dscFileLists)

	// Dgit and the unknown fields follow, as dpkg sorts them after the known ones.
	p.addExtra(d.Extra)
	p.add("Dgit", d.Dgit)

	return p.cf
}

// Marshal renders the .dsc body, without a signature, as dpkg-source writes it.
func (d *DSC) Marshal() ([]byte, error) {
	if d.Format == "" || d.Source == "" || d.Version == "" {
		return nil, fmt.Errorf("%w: Format, Source and Version are required", ErrInvalid)
	}

	for _, f := range d.Files {
		if err := validFileName(f.Name); err != nil {
			return nil, err
		}
	}

	return []byte(d.Control().String()), nil
}

// Sign returns the .dsc clear-signed with signer.
func (d *DSC) Sign(signer gpg.Signer) ([]byte, error) {
	body, err := d.Marshal()
	if err != nil {
		return nil, err
	}

	return clearsign(signer, body)
}

func clearsign(signer gpg.Signer, body []byte) ([]byte, error) {
	if signer == nil {
		return nil, deb.ErrNoSigner
	}

	r, err := signer.CleartextSign(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("source: signing: %w", err)
	}

	out, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return nil, fmt.Errorf("source: reading signature: %w", err)
	}

	return out, nil
}

// Relations parses one of the build relationship fields ("Build-Depends",
// "Build-Depends-Arch", "Build-Depends-Indep", "Build-Conflicts",
// "Build-Conflicts-Arch", "Build-Conflicts-Indep") with [deb.ParseRelations].
func (d *DSC) Relations(field string) ([]deb.Alternatives, error) {
	var v string

	switch strings.ToLower(field) {
	case "build-depends":
		v = d.BuildDepends
	case "build-depends-arch":
		v = d.BuildDependsArch
	case "build-depends-indep":
		v = d.BuildDependsIndep
	case "build-conflicts":
		v = d.BuildConflicts
	case "build-conflicts-arch":
		v = d.BuildConflictsArch
	case "build-conflicts-indep":
		v = d.BuildConflictsIndep
	default:
		return nil, fmt.Errorf("%w: %q is not a build relationship field", ErrInvalid, field)
	}

	return deb.ParseRelations(v)
}

// File returns the file entry named name, or nil.
func (d *DSC) File(name string) *FileRef {
	for i := range d.Files {
		if d.Files[i].Name == name {
			return &d.Files[i]
		}
	}

	return nil
}
