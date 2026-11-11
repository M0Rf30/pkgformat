package source

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/M0Rf30/pkgformat/deb"
	"github.com/M0Rf30/pkgformat/gpg"
)

// ChangesFormat is the Format of the .changes files this package writes.
const ChangesFormat = "1.8"

// changesDateLayout is the RFC 2822 layout of the Date field.
const changesDateLayout = "Mon, 02 Jan 2006 15:04:05 -0700"

var dateLayouts = []string{
	changesDateLayout, "Mon, 2 Jan 2006 15:04:05 -0700", "2 Jan 2006 15:04:05 -0700",
	"Mon, 02 Jan 2006 15:04:05 MST", "Mon, 2 Jan 2006 15:04:05 MST",
}

func parseDate(v string) (time.Time, error) {
	v = strings.TrimSpace(v)

	for _, l := range dateLayouts {
		if t, err := time.Parse(l, v); err == nil {
			return t, nil
		}
	}

	return time.Time{}, fmt.Errorf("%w: date %q", ErrInvalid, v)
}

// BinaryDescription is one line of the Description field of a .changes file:
// a binary package and its synopsis.
type BinaryDescription struct {
	Package string
	Summary string
}

// Changes is a Debian .changes file, the description of an upload.
type Changes struct {
	// Format is the changes format, "1.8" for current dpkg.
	Format string
	Date   time.Time
	Source string
	// Binary lists the binary packages of the upload.
	Binary []string
	// BuiltForProfiles lists the build profiles the upload was built with.
	BuiltForProfiles []string
	// Architecture lists the architectures: "source", "all", "amd64", ...
	Architecture []string
	Version      string
	Distribution string
	Urgency      string
	Maintainer   string
	ChangedBy    string
	Description  []BinaryDescription
	// Closes lists the bug numbers the upload closes.
	Closes []int
	// Changes is the text of the changelog entries, one logical line per line
	// and an empty line for a paragraph break.
	Changes string
	// Files lists the files with every digest the document carries, and their
	// Section and Priority.
	Files []FileRef
	// Extra holds the fields not modelled above, in document order.
	Extra []Field
}

var changesKnown = nameSet(
	"Format", "Date", "Source", "Binary", "Built-For-Profiles", "Architecture", "Version", "Distribution",
	"Urgency", "Maintainer", "Changed-By", "Description", "Closes", "Changes",
	"Files", "Checksums-Sha1", "Checksums-Sha256", "Checksums-Sha512",
)

var changesFileLists = fileListSpec{
	kinds:           []int{hashSHA1, hashSHA256, hashSHA512, hashMD5},
	md5Field:        "Files",
	sectionPriority: true,
}

// ParseChanges parses a .changes file, clear-signed or not. A signature is not
// verified: use [ParseSignedChanges] for that.
func ParseChanges(data []byte) (*Changes, error) {
	cf, _, err := openDocument(data)
	if err != nil {
		return nil, err
	}

	return changesFromControl(cf)
}

// ReadChanges reads and parses a .changes file from r, reading at most
// [MaxDocumentBytes].
func ReadChanges(r io.Reader) (*Changes, error) {
	data, err := readLimited(r)
	if err != nil {
		return nil, err
	}

	return ParseChanges(data)
}

// ParseSignedChanges verifies the clear-signed .changes file against kr and
// parses it. An unsigned file fails with [ErrNotSigned].
func ParseSignedChanges(data []byte, kr *gpg.Keyring) (*Changes, gpg.Verified, error) {
	cf, who, err := openVerified(data, kr)
	if err != nil {
		return nil, gpg.Verified{}, err
	}

	c, err := changesFromControl(cf)
	if err != nil {
		return nil, gpg.Verified{}, err
	}

	return c, who, nil
}

func readLimited(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxDocumentBytes+1))
	if err != nil {
		return nil, err
	}

	if len(data) > MaxDocumentBytes {
		return nil, fmt.Errorf("%w: document over %d bytes", ErrTooLarge, MaxDocumentBytes)
	}

	return data, nil
}

func changesFromControl(cf *deb.ControlFile) (*Changes, error) {
	c := &Changes{
		Format:           strings.TrimSpace(cf.Get("Format")),
		Source:           strings.TrimSpace(cf.Get("Source")),
		Binary:           splitWords(cf.Get("Binary")),
		BuiltForProfiles: splitWords(cf.Get("Built-For-Profiles")),
		Architecture:     splitWords(cf.Get("Architecture")),
		Version:          strings.TrimSpace(cf.Get("Version")),
		Distribution:     strings.TrimSpace(cf.Get("Distribution")),
		Urgency:          strings.TrimSpace(cf.Get("Urgency")),
		Maintainer:       cf.Get("Maintainer"),
		ChangedBy:        cf.Get("Changed-By"),
		Changes:          strings.TrimPrefix(cf.Get("Changes"), "\n"),
		Extra:            unknownFields(cf, changesKnown),
	}

	if c.Format == "" || c.Source == "" || c.Version == "" {
		return nil, fmt.Errorf("%w: .changes needs Format, Source and Version", ErrInvalid)
	}

	if !sourceNameRE.MatchString(c.Source) || !deb.ValidVersion(c.Version) {
		return nil, fmt.Errorf("%w: .changes Source %q Version %q", ErrInvalid, c.Source, c.Version)
	}

	if v, ok := cf.Lookup("Date"); ok {
		t, err := parseDate(v)
		if err != nil {
			return nil, err
		}

		c.Date = t
	}

	for _, line := range strings.Split(cf.Get("Description"), "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}

		name, summary, ok := strings.Cut(line, " - ")
		if !ok {
			return nil, fmt.Errorf("%w: Description line %q", ErrInvalid, line)
		}

		c.Description = append(c.Description, BinaryDescription{Package: strings.TrimSpace(name), Summary: strings.TrimSpace(summary)})
	}

	for _, w := range splitWords(cf.Get("Closes")) {
		n, err := strconv.Atoi(w)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("%w: Closes entry %q", ErrInvalid, w)
		}

		c.Closes = append(c.Closes, n)
	}

	files, err := parseFileLists(cf, 2, "Files")
	if err != nil {
		return nil, err
	}

	c.Files = files

	return c, nil
}

// Control renders the .changes file as a deb822 paragraph in the order
// dpkg-genchanges writes it.
func (c *Changes) Control() *deb.ControlFile {
	p := newParagraph()
	p.add("Format", c.Format)

	if !c.Date.IsZero() {
		p.add("Date", c.Date.Format(changesDateLayout))
	}

	p.add("Source", c.Source)
	p.add("Binary", strings.Join(c.Binary, " "))
	p.add("Built-For-Profiles", strings.Join(c.BuiltForProfiles, " "))
	p.add("Architecture", strings.Join(c.Architecture, " "))
	p.add("Version", c.Version)
	p.add("Distribution", c.Distribution)
	p.add("Urgency", c.Urgency)
	p.add("Maintainer", c.Maintainer)
	p.add("Changed-By", c.ChangedBy)

	if len(c.Description) > 0 {
		var sb strings.Builder

		for _, d := range c.Description {
			fmt.Fprintf(&sb, "\n%-10s - %s", d.Package, d.Summary)
		}

		p.add("Description", sb.String())
	}

	if len(c.Closes) > 0 {
		words := make([]string, len(c.Closes))
		for i, n := range c.Closes {
			words[i] = strconv.Itoa(n)
		}

		p.add("Closes", strings.Join(words, " "))
	}

	if c.Changes != "" {
		p.add("Changes", "\n"+c.Changes)
	}

	p.addFiles(c.Files, changesFileLists)
	p.addExtra(c.Extra)

	return p.cf
}

// Marshal renders the .changes file without a signature.
func (c *Changes) Marshal() ([]byte, error) {
	if c.Format == "" || c.Source == "" || c.Version == "" {
		return nil, fmt.Errorf("%w: Format, Source and Version are required", ErrInvalid)
	}

	for _, f := range c.Files {
		if err := validFileName(f.Name); err != nil {
			return nil, err
		}
	}

	return []byte(c.Control().String()), nil
}

// Sign returns the .changes file clear-signed with signer.
func (c *Changes) Sign(signer gpg.Signer) ([]byte, error) {
	body, err := c.Marshal()
	if err != nil {
		return nil, err
	}

	return clearsign(signer, body)
}

// File returns the file entry named name, or nil.
func (c *Changes) File(name string) *FileRef {
	for i := range c.Files {
		if c.Files[i].Name == name {
			return &c.Files[i]
		}
	}

	return nil
}

// InstalledPackage is one entry of Installed-Build-Depends: a package at the
// exact version that was installed for the build.
type InstalledPackage struct {
	Name string
	// Architecture is set when the entry names one ("libc6:amd64").
	Architecture string
	Version      string
}

// String renders the entry as "name (= version)".
func (p InstalledPackage) String() string {
	name := p.Name
	if p.Architecture != "" {
		name += ":" + p.Architecture
	}

	return name + " (= " + p.Version + ")"
}

// EnvVar is one variable of the Environment field of a .buildinfo file.
type EnvVar struct {
	Name  string
	Value string
}

// BuildInfo is a Debian .buildinfo file, the record of a build.
type BuildInfo struct {
	// Format is the buildinfo format, "1.0".
	Format       string
	Source       string
	Binary       []string
	Architecture []string
	Version      string
	// BinaryOnlyChanges is the changelog text of a binary-only upload.
	BinaryOnlyChanges string
	// Files lists the files the build produced, with their digests (the
	// Checksums-Md5, Checksums-Sha1 and Checksums-Sha256 fields).
	Files             []FileRef
	BuildOrigin       string
	BuildArchitecture string
	BuildDate         time.Time
	BuildKernel       string
	BuildPath         string
	// BuildTaintedBy lists the reasons the build environment is tainted.
	BuildTaintedBy []string
	// InstalledBuildDepends lists the packages installed for the build.
	InstalledBuildDepends []InstalledPackage
	// Environment holds the whitelisted variables of the build environment.
	Environment []EnvVar
	// Extra holds the fields not modelled above, in document order.
	Extra []Field
}

var buildInfoKnown = nameSet(
	"Format", "Source", "Binary", "Architecture", "Version", "Binary-Only-Changes",
	"Checksums-Md5", "Checksums-Sha1", "Checksums-Sha256", "Checksums-Sha512",
	"Build-Origin", "Build-Architecture", "Build-Date", "Build-Kernel-Version", "Build-Path",
	"Build-Tainted-By", "Installed-Build-Depends", "Environment",
)

var buildInfoFileLists = fileListSpec{
	kinds:    []int{hashMD5, hashSHA1, hashSHA256, hashSHA512},
	md5Field: "Checksums-Md5",
}

// ParseBuildInfo parses a .buildinfo file, clear-signed or not. A signature is
// not verified: use [ParseSignedBuildInfo] for that.
func ParseBuildInfo(data []byte) (*BuildInfo, error) {
	cf, _, err := openDocument(data)
	if err != nil {
		return nil, err
	}

	return buildInfoFromControl(cf)
}

// ReadBuildInfo reads and parses a .buildinfo file from r, reading at most
// [MaxDocumentBytes].
func ReadBuildInfo(r io.Reader) (*BuildInfo, error) {
	data, err := readLimited(r)
	if err != nil {
		return nil, err
	}

	return ParseBuildInfo(data)
}

// ParseSignedBuildInfo verifies the clear-signed .buildinfo file against kr and
// parses it. An unsigned file fails with [ErrNotSigned].
func ParseSignedBuildInfo(data []byte, kr *gpg.Keyring) (*BuildInfo, gpg.Verified, error) {
	cf, who, err := openVerified(data, kr)
	if err != nil {
		return nil, gpg.Verified{}, err
	}

	b, err := buildInfoFromControl(cf)
	if err != nil {
		return nil, gpg.Verified{}, err
	}

	return b, who, nil
}

func buildInfoFromControl(cf *deb.ControlFile) (*BuildInfo, error) {
	b := &BuildInfo{
		Format:            strings.TrimSpace(cf.Get("Format")),
		Source:            strings.TrimSpace(cf.Get("Source")),
		Binary:            splitWords(cf.Get("Binary")),
		Architecture:      splitWords(cf.Get("Architecture")),
		Version:           strings.TrimSpace(cf.Get("Version")),
		BinaryOnlyChanges: strings.TrimPrefix(cf.Get("Binary-Only-Changes"), "\n"),
		BuildOrigin:       strings.TrimSpace(cf.Get("Build-Origin")),
		BuildArchitecture: strings.TrimSpace(cf.Get("Build-Architecture")),
		BuildKernel:       strings.TrimSpace(cf.Get("Build-Kernel-Version")),
		BuildPath:         strings.TrimSpace(cf.Get("Build-Path")),
		BuildTaintedBy:    splitWords(cf.Get("Build-Tainted-By")),
		Extra:             unknownFields(cf, buildInfoKnown),
	}

	if b.Format == "" || b.Source == "" || b.Version == "" {
		return nil, fmt.Errorf("%w: .buildinfo needs Format, Source and Version", ErrInvalid)
	}

	if !sourceNameRE.MatchString(b.Source) || !deb.ValidVersion(b.Version) {
		return nil, fmt.Errorf("%w: .buildinfo Source %q Version %q", ErrInvalid, b.Source, b.Version)
	}

	if v, ok := cf.Lookup("Build-Date"); ok {
		t, err := parseDate(v)
		if err != nil {
			return nil, err
		}

		b.BuildDate = t
	}

	files, err := parseFileLists(cf, 0, "Checksums-Md5")
	if err != nil {
		return nil, err
	}

	b.Files = files

	if err := b.parseInstalled(cf.Get("Installed-Build-Depends")); err != nil {
		return nil, err
	}

	return b, b.parseEnvironment(cf.Get("Environment"))
}

func (b *BuildInfo) parseInstalled(v string) error {
	rels, err := deb.ParseRelations(v)
	if err != nil {
		return fmt.Errorf("%w: Installed-Build-Depends: %w", ErrInvalid, err)
	}

	for _, alts := range rels {
		if len(alts) != 1 || alts[0].Op != "=" {
			return fmt.Errorf("%w: Installed-Build-Depends entry %q is not name (= version)", ErrInvalid, alts.String())
		}

		r := alts[0]
		p := InstalledPackage{Name: r.Name, Architecture: r.Arch, Version: r.Version}

		b.InstalledBuildDepends = append(b.InstalledBuildDepends, p)
	}

	return nil
}

func (b *BuildInfo) parseEnvironment(v string) error {
	for _, line := range strings.Split(v, "\n") {
		if line = strings.TrimSpace(line); line == "" {
			continue
		}

		name, val, ok := strings.Cut(line, "=")
		if !ok || name == "" {
			return fmt.Errorf("%w: Environment line %q", ErrInvalid, line)
		}

		unquoted, err := unquoteEnv(val)
		if err != nil {
			return fmt.Errorf("%w: Environment %s: %w", ErrInvalid, name, err)
		}

		b.Environment = append(b.Environment, EnvVar{Name: name, Value: unquoted})
	}

	return nil
}

// unquoteEnv decodes a double-quoted value with backslash escapes.
func unquoteEnv(v string) (string, error) {
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return "", fmt.Errorf("value %q is not quoted", truncate(v))
	}

	var sb strings.Builder

	body := v[1 : len(v)-1]
	for i := 0; i < len(body); i++ {
		if body[i] == '\\' && i+1 < len(body) {
			i++
		}

		sb.WriteByte(body[i])
	}

	return sb.String(), nil
}

func quoteEnv(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// Control renders the .buildinfo file as a deb822 paragraph in the order
// dpkg-genbuildinfo writes it.
func (b *BuildInfo) Control() *deb.ControlFile {
	p := newParagraph()
	p.add("Format", b.Format)
	p.add("Source", b.Source)
	p.add("Binary", strings.Join(b.Binary, " "))
	p.add("Architecture", strings.Join(b.Architecture, " "))
	p.add("Version", b.Version)

	if b.BinaryOnlyChanges != "" {
		p.add("Binary-Only-Changes", "\n"+b.BinaryOnlyChanges)
	}

	p.addFiles(b.Files, buildInfoFileLists)
	p.add("Build-Origin", b.BuildOrigin)
	p.add("Build-Architecture", b.BuildArchitecture)

	if !b.BuildDate.IsZero() {
		p.add("Build-Date", b.BuildDate.Format(changesDateLayout))
	}

	p.add("Build-Kernel-Version", b.BuildKernel)
	p.add("Build-Path", b.BuildPath)

	if len(b.BuildTaintedBy) > 0 {
		p.add("Build-Tainted-By", "\n"+strings.Join(b.BuildTaintedBy, "\n"))
	}

	if len(b.InstalledBuildDepends) > 0 {
		lines := make([]string, len(b.InstalledBuildDepends))
		for i, d := range b.InstalledBuildDepends {
			lines[i] = d.String()
		}

		p.add("Installed-Build-Depends", "\n"+strings.Join(lines, ",\n"))
	}

	if len(b.Environment) > 0 {
		lines := make([]string, len(b.Environment))
		for i, e := range b.Environment {
			lines[i] = e.Name + "=" + quoteEnv(e.Value)
		}

		p.add("Environment", "\n"+strings.Join(lines, "\n"))
	}

	p.addExtra(b.Extra)

	return p.cf
}

// Marshal renders the .buildinfo file without a signature.
func (b *BuildInfo) Marshal() ([]byte, error) {
	if b.Format == "" || b.Source == "" || b.Version == "" {
		return nil, fmt.Errorf("%w: Format, Source and Version are required", ErrInvalid)
	}

	for _, f := range b.Files {
		if err := validFileName(f.Name); err != nil {
			return nil, err
		}
	}

	return []byte(b.Control().String()), nil
}

// Sign returns the .buildinfo file clear-signed with signer.
func (b *BuildInfo) Sign(signer gpg.Signer) ([]byte, error) {
	body, err := b.Marshal()
	if err != nil {
		return nil, err
	}

	return clearsign(signer, body)
}
