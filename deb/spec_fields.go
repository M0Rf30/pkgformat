package deb

import (
	"io/fs"
	"regexp"
	"strings"
)

// Field is a control field with an arbitrary name, written after the fields a
// Spec has a member for. The order of Spec.Fields is the order in the control
// file.
type Field struct {
	// Name is the field name as it is written: "Rules-Requires-Root",
	// "X-Packager".
	Name string
	// Value is the logical value. A multi-line value (a Tag list, say) is
	// written with continuation lines; a blank line in it is encoded as " .".
	Value string
}

// fieldNamePattern is what dpkg accepts as a field name: it starts with a
// letter or digit and goes on with letters, digits and "-" or "_".
var fieldNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)

func validFieldName(name string) error {
	if !fieldNamePattern.MatchString(name) {
		return invalidSpec("field name %q is not valid", name)
	}

	return nil
}

// specManaged lists the fields the members of Spec produce, by lower-case
// name and the member that sets them. Fields cannot set them a second time.
var specManaged = map[string]string{
	"package": "Name", "version": "Version", "architecture": "Architecture",
	"section": "Section", "priority": "Priority", "maintainer": "Maintainer",
	"source": "SourcePkg", "installed-size": "InstalledSize", "description": "Description",
	"homepage": "URL", "bugs": "Bugs", "multi-arch": "MultiArch",
	"essential": "Essential", "protected": "Protected",
	"provides": "Provides", "pre-depends": "PreDepends", "depends": "Depends",
	"conflicts": "Conflicts", "breaks": "Breaks", "replaces": "Replaces",
	"recommends": "Recommends", "suggests": "Suggests", "enhances": "Enhances",
	"built-using": "BuiltUsing", "static-built-using": "StaticBuiltUsing",
}

// yesNoFields hold "yes" or "no".
var yesNoFields = map[string]bool{"important": true, "build-essential": true}

// buildRelationFields are the dependency fields of a source package; their
// values may carry architecture and profile restrictions.
var buildRelationFields = map[string]bool{
	"build-depends": true, "build-depends-indep": true, "build-depends-arch": true,
	"build-conflicts": true, "build-conflicts-indep": true, "build-conflicts-arch": true,
}

var (
	md5HexPattern    = regexp.MustCompile(`^[0-9a-f]{32}$`)
	rootKeywordRegex = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*(/[a-z0-9-]+)+$`)
	packageTypes     = map[string]bool{"deb": true, "udeb": true, "ddeb": true}
	debugSymbols     = "debug-symbols"
)

// validate checks the field the way dpkg or policy reads it, for the fields
// that have a defined syntax; any other field only has to be well-formed.
func (f Field) validate() error {
	if err := validFieldName(f.Name); err != nil {
		return err
	}

	lower := strings.ToLower(f.Name)

	if member, ok := specManaged[lower]; ok {
		return invalidSpec("field %q is written from Spec.%s", f.Name, member)
	}

	if strings.ContainsRune(f.Value, 0) || strings.ContainsRune(f.Value, '\r') {
		return invalidSpec("field %q holds a NUL or CR character", f.Name)
	}

	if strings.TrimSpace(f.Value) == "" {
		return invalidSpec("field %q is empty", f.Name)
	}

	switch {
	case yesNoFields[lower]:
		return enum(f, "yes", "no")
	case lower == "rules-requires-root":
		return validRulesRequiresRoot(f)
	case lower == "description-md5":
		if !md5HexPattern.MatchString(f.Value) {
			return invalidSpec("field %q must be 32 lower-case hex digits", f.Name)
		}
	case lower == "package-type":
		if !packageTypes[f.Value] {
			return invalidSpec("field %q is %q, want deb, udeb or ddeb", f.Name, f.Value)
		}
	case lower == "auto-built-package":
		if f.Value != debugSymbols {
			return invalidSpec("field %q is %q, want %s", f.Name, f.Value, debugSymbols)
		}
	case buildRelationFields[lower]:
		if _, err := ParseRelations(f.Value); err != nil {
			return invalidSpec("field %q: %v", f.Name, err)
		}
	case lower == "original-maintainer", lower == "origin", strings.HasPrefix(lower, "vcs-"):
		return singleLine(f)
	}

	return nil
}

func singleLine(f Field) error {
	if strings.ContainsRune(f.Value, '\n') {
		return invalidSpec("field %q must be on one line", f.Name)
	}

	return nil
}

func enum(f Field, allowed ...string) error {
	for _, a := range allowed {
		if f.Value == a {
			return nil
		}
	}

	return invalidSpec("field %q is %q, want one of %s", f.Name, f.Value, strings.Join(allowed, ", "))
}

// validRulesRequiresRoot accepts "no", "binary-targets", or a list of
// keywords "namespace/name" (dpkg-buildpackage(1)).
func validRulesRequiresRoot(f Field) error {
	if strings.ContainsRune(f.Value, '\n') {
		return invalidSpec("field %q must be on one line", f.Name)
	}

	words := strings.Fields(f.Value)
	if len(words) == 0 {
		return invalidSpec("field %q is empty", f.Name)
	}

	for _, w := range words {
		if w == "no" || w == "binary-targets" {
			if len(words) != 1 {
				return invalidSpec("field %q: %q cannot be combined with other values", f.Name, w)
			}

			continue
		}

		if !rootKeywordRegex.MatchString(w) {
			return invalidSpec("field %q: %q is not no, binary-targets or a namespace/name keyword", f.Name, w)
		}
	}

	return nil
}

// validateFields checks the free-form fields of a spec.
func validateFields(fields []Field) error {
	seen := make(map[string]bool, len(fields))

	for _, f := range fields {
		if err := f.validate(); err != nil {
			return err
		}

		lower := strings.ToLower(f.Name)
		if seen[lower] {
			return invalidSpec("field %q is given twice", f.Name)
		}

		seen[lower] = true
	}

	return nil
}

// relationRules describe what a dependency field of a binary package may
// hold.
type relationRules struct {
	// alternatives allows "a | b".
	alternatives bool
	// onlyEqual limits the operator to "=" (Provides, Built-Using).
	onlyEqual bool
	// needVersion requires an "= version" constraint (Built-Using).
	needVersion bool
	// archQualifier allows ":any" and ":arch" after the name.
	archQualifier bool
}

// Rules per relationship field. Restrictions ("[amd64]", "<!nocheck>") are
// never valid in a binary package: dpkg refuses to read them.
var (
	depRules      = relationRules{alternatives: true, archQualifier: true}
	conflictRules = relationRules{archQualifier: true}
	replaceRules  = relationRules{archQualifier: true}
	provideRules  = relationRules{onlyEqual: true}
	builtRules    = relationRules{onlyEqual: true, needVersion: true}
)

var relationOps = map[string]bool{"<<": true, "<=": true, "=": true, ">=": true, ">>": true}

// ParseRelationList parses entries, each a control-file dependency or several
// joined by commas ("libc6 (>= 2.31)", "a | b, c"), into the typed form the
// relationship fields of Spec take. It keeps restrictions on the relations;
// Spec.Validate then rejects those, which are not valid in a binary package.
func ParseRelationList(entries ...string) ([]Alternatives, error) {
	return ParseRelations(strings.Join(entries, ", "))
}

// validateRelations checks the relations of one field against rules.
func validateRelations(field string, list []Alternatives, rules relationRules) error {
	for _, alts := range list {
		if len(alts) == 0 {
			return invalidSpec("%s holds an empty alternative group", field)
		}

		if len(alts) > 1 && !rules.alternatives {
			return invalidSpec("%s does not allow alternatives: %q", field, alts.String())
		}

		for _, r := range alts {
			if err := validateRelation(field, r, rules); err != nil {
				return err
			}
		}
	}

	return nil
}

func validateRelation(field string, r Relation, rules relationRules) error {
	if !namePattern.MatchString(r.Name) {
		return invalidSpec("%s: package name %q is not valid", field, r.Name)
	}

	if len(r.ArchRestrictions) > 0 || len(r.ProfileGroups) > 0 {
		return invalidSpec("%s: %q has architecture or profile restrictions, not valid in a binary package", field, r.String())
	}

	if r.Arch != "" {
		if !rules.archQualifier || r.Arch == "native" || !archPattern.MatchString(r.Arch) {
			return invalidSpec("%s: architecture qualifier %q on %q is not valid here", field, r.Arch, r.Name)
		}
	}

	if r.Op == "" {
		if r.Version != "" {
			return invalidSpec("%s: %q has a version but no operator", field, r.Name)
		}

		if rules.needVersion {
			return invalidSpec("%s: %q needs an \"= version\" constraint", field, r.Name)
		}

		return nil
	}

	if !relationOps[r.Op] {
		return invalidSpec("%s: operator %q on %q is not one of << <= = >= >>", field, r.Op, r.Name)
	}

	if rules.onlyEqual && r.Op != "=" {
		return invalidSpec("%s: %q must use the operator =", field, r.String())
	}

	if !ValidVersion(r.Version) {
		return invalidSpec("%s: version %q of %q is not valid", field, r.Version, r.Name)
	}

	return nil
}

// checkSingleLine reports a line break in a one-line value.
func checkSingleLine(name, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return invalidSpec("%s holds a line break", name)
	}

	return nil
}

// controlMemberNames are the members of the control archive that Spec writes
// itself, by file name and the member of Spec that fills it.
var controlMemberNames = map[string]string{
	"control": "the fields of Spec", "md5sums": "the payload", "conffiles": "Conffiles",
	"copyright": "Licenses", "triggers": "Triggers", "shlibs": "Shlibs", "symbols": "Symbols",
	"preinst": "Scripts.Preinst", "postinst": "Scripts.Postinst", "prerm": "Scripts.Prerm",
	"postrm": "Scripts.Postrm", "config": "Scripts.Config", "templates": "Scripts.Templates",
}

var controlMemberNamePattern = regexp.MustCompile(`^[A-Za-z0-9_+][A-Za-z0-9._+-]*$`)

// validScriptMode follows dpkg-deb: a maintainer script is a plain
// file readable and executable by everybody, writable by its owner only, with
// no special bit.
func validScriptMode(name string, m fs.FileMode) error {
	if m&^0o777 != 0 {
		return invalidSpec("mode of %s holds more than permission bits", name)
	}

	switch name {
	case "preinst", "postinst", "prerm", "postrm":
		if m&0o7557 != 0o555 {
			return invalidSpec("mode %03o of %s is not between 0555 and 0775", uint32(m), name)
		}
	}

	return nil
}

func (s *Spec) validateControlMembers() error {
	for _, sm := range [...]struct {
		name string
		mode fs.FileMode
	}{
		{"preinst", s.Scripts.Modes.Preinst}, {"postinst", s.Scripts.Modes.Postinst},
		{"prerm", s.Scripts.Modes.Prerm}, {"postrm", s.Scripts.Modes.Postrm},
		{"config", s.Scripts.Modes.Config}, {"templates", s.Scripts.Modes.Templates},
	} {
		if sm.mode == 0 {
			continue
		}

		if err := validScriptMode(sm.name, sm.mode); err != nil {
			return err
		}
	}

	for _, t := range s.Triggers {
		if err := t.validate(); err != nil {
			return err
		}
	}

	for _, sh := range s.Shlibs {
		if err := sh.validate(); err != nil {
			return err
		}
	}

	for _, l := range s.Symbols {
		if err := l.validate(); err != nil {
			return err
		}
	}

	seen := make(map[string]bool, len(s.ExtraControl))

	for _, m := range s.ExtraControl {
		if !controlMemberNamePattern.MatchString(m.Name) {
			return invalidSpec("control member name %q is not valid", m.Name)
		}

		if from, ok := controlMemberNames[m.Name]; ok {
			return invalidSpec("control member %q is written from %s", m.Name, from)
		}

		if seen[m.Name] {
			return invalidSpec("control member %q is given twice", m.Name)
		}

		seen[m.Name] = true

		if len(m.Data) > MaxControlFileSize {
			return invalidSpec("control member %q is over %d bytes", m.Name, MaxControlFileSize)
		}

		if err := validScriptMode(m.Name, m.Mode); err != nil {
			return err
		}
	}

	return nil
}

// dataCompression returns the method and level of the data archive.
func (s *Spec) dataCompression() (Compression, int) {
	c, _ := ParseCompression(s.Compression) // validated

	return c, s.CompressionLevel
}

// controlCompression returns the method and level of the control archive.
func (s *Spec) controlCompression() (Compression, int) {
	if s.ControlCompression == "" {
		return s.dataCompression()
	}

	c, _ := ParseCompression(s.ControlCompression) // validated

	return c, s.ControlCompressionLevel
}

func (s *Spec) validateCompression() error {
	c, err := ParseCompression(s.Compression)
	if err != nil {
		return err
	}

	if err := checkLevel(c, s.CompressionLevel); err != nil {
		return err
	}

	if s.ControlCompression == "" {
		if s.ControlCompressionLevel != 0 {
			return invalidSpec("ControlCompressionLevel is set without ControlCompression")
		}

		return nil
	}

	cc, err := ParseCompression(s.ControlCompression)
	if err != nil {
		return err
	}

	return checkLevel(cc, s.ControlCompressionLevel)
}
