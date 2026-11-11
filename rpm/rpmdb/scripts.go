package rpmdb

import (
	"context"
	"fmt"
	"iter"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm"
	"github.com/M0Rf30/pkgformat/rpm/richdep"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// Scriptlet is one script of a package: what rpm runs at some step of a
// transaction.
type Scriptlet struct {
	// Body is the text of the script. It is empty for a scriptlet that only
	// names a program, as in "%post -p /sbin/ldconfig".
	Body string
	// Prog is the interpreter: the program followed by its arguments for the
	// scriptlets of a package, "<lua>" for rpm's built-in Lua, the program
	// as stored (one string) for the scripts of triggers.
	Prog []string
	// Flags holds the tag.RPMSCRIPT_FLAG_* bits: macro expansion (%post -e),
	// query format expansion (-q) and the like.
	Flags uint32
}

// TriggerKind is when a trigger runs.
type TriggerKind int

// The kinds of trigger and file trigger.
const (
	// TriggerUnknown is a trigger whose flags name no kind.
	TriggerUnknown TriggerKind = iota
	// TriggerIn runs after the triggering package is installed
	// (%triggerin, %filetriggerin, %transfiletriggerin).
	TriggerIn
	// TriggerUn runs before the triggering package is removed.
	TriggerUn
	// TriggerPostUn runs after the triggering package is removed.
	TriggerPostUn
	// TriggerPreIn runs before the triggering package is installed
	// (%triggerprein).
	TriggerPreIn
)

// String returns the suffix rpm prints after "trigger": "in", "un", "postun"
// or "prein"; "" for [TriggerUnknown].
func (k TriggerKind) String() string {
	switch k {
	case TriggerIn:
		return "in"
	case TriggerUn:
		return "un"
	case TriggerPostUn:
		return "postun"
	case TriggerPreIn:
		return "prein"
	default:
		return ""
	}
}

// kindOf reads the kind from the flags of a trigger condition.
func kindOf(flags uint32) TriggerKind {
	switch {
	case flags&tag.RPMSENSE_TRIGGERIN != 0:
		return TriggerIn
	case flags&tag.RPMSENSE_TRIGGERUN != 0:
		return TriggerUn
	case flags&tag.RPMSENSE_TRIGGERPOSTUN != 0:
		return TriggerPostUn
	case flags&tag.RPMSENSE_TRIGGERPREIN != 0:
		return TriggerPreIn
	default:
		return TriggerUnknown
	}
}

// Trigger is a script that runs when other packages are installed or removed.
type Trigger struct {
	Kind TriggerKind
	// Conditions are the packages, with versions, that fire the trigger.
	// Their Flags also carry the comparison and the kind of the trigger.
	Conditions []rpm.Dependency
	Script     Scriptlet
}

// FileTrigger is a script that runs when files under some path prefixes are
// installed or removed, for each package (a file trigger) or once per
// transaction (a transaction file trigger).
type FileTrigger struct {
	Kind TriggerKind
	// Prefixes are the directories whose files fire the trigger.
	Prefixes []string
	// Priority orders the file triggers that run together; the higher runs
	// first. rpm's default is 1000000.
	Priority int32
	Script   Scriptlet
}

// Scripts is everything a package runs: its scriptlets, triggers and file
// triggers, read from the raw tags of its header. A scriptlet the package does
// not have is nil.
type Scripts struct {
	PreTrans, PreIn, PostIn, PreUn, PostUn, PostTrans *Scriptlet
	PreUnTrans, PostUnTrans                           *Scriptlet
	Verify                                            *Scriptlet
	Triggers                                          []Trigger
	FileTriggers                                      []FileTrigger
	TransFileTriggers                                 []FileTrigger
}

// PackageScripts is the [Scripts] of one installed package.
type PackageScripts struct {
	Package *rpm.Package
	Scripts *Scripts
}

// scriptTags are the tags of one scriptlet.
type scriptTags struct{ body, prog, flags int }

// readScriptlet reads the scriptlet of a header, nil when it has none.
func readScriptlet(hdr *rpm.RpmHeader, t scriptTags) *Scriptlet {
	if !hdr.HasTag(t.body) && !hdr.HasTag(t.prog) {
		return nil
	}

	s := &Scriptlet{}
	s.Body, _ = hdr.GetString(t.body)
	s.Prog, _ = hdr.GetStrings(t.prog)
	s.Flags, _ = hdr.GetUint32(t.flags)

	return s
}

// scriptsFromHeader decodes the scripts of a header. At most limit triggers
// and conditions are read; a header that declares more fails with ErrTooLarge.
func scriptsFromHeader(hdr *rpm.RpmHeader, limit int) (*Scripts, error) {
	s := &Scripts{
		PreTrans:    readScriptlet(hdr, scriptTags{tag.PRETRANS, tag.PRETRANSPROG, tag.PRETRANSFLAGS}),
		PreIn:       readScriptlet(hdr, scriptTags{tag.PREIN, tag.PREINPROG, tag.PREINFLAGS}),
		PostIn:      readScriptlet(hdr, scriptTags{tag.POSTIN, tag.POSTINPROG, tag.POSTINFLAGS}),
		PreUn:       readScriptlet(hdr, scriptTags{tag.PREUN, tag.PREUNPROG, tag.PREUNFLAGS}),
		PostUn:      readScriptlet(hdr, scriptTags{tag.POSTUN, tag.POSTUNPROG, tag.POSTUNFLAGS}),
		PostTrans:   readScriptlet(hdr, scriptTags{tag.POSTTRANS, tag.POSTTRANSPROG, tag.POSTTRANSFLAGS}),
		PreUnTrans:  readScriptlet(hdr, scriptTags{tag.PREUNTRANS, tag.PREUNTRANSPROG, tag.PREUNTRANSFLAGS}),
		PostUnTrans: readScriptlet(hdr, scriptTags{tag.POSTUNTRANS, tag.POSTUNTRANSPROG, tag.POSTUNTRANSFLAGS}),
		Verify:      readScriptlet(hdr, scriptTags{tag.VERIFYSCRIPT, tag.VERIFYSCRIPTPROG, tag.VERIFYSCRIPTFLAGS}),
	}

	var err error

	s.Triggers, err = readTriggers(hdr, limit, triggerTags{
		scripts: tag.TRIGGERSCRIPTS, prog: tag.TRIGGERSCRIPTPROG, flags: tag.TRIGGERSCRIPTFLAGS,
		name: tag.TRIGGERNAME, version: tag.TRIGGERVERSION, condFlags: tag.TRIGGERFLAGS, index: tag.TRIGGERINDEX,
	})
	if err != nil {
		return nil, err
	}

	s.FileTriggers, err = readFileTriggers(hdr, limit, triggerTags{
		scripts: tag.FILETRIGGERSCRIPTS, prog: tag.FILETRIGGERSCRIPTPROG, flags: tag.FILETRIGGERSCRIPTFLAGS,
		name: tag.FILETRIGGERNAME, version: tag.FILETRIGGERVERSION, condFlags: tag.FILETRIGGERFLAGS, index: tag.FILETRIGGERINDEX,
		priorities: tag.FILETRIGGERPRIORITIES,
	})
	if err != nil {
		return nil, err
	}

	s.TransFileTriggers, err = readFileTriggers(hdr, limit, triggerTags{
		scripts: tag.TRANSFILETRIGGERSCRIPTS, prog: tag.TRANSFILETRIGGERSCRIPTPROG, flags: tag.TRANSFILETRIGGERSCRIPTFLAGS,
		name: tag.TRANSFILETRIGGERNAME, version: tag.TRANSFILETRIGGERVERSION, condFlags: tag.TRANSFILETRIGGERFLAGS,
		index: tag.TRANSFILETRIGGERINDEX, priorities: tag.TRANSFILETRIGGERPRIORITIES,
	})
	if err != nil {
		return nil, err
	}

	return s, nil
}

// triggerTags are the tags of one kind of trigger: the scripts are arrays
// with one element per script, the conditions arrays with one element per
// condition, and index says which script each condition belongs to.
type triggerTags struct {
	scripts, prog, flags            int
	name, version, condFlags, index int
	priorities                      int
}

// triggerScripts reads the scripts of a kind of trigger with the conditions
// that belong to each, as indexes into the conditions.
func triggerScripts(hdr *rpm.RpmHeader, limit int, t triggerTags) (scripts []Scriptlet, conds [][]int, all []rpm.Dependency, err error) {
	bodies, _ := hdr.GetStrings(t.scripts)
	if len(bodies) == 0 {
		return nil, nil, nil, nil
	}

	if len(bodies) > limit {
		return nil, nil, nil, fmt.Errorf("%w: %d trigger scripts exceed %d", ErrTooLarge, len(bodies), limit)
	}

	progs, _ := hdr.GetStrings(t.prog)
	flags, _ := hdr.GetUint32s(t.flags)

	scripts = make([]Scriptlet, len(bodies))
	for i, body := range bodies {
		scripts[i].Body = body

		if i < len(progs) {
			scripts[i].Prog = []string{progs[i]}
		}

		if i < len(flags) {
			scripts[i].Flags = flags[i]
		}
	}

	all, err = hdr.Dependencies(t.name, t.condFlags, t.version)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("rpmdb: trigger conditions: %w", err)
	}

	if len(all) > limit {
		return nil, nil, nil, fmt.Errorf("%w: %d trigger conditions exceed %d", ErrTooLarge, len(all), limit)
	}

	index, _ := hdr.GetUint32s(t.index)
	conds = make([][]int, len(scripts))

	// A condition without an index, or one that points past the scripts,
	// belongs to nothing.
	for i := range all {
		if i < len(index) && int(index[i]) < len(scripts) {
			conds[index[i]] = append(conds[index[i]], i)
		}
	}

	return scripts, conds, all, nil
}

func readTriggers(hdr *rpm.RpmHeader, limit int, t triggerTags) ([]Trigger, error) {
	scripts, conds, all, err := triggerScripts(hdr, limit, t)
	if err != nil || scripts == nil {
		return nil, err
	}

	out := make([]Trigger, len(scripts))

	for i := range scripts {
		out[i].Script = scripts[i]

		for _, c := range conds[i] {
			out[i].Conditions = append(out[i].Conditions, all[c])
		}

		if len(out[i].Conditions) > 0 {
			out[i].Kind = kindOf(out[i].Conditions[0].Flags)
		}
	}

	return out, nil
}

func readFileTriggers(hdr *rpm.RpmHeader, limit int, t triggerTags) ([]FileTrigger, error) {
	scripts, conds, all, err := triggerScripts(hdr, limit, t)
	if err != nil || scripts == nil {
		return nil, err
	}

	var priorities []uint32

	if t.priorities != 0 {
		priorities, _ = hdr.GetUint32s(t.priorities)
	}

	out := make([]FileTrigger, len(scripts))

	for i := range scripts {
		out[i].Script = scripts[i]

		for _, c := range conds[i] {
			out[i].Prefixes = append(out[i].Prefixes, all[c].Name)
		}

		if len(conds[i]) > 0 {
			out[i].Kind = kindOf(all[conds[i][0]].Flags)
		}

		if i < len(priorities) {
			out[i].Priority = int32(priorities[i])
		}
	}

	return out, nil
}

// String renders the scripts as rpm -q --scripts --triggers --filetriggers
// prints them: each scriptlet under its heading, then the triggers, the file
// triggers and the transaction file triggers.
func (s *Scripts) String() string {
	var b strings.Builder

	for _, e := range []struct {
		name string
		s    *Scriptlet
	}{
		{"pretrans", s.PreTrans}, {"preinstall", s.PreIn}, {"postinstall", s.PostIn},
		{"preuninstall", s.PreUn}, {"postuninstall", s.PostUn}, {"posttrans", s.PostTrans},
		{"preuntrans", s.PreUnTrans}, {"postuntrans", s.PostUnTrans}, {"verify", s.Verify},
	} {
		if e.s == nil {
			continue
		}

		if e.s.Body == "" {
			fmt.Fprintf(&b, "%s program: %s\n", e.name, strings.Join(e.s.Prog, " "))

			continue
		}

		fmt.Fprintf(&b, "%s scriptlet (using%s):\n%s\n", e.name, spaced(e.s.Prog), e.s.Body)
	}

	for _, t := range s.Triggers {
		conds := make([]string, len(t.Conditions))
		for i, c := range t.Conditions {
			conds[i] = richdep.AtomOf(c).String()
		}

		writeTrigger(&b, "trigger", t.Kind, &t.Script, conds)
	}

	for _, t := range s.FileTriggers {
		writeTrigger(&b, "filetrigger", t.Kind, &t.Script, t.Prefixes)
	}

	for _, t := range s.TransFileTriggers {
		writeTrigger(&b, "transfiletrigger", t.Kind, &t.Script, t.Prefixes)
	}

	return b.String()
}

func spaced(prog []string) string {
	var b strings.Builder

	for _, p := range prog {
		b.WriteByte(' ')
		b.WriteString(p)
	}

	return b.String()
}

func writeTrigger(b *strings.Builder, prefix string, kind TriggerKind, s *Scriptlet, conds []string) {
	fmt.Fprintf(b, "%s%s scriptlet (using%s) -- %s\n%s\n", prefix, kind, spaced(s.Prog), strings.Join(conds, ", "), s.Body)
}

// Scripts returns the scripts of an installed package, as the database holds
// them, found by the name, epoch, version, release and architecture of pkg
// and its install time (so two copies of one version installed at different
// times stay apart). It reads the database, as headers are not kept in memory.
// It returns [ErrNotFound] when no installed package matches. Use
// [DB.AllScripts] to read the scripts of many packages in one pass.
func (db *DB) Scripts(ctx context.Context, pkg *rpm.Package) (*Scripts, error) {
	if pkg == nil || pkg.Name == "" {
		return nil, fmt.Errorf("%w: no package", ErrInvalidQuery)
	}

	for rec, err := range db.records(ctx) {
		if err != nil {
			return nil, err
		}

		if sameInstall(rec.pkg, pkg) {
			return scriptsFromHeader(rec.hdr, db.opts.Package.MaxArrayEntries)
		}
	}

	return nil, fmt.Errorf("%w: package %s", ErrNotFound, pkg.Name)
}

// sameInstall reports whether two packages are the same installed package.
func sameInstall(a, b *rpm.Package) bool {
	return sameNEVRA(a, b) && a.InstallTime == b.InstallTime
}

// sameNEVRA reports whether two packages have the same name, epoch, version,
// release and architecture.
func sameNEVRA(a, b *rpm.Package) bool {
	return a.Name == b.Name && a.Epoch == b.Epoch && a.Version == b.Version &&
		a.Release == b.Release && a.Arch == b.Arch
}

// AllScripts iterates over the installed packages with their scripts, in the
// order of [DB.Packages]. A package whose scripts do not decode ends the
// iteration with that error, the last pair it yields.
func (db *DB) AllScripts(ctx context.Context) iter.Seq2[PackageScripts, error] {
	return func(yield func(PackageScripts, error) bool) {
		for rec, err := range db.records(ctx) {
			if err != nil {
				yield(PackageScripts{}, err)

				return
			}

			s, err := scriptsFromHeader(rec.hdr, db.opts.Package.MaxArrayEntries)
			if err != nil {
				yield(PackageScripts{}, fmt.Errorf("rpmdb: %s: %w", rec.pkg.Name, err))

				return
			}

			if !yield(PackageScripts{Package: rec.pkg, Scripts: s}, nil) {
				return
			}
		}
	}
}
