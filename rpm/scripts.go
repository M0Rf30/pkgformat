package rpm

import (
	"fmt"
	"strings"

	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// ScriptFlags are the flags of a scriptlet (the *FLAGS tags such as
// PREINFLAGS): how rpm runs it.
type ScriptFlags uint32

// The scriptlet flags, the tag.RPMSCRIPT_FLAG_* values.
const (
	// ScriptExpand makes rpm expand macros in the body before running it
	// (spec file option -e).
	ScriptExpand ScriptFlags = tag.RPMSCRIPT_FLAG_EXPAND
	// ScriptQFormat makes rpm expand query-format tags in the body (-q).
	ScriptQFormat ScriptFlags = tag.RPMSCRIPT_FLAG_QFORMAT
	// ScriptCritical makes a failure of the scriptlet abort the transaction.
	ScriptCritical ScriptFlags = tag.RPMSCRIPT_FLAG_CRITICAL
)

// Expand reports the macro expansion flag.
func (f ScriptFlags) Expand() bool { return f&ScriptExpand != 0 }

// QFormat reports the query-format expansion flag.
func (f ScriptFlags) QFormat() bool { return f&ScriptQFormat != 0 }

// Critical reports the flag that makes a failing scriptlet abort the
// transaction.
func (f ScriptFlags) Critical() bool { return f&ScriptCritical != 0 }

// LuaInterpreter is the interpreter of a scriptlet that rpm runs in its
// embedded Lua (spec file option -p <lua>).
const LuaInterpreter = "<lua>"

// Scriptlet is one script of a package: the body and how it is run.
type Scriptlet struct {
	// Body is the text of the script. It is empty for a scriptlet that only
	// names a program, such as "%post -p /sbin/ldconfig".
	Body string `json:"body,omitempty"`
	// Interpreter is the program that runs Body (the first element of the
	// *PROG tag): "/bin/sh", "/usr/bin/python3" or [LuaInterpreter]. It is
	// empty when the package does not name one, which means /bin/sh.
	Interpreter string `json:"interpreter,omitempty"`
	// Args are the arguments of Interpreter (the remaining elements of the
	// *PROG tag), such as "-e" of "/bin/bash -e".
	Args  []string    `json:"args,omitempty"`
	Flags ScriptFlags `json:"flags,omitempty"`
}

// Program returns the interpreter followed by its arguments, as the *PROG tag
// stores them. A scriptlet with no interpreter runs with "/bin/sh".
func (s Scriptlet) Program() []string {
	if s.Interpreter == "" {
		return append([]string{"/bin/sh"}, s.Args...)
	}

	return append([]string{s.Interpreter}, s.Args...)
}

// IsLua reports whether rpm runs the scriptlet in its embedded Lua.
func (s Scriptlet) IsLua() bool { return s.Interpreter == LuaInterpreter }

// Scripts holds the scriptlets of a package. A scriptlet the package does not
// have is nil.
type Scripts struct {
	PreTrans    *Scriptlet `json:"pretrans,omitempty"`
	Pre         *Scriptlet `json:"pre,omitempty"`
	Post        *Scriptlet `json:"post,omitempty"`
	PreUn       *Scriptlet `json:"preun,omitempty"`
	PostUn      *Scriptlet `json:"postun,omitempty"`
	PostTrans   *Scriptlet `json:"posttrans,omitempty"`
	PreUnTrans  *Scriptlet `json:"preuntrans,omitempty"`
	PostUnTrans *Scriptlet `json:"postuntrans,omitempty"`
	// Verify is the %verifyscript, run by "rpm -V".
	Verify *Scriptlet `json:"verify,omitempty"`
}

// NamedScript is a scriptlet with the name of its slot in [Scripts].
type NamedScript struct {
	// Name is "pretrans", "pre", "post", "preun", "postun", "posttrans",
	// "preuntrans", "postuntrans" or "verify".
	Name string
	*Scriptlet
}

// All returns the scriptlets the package has, in the order of the fields of
// [Scripts].
func (s Scripts) All() []NamedScript {
	var out []NamedScript

	for _, e := range []NamedScript{
		{"pretrans", s.PreTrans}, {"pre", s.Pre}, {"post", s.Post}, {"preun", s.PreUn},
		{"postun", s.PostUn}, {"posttrans", s.PostTrans}, {"preuntrans", s.PreUnTrans},
		{"postuntrans", s.PostUnTrans}, {"verify", s.Verify},
	} {
		if e.Scriptlet != nil {
			out = append(out, e)
		}
	}

	return out
}

// IsZero reports whether the package has no scriptlet.
func (s Scripts) IsZero() bool { return len(s.All()) == 0 }

// TriggerKind says when a trigger runs relative to the install or removal of
// the package it watches.
type TriggerKind string

// The kinds of trigger. A file trigger is never "prein".
const (
	// TriggerPrein runs before the watched package is installed
	// (%triggerprein).
	TriggerPrein TriggerKind = "prein"
	// TriggerIn runs after the watched package is installed or upgraded
	// (%triggerin).
	TriggerIn TriggerKind = "in"
	// TriggerUn runs before the watched package is removed (%triggerun).
	TriggerUn TriggerKind = "un"
	// TriggerPostun runs after the watched package is removed
	// (%triggerpostun).
	TriggerPostun TriggerKind = "postun"
)

// Trigger is a package trigger: a script that runs when another package
// matching one of the conditions is installed or removed.
type Trigger struct {
	Kind   TriggerKind `json:"kind"`
	Script Scriptlet   `json:"script"`
	// Conditions are the watched packages: the name, comparison and version
	// of each "%triggerin -- foo, bar >= 2.0" target. Their Flags carry the
	// trigger kind bits as well as the comparison.
	Conditions []Dependency `json:"conditions,omitempty"`
}

// FileTrigger is a file trigger (%filetriggerin and friends) or, with
// Transaction set, a transaction file trigger (%transfiletriggerin and
// friends): a script that runs when files below one of the watched path
// prefixes are installed or removed.
type FileTrigger struct {
	// Kind is [TriggerIn], [TriggerUn] or [TriggerPostun].
	Kind TriggerKind `json:"kind"`
	// Transaction is true for a transaction file trigger, run once at the end
	// of the transaction instead of once per package.
	Transaction bool `json:"transaction,omitempty"`
	// Priority orders the triggers of a transaction: the higher runs first.
	// rpm assigns 1000000 to a trigger that sets none.
	Priority uint32    `json:"priority"`
	Script   Scriptlet `json:"script"`
	// Paths are the watched path prefixes.
	Paths []string `json:"paths"`
}

// scriptTags names the tags that hold one scriptlet.
type scriptTags struct{ body, prog, flags int }

var (
	preTransTags    = scriptTags{tag.PRETRANS, tag.PRETRANSPROG, tag.PRETRANSFLAGS}
	preTags         = scriptTags{tag.PREIN, tag.PREINPROG, tag.PREINFLAGS}
	postTags        = scriptTags{tag.POSTIN, tag.POSTINPROG, tag.POSTINFLAGS}
	preUnTags       = scriptTags{tag.PREUN, tag.PREUNPROG, tag.PREUNFLAGS}
	postUnTags      = scriptTags{tag.POSTUN, tag.POSTUNPROG, tag.POSTUNFLAGS}
	postTransTags   = scriptTags{tag.POSTTRANS, tag.POSTTRANSPROG, tag.POSTTRANSFLAGS}
	preUnTransTags  = scriptTags{tag.PREUNTRANS, tag.PREUNTRANSPROG, tag.PREUNTRANSFLAGS}
	postUnTransTags = scriptTags{tag.POSTUNTRANS, tag.POSTUNTRANSPROG, tag.POSTUNTRANSFLAGS}
	verifyTags      = scriptTags{tag.VERIFYSCRIPT, tag.VERIFYSCRIPTPROG, tag.VERIFYSCRIPTFLAGS}
)

// scriptlet reads one scriptlet; it is nil when none of its tags is present.
// A scriptlet may lack the body and keep only the program.
func (hdr *rpmHeader) scriptlet(t scriptTags) *Scriptlet {
	if !hdr.HasTag(t.body) && !hdr.HasTag(t.prog) && !hdr.HasTag(t.flags) {
		return nil
	}

	s := &Scriptlet{Body: hdr.firstString(t.body)}
	s.Interpreter, s.Args = splitProgram(hdr.stringsAll(t.prog))
	s.Flags = ScriptFlags(hdr.firstNumber(t.flags))

	return s
}

// scripts reads the scriptlets of the package.
func (hdr *rpmHeader) scripts() Scripts {
	return Scripts{
		PreTrans:    hdr.scriptlet(preTransTags),
		Pre:         hdr.scriptlet(preTags),
		Post:        hdr.scriptlet(postTags),
		PreUn:       hdr.scriptlet(preUnTags),
		PostUn:      hdr.scriptlet(postUnTags),
		PostTrans:   hdr.scriptlet(postTransTags),
		PreUnTrans:  hdr.scriptlet(preUnTransTags),
		PostUnTrans: hdr.scriptlet(postUnTransTags),
		Verify:      hdr.scriptlet(verifyTags),
	}
}

// stringsAll returns every string of a string tag, bounded by the data of the
// header; a missing tag yields nil.
func (hdr *rpmHeader) stringsAll(id int) []string {
	strs, _ := hdr.stringsPrefix(id, 1<<16)

	return strs
}

// splitProgram splits the value of a *PROG tag. A program of one element that
// contains spaces and no argument elements is written by some old tools as a
// command line: it is split on white space.
func splitProgram(prog []string) (interpreter string, args []string) {
	switch len(prog) {
	case 0:
		return "", nil
	case 1:
		if fields := strings.Fields(prog[0]); len(fields) > 1 {
			return fields[0], fields[1:]
		}

		return prog[0], nil
	default:
		return prog[0], prog[1:]
	}
}

// triggerKindFromFlags derives the kind of a trigger from the sense flags of
// one of its conditions.
func triggerKindFromFlags(flags Sense) TriggerKind {
	switch {
	case flags&SenseTriggerPrein != 0:
		return TriggerPrein
	case flags&SenseTriggerIn != 0:
		return TriggerIn
	case flags&SenseTriggerUn != 0:
		return TriggerUn
	case flags&SenseTriggerPostun != 0:
		return TriggerPostun
	}

	return ""
}

// triggerTags names the tags of one family of triggers.
type triggerTags struct {
	scripts, prog, scriptFlags  int
	name, index, version, flags int
	priorities, kind            int
	transaction                 bool
}

var (
	pkgTriggerTags = triggerTags{
		scripts: tag.TRIGGERSCRIPTS, prog: tag.TRIGGERSCRIPTPROG, scriptFlags: tag.TRIGGERSCRIPTFLAGS,
		name: tag.TRIGGERNAME, index: tag.TRIGGERINDEX, version: tag.TRIGGERVERSION, flags: tag.TRIGGERFLAGS,
		kind: tag.TRIGGERTYPE,
	}
	fileTriggerTags = triggerTags{
		scripts: tag.FILETRIGGERSCRIPTS, prog: tag.FILETRIGGERSCRIPTPROG, scriptFlags: tag.FILETRIGGERSCRIPTFLAGS,
		name: tag.FILETRIGGERNAME, index: tag.FILETRIGGERINDEX, version: tag.FILETRIGGERVERSION,
		flags: tag.FILETRIGGERFLAGS, priorities: tag.FILETRIGGERPRIORITIES, kind: tag.FILETRIGGERTYPE,
	}
	transFileTriggerTags = triggerTags{
		scripts: tag.TRANSFILETRIGGERSCRIPTS, prog: tag.TRANSFILETRIGGERSCRIPTPROG,
		scriptFlags: tag.TRANSFILETRIGGERSCRIPTFLAGS, name: tag.TRANSFILETRIGGERNAME,
		index: tag.TRANSFILETRIGGERINDEX, version: tag.TRANSFILETRIGGERVERSION,
		flags: tag.TRANSFILETRIGGERFLAGS, priorities: tag.TRANSFILETRIGGERPRIORITIES,
		kind: tag.TRANSFILETRIGGERTYPE, transaction: true,
	}
)

// defaultFileTriggerPriority is the priority rpm gives a file trigger that
// sets none.
const defaultFileTriggerPriority = 1000000

// triggerGroup is one trigger as laid out in the header: a script and the
// conditions that point at it.
type triggerGroup struct {
	script     Scriptlet
	conditions []Dependency
	priority   uint32
	kind       TriggerKind
}

// triggerGroups reads the triggers of one family. The header stores them as parallel
// arrays: one entry per script (body, program, flags, priority, kind) and one
// per condition, which names its script by index.
func (hdr *rpmHeader) triggerGroups(t triggerTags, limit int) ([]triggerGroup, error) {
	bodies, declared := hdr.stringsPrefix(t.scripts, limit)
	if declared > limit {
		return nil, fmt.Errorf("%w: tag %d declares %d entries, at most %d", ErrHeaderTooLarge, t.scripts, declared, limit)
	}

	if len(bodies) == 0 {
		return nil, nil
	}

	_, n := hdr.stringsPrefix(t.name, 0)
	if n > limit {
		return nil, fmt.Errorf("%w: tag %d declares %d entries, at most %d", ErrHeaderTooLarge, t.name, n, limit)
	}

	conds, _ := hdr.dependencies(t.name, t.flags, t.version, limit)
	index, _ := hdr.numbersPrefix(t.index, len(conds))
	progs := hdr.arrayOfStrings(t.prog, len(bodies))
	flags, _ := hdr.numbersPrefix(t.scriptFlags, len(bodies))
	kinds, _ := hdr.stringsPrefix(t.kind, len(bodies))

	var priorities []uint64
	if t.priorities != 0 {
		priorities, _ = hdr.numbersPrefix(t.priorities, len(bodies))
	}

	groups := make([]triggerGroup, len(bodies))
	for i, body := range bodies {
		g := &groups[i]
		g.script.Body = body

		if i < len(progs) {
			g.script.Interpreter, g.script.Args = splitProgram(progs[i])
		}

		if i < len(flags) {
			g.script.Flags = ScriptFlags(flags[i])
		}

		if i < len(kinds) {
			g.kind = TriggerKind(kinds[i])
		}

		g.priority = defaultFileTriggerPriority
		if i < len(priorities) {
			g.priority = uint32(priorities[i])
		}
	}

	for j, c := range conds {
		if j >= len(index) || index[j] >= uint64(len(groups)) {
			continue
		}

		g := &groups[index[j]]
		g.conditions = append(g.conditions, c)

		if g.kind == "" {
			g.kind = triggerKindFromFlags(c.Flags)
		}
	}

	return groups, nil
}

// arrayOfStrings returns the *PROG values of a family of triggers: the tag
// holds one program per script, so every element is a program of its own
// (see splitProgram for one written as a command line).
func (hdr *rpmHeader) arrayOfStrings(id, n int) [][]string {
	strs, _ := hdr.stringsPrefix(id, n)
	out := make([][]string, len(strs))

	for i, s := range strs {
		out[i] = []string{s}
	}

	return out
}

// triggers reads the package triggers.
func (hdr *rpmHeader) triggers(limit int) ([]Trigger, error) {
	groups, err := hdr.triggerGroups(pkgTriggerTags, limit)
	if err != nil {
		return nil, err
	}

	var out []Trigger

	for _, g := range groups {
		out = append(out, Trigger{Kind: g.kind, Script: g.script, Conditions: g.conditions})
	}

	return out, nil
}

// fileTriggers reads the file triggers and the transaction file triggers.
func (hdr *rpmHeader) fileTriggers(limit int) ([]FileTrigger, error) {
	var out []FileTrigger

	for _, t := range []triggerTags{fileTriggerTags, transFileTriggerTags} {
		groups, err := hdr.triggerGroups(t, limit)
		if err != nil {
			return nil, err
		}

		for _, g := range groups {
			ft := FileTrigger{Kind: g.kind, Transaction: t.transaction, Priority: g.priority, Script: g.script}
			for _, c := range g.conditions {
				ft.Paths = append(ft.Paths, c.Name)
			}

			out = append(out, ft)
		}
	}

	return out, nil
}
