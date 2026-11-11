package pack

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	rpmhdr "github.com/M0Rf30/pkgformat/rpm/internal/header"
	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// DefaultInterpreter runs scriptlets that name no interpreter.
const DefaultInterpreter = "/bin/sh"

// LuaInterpreter selects the Lua interpreter built into rpm.
const LuaInterpreter = "<lua>"

// DefaultTriggerPriority is the priority of file triggers that set none.
const DefaultTriggerPriority = 1000000

// ErrInvalidScript is returned by Write for scriptlets, triggers and file triggers
// that cannot be represented in an rpm header.
var ErrInvalidScript = errors.New("invalid rpm scriptlet")

// ScriptFlags are the flags of a scriptlet (RPMSCRIPT_FLAG_*).
type ScriptFlags uint32

const (
	// ScriptExpand expands macros in the script when the package is installed (%post -e).
	ScriptExpand ScriptFlags = tag.RPMSCRIPT_FLAG_EXPAND
	// ScriptQFormat expands header query format tags in the script (%post -q).
	ScriptQFormat ScriptFlags = tag.RPMSCRIPT_FLAG_QFORMAT
	// ScriptCritical makes a failure of the script abort the transaction.
	ScriptCritical ScriptFlags = tag.RPMSCRIPT_FLAG_CRITICAL
)

const scriptFlagsMask = ScriptExpand | ScriptQFormat | ScriptCritical

// Scriptlet is a script with its interpreter.
type Scriptlet struct {
	// Script is the body of the script. It may be empty when the interpreter
	// alone does the work, as for "%post -p /sbin/ldconfig".
	Script string
	// Interpreter is the interpreter and its arguments, for example
	// {"/bin/sh", "-e"}. An empty value selects DefaultInterpreter and
	// {LuaInterpreter} the Lua of rpm. Triggers and file triggers cannot
	// have interpreter arguments.
	Interpreter []string
	// Flags are the expand, query format and critical flags.
	Flags ScriptFlags
}

func (s Scriptlet) isSet() bool {
	return s.Script != "" || len(s.Interpreter) > 0 || s.Flags != 0
}

// interp returns the interpreter, applying the default.
func (s Scriptlet) interp() []string {
	if len(s.Interpreter) == 0 {
		return []string{DefaultInterpreter}
	}
	return s.Interpreter
}

func (s Scriptlet) validate(what string, noArgs bool) error {
	if strings.IndexByte(s.Script, 0) >= 0 {
		return fmt.Errorf("%w: %s has an embedded NUL byte", ErrInvalidScript, what)
	}
	if s.Flags&^scriptFlagsMask != 0 {
		return fmt.Errorf("%w: %s has unknown flags %#x", ErrInvalidScript, what, uint32(s.Flags&^scriptFlagsMask))
	}
	for _, a := range s.Interpreter {
		if a == "" || hasNUL(a) {
			return fmt.Errorf("%w: %s has an empty interpreter or argument or one with a NUL byte", ErrInvalidScript, what)
		}
	}
	if len(s.Interpreter) > 1 && (noArgs || s.Interpreter[0] == LuaInterpreter) {
		return fmt.Errorf("%w: %s: interpreter arguments are not allowed here: %q", ErrInvalidScript, what, s.Interpreter)
	}
	return nil
}

// isLua reports whether the scriptlet runs in the Lua of rpm.
func (s Scriptlet) isLua() bool { return s.interp()[0] == LuaInterpreter }

// ScriptKind selects the stage of a scriptlet.
type ScriptKind int

// The stages of scriptlets, in the order rpm documents them.
const (
	ScriptPretrans ScriptKind = iota
	ScriptPrein
	ScriptPostin
	ScriptPreun
	ScriptPostun
	ScriptPosttrans
	ScriptPreuntrans
	ScriptPostuntrans
	ScriptVerify
	numScriptKinds
)

// scriptTags are the header tags of one scriptlet kind.
type scriptTags struct {
	name             string
	script, prog, fl int
	scope            Sense
}

var scriptKindTags = [numScriptKinds]scriptTags{
	ScriptPretrans:    {"pretrans", tag.PRETRANS, tag.PRETRANSPROG, tag.PRETRANSFLAGS, SensePretrans},
	ScriptPrein:       {"prein", tag.PREIN, tag.PREINPROG, tag.PREINFLAGS, SenseScriptPre},
	ScriptPostin:      {"postin", tag.POSTIN, tag.POSTINPROG, tag.POSTINFLAGS, SenseScriptPost},
	ScriptPreun:       {"preun", tag.PREUN, tag.PREUNPROG, tag.PREUNFLAGS, SenseScriptPreun},
	ScriptPostun:      {"postun", tag.POSTUN, tag.POSTUNPROG, tag.POSTUNFLAGS, SenseScriptPostun},
	ScriptPosttrans:   {"posttrans", tag.POSTTRANS, tag.POSTTRANSPROG, tag.POSTTRANSFLAGS, SensePosttrans},
	ScriptPreuntrans:  {"preuntrans", tag.PREUNTRANS, tag.PREUNTRANSPROG, tag.PREUNTRANSFLAGS, SensePreuntrans},
	ScriptPostuntrans: {"postuntrans", tag.POSTUNTRANS, tag.POSTUNTRANSPROG, tag.POSTUNTRANSFLAGS, SensePostuntrans},
	ScriptVerify:      {"verifyscript", tag.VERIFYSCRIPT, tag.VERIFYSCRIPTPROG, tag.VERIFYSCRIPTFLAGS, SenseScriptVerify},
}

// String returns the name of the scriptlet as rpm calls it, e.g. "posttrans".
func (k ScriptKind) String() string {
	if k < 0 || k >= numScriptKinds {
		return fmt.Sprintf("ScriptKind(%d)", int(k))
	}
	return scriptKindTags[k].name
}

// AddScriptlet sets the scriptlet of the given kind, replacing the previous one.
func (r *RPM) AddScriptlet(kind ScriptKind, s Scriptlet) {
	if kind >= 0 && kind < numScriptKinds {
		r.scripts[kind] = s
	}
}

// AddPretrans adds a pretrans scriptlet
func (r *RPM) AddPretrans(s string) { r.scripts[ScriptPretrans] = Scriptlet{Script: s} }

// AddPrein adds a prein scriptlet
func (r *RPM) AddPrein(s string) { r.scripts[ScriptPrein] = Scriptlet{Script: s} }

// AddPostin adds a postin scriptlet
func (r *RPM) AddPostin(s string) { r.scripts[ScriptPostin] = Scriptlet{Script: s} }

// AddPreun adds a preun scriptlet
func (r *RPM) AddPreun(s string) { r.scripts[ScriptPreun] = Scriptlet{Script: s} }

// AddPostun adds a postun scriptlet
func (r *RPM) AddPostun(s string) { r.scripts[ScriptPostun] = Scriptlet{Script: s} }

// AddPosttrans adds a posttrans scriptlet
func (r *RPM) AddPosttrans(s string) { r.scripts[ScriptPosttrans] = Scriptlet{Script: s} }

// AddPreuntrans adds a preuntrans scriptlet
func (r *RPM) AddPreuntrans(s string) { r.scripts[ScriptPreuntrans] = Scriptlet{Script: s} }

// AddPostuntrans adds a postuntrans scriptlet
func (r *RPM) AddPostuntrans(s string) { r.scripts[ScriptPostuntrans] = Scriptlet{Script: s} }

// AddVerifyScript adds a verifyscript scriptlet
func (r *RPM) AddVerifyScript(s string) { r.scripts[ScriptVerify] = Scriptlet{Script: s} }

// progEntry encodes the interpreter: a string for a single word, an array when
// the interpreter has arguments.
func progEntry(interp []string) IndexEntry {
	if len(interp) == 1 {
		return EntryString(interp[0])
	}
	return EntryStringSlice(interp)
}

// addScriptlets writes the scriptlet tags.
func (r *RPM) addScriptlets(h *rpmhdr.Index) {
	for kind, s := range r.scripts {
		if !s.isSet() {
			continue
		}
		t := scriptKindTags[kind]
		if s.Script != "" {
			h.Add(t.script, EntryString(s.Script))
		}
		h.Add(t.prog, progEntry(s.interp()))
		if s.Flags != 0 {
			h.Add(t.fl, EntryUint32([]uint32{uint32(s.Flags)}))
		}
	}
}

// TriggerKind selects when a trigger runs.
type TriggerKind int

// The kinds of triggers.
const (
	// TriggerPrein runs before a package matching the condition is installed.
	TriggerPrein TriggerKind = iota
	// TriggerIn runs after a package matching the condition is installed.
	TriggerIn
	// TriggerUn runs before a package matching the condition is removed.
	TriggerUn
	// TriggerPostun runs after a package matching the condition is removed.
	TriggerPostun
)

func (k TriggerKind) sense() (Sense, bool) {
	switch k {
	case TriggerPrein:
		return tag.RPMSENSE_TRIGGERPREIN, true
	case TriggerIn:
		return tag.RPMSENSE_TRIGGERIN, true
	case TriggerUn:
		return tag.RPMSENSE_TRIGGERUN, true
	case TriggerPostun:
		return tag.RPMSENSE_TRIGGERPOSTUN, true
	}
	return 0, false
}

// Trigger is a scriptlet that runs when other packages are installed or removed.
type Trigger struct {
	Kind TriggerKind
	// Conditions are the packages (with optional versions) that fire the
	// trigger: "%triggerin -- foo, bar >= 2.0". Boolean dependencies are not
	// supported as trigger conditions.
	Conditions Relations
	// Script is the trigger script. Its interpreter cannot have arguments.
	Script Scriptlet
}

// FileTriggerKind selects when a file trigger runs.
type FileTriggerKind int

// The kinds of file triggers.
const (
	// FileTriggerIn runs when files below a prefix were installed.
	FileTriggerIn FileTriggerKind = iota
	// FileTriggerUn runs when files below a prefix are about to be removed.
	FileTriggerUn
	// FileTriggerPostun runs when files below a prefix were removed.
	FileTriggerPostun
)

func (k FileTriggerKind) sense() (Sense, bool) {
	switch k {
	case FileTriggerIn:
		return tag.RPMSENSE_TRIGGERIN, true
	case FileTriggerUn:
		return tag.RPMSENSE_TRIGGERUN, true
	case FileTriggerPostun:
		return tag.RPMSENSE_TRIGGERPOSTUN, true
	}
	return 0, false
}

// FileTrigger is a scriptlet that runs when files below one of its prefixes are
// installed or removed (%filetriggerin and friends), or, with Transaction set, once
// at the end of the transaction (%transfiletriggerin and friends).
type FileTrigger struct {
	Kind        FileTriggerKind
	Transaction bool
	// Prefixes are the absolute directories that fire the trigger.
	Prefixes []string
	// Priority orders the triggers; lower runs first. Zero selects
	// DefaultTriggerPriority.
	Priority int32
	// Script is the trigger script. Its interpreter cannot have arguments.
	Script Scriptlet
}

// AddTrigger adds a trigger. Triggers keep the order they were added in.
func (r *RPM) AddTrigger(t Trigger) { r.triggers = append(r.triggers, t) }

// AddFileTrigger adds a file trigger.
func (r *RPM) AddFileTrigger(t FileTrigger) { r.fileTriggers = append(r.fileTriggers, t) }

func (r *RPM) validateScripts() error {
	for kind, s := range r.scripts {
		if err := s.validate(ScriptKind(kind).String(), false); err != nil {
			return err
		}
	}
	for i, t := range r.triggers {
		if _, ok := t.Kind.sense(); !ok {
			return fmt.Errorf("%w: trigger %d has unknown kind %d", ErrInvalidScript, i, t.Kind)
		}
		if len(t.Conditions) == 0 {
			return fmt.Errorf("%w: trigger %d has no conditions", ErrInvalidScript, i)
		}
		for _, c := range t.Conditions {
			switch {
			case c == nil || c.Name == "":
				return fmt.Errorf("%w: trigger %d has an empty condition", ErrInvalidScript, i)
			case isRich(c.Name):
				return fmt.Errorf("%w: trigger %d: boolean dependency %q is not supported as a condition", ErrInvalidScript, i, c.Name)
			case hasNUL(c.Name) || hasNUL(c.Version):
				return fmt.Errorf("%w: trigger %d has an embedded NUL byte", ErrInvalidScript, i)
			}
		}
		if err := t.Script.validate(fmt.Sprintf("trigger %d", i), true); err != nil {
			return err
		}
	}
	for i, t := range r.fileTriggers {
		if _, ok := t.Kind.sense(); !ok {
			return fmt.Errorf("%w: file trigger %d has unknown kind %d", ErrInvalidScript, i, t.Kind)
		}
		if len(t.Prefixes) == 0 {
			return fmt.Errorf("%w: file trigger %d has no prefixes", ErrInvalidScript, i)
		}
		for _, p := range t.Prefixes {
			if !strings.HasPrefix(p, "/") || hasNUL(p) {
				return fmt.Errorf("%w: file trigger %d: prefix %q is not an absolute path", ErrInvalidScript, i, p)
			}
		}
		if t.Priority < 0 {
			return fmt.Errorf("%w: file trigger %d has a negative priority", ErrInvalidScript, i)
		}
		if err := t.Script.validate(fmt.Sprintf("file trigger %d", i), true); err != nil {
			return err
		}
	}
	return nil
}

// addTriggers writes the TRIGGER* tags as rpmbuild lays them out: one entry per
// trigger script, and one condition entry per package name, sorted by name, whose
// index refers to the script.
func (r *RPM) addTriggers(h *rpmhdr.Index) {
	if len(r.triggers) == 0 {
		return
	}
	type cond struct {
		name, version string
		flags, index  uint32
	}
	var (
		conds   []cond
		scripts = make([]string, len(r.triggers))
		progs   = make([]string, len(r.triggers))
		flags   = make([]uint32, len(r.triggers))
		anyFlag bool
	)
	for i, t := range r.triggers {
		scripts[i] = t.Script.Script
		progs[i] = t.Script.interp()[0]
		flags[i] = uint32(t.Script.Flags)
		anyFlag = anyFlag || flags[i] != 0
		kind, _ := t.Kind.sense()
		for _, c := range t.Conditions {
			conds = append(conds, cond{c.Name, c.Version, uint32(c.Sense.Compare() | kind), uint32(i)})
		}
	}
	slices.SortStableFunc(conds, func(a, b cond) int { return strings.Compare(a.name, b.name) })
	names := make([]string, len(conds))
	versions := make([]string, len(conds))
	cflags := make([]uint32, len(conds))
	index := make([]uint32, len(conds))
	for i, c := range conds {
		names[i], versions[i], cflags[i], index[i] = c.name, c.version, c.flags, c.index
	}
	h.Add(tag.TRIGGERSCRIPTS, EntryStringSlice(scripts))
	h.Add(tag.TRIGGERSCRIPTPROG, EntryStringSlice(progs))
	if anyFlag {
		h.Add(tag.TRIGGERSCRIPTFLAGS, EntryUint32(flags))
	}
	h.Add(tag.TRIGGERNAME, EntryStringSlice(names))
	h.Add(tag.TRIGGERVERSION, EntryStringSlice(versions))
	h.Add(tag.TRIGGERFLAGS, EntryUint32(cflags))
	h.Add(tag.TRIGGERINDEX, EntryUint32(index))
}

// fileTriggerTags are the tags of the file triggers or of the transaction file triggers.
type fileTriggerTags struct {
	scripts, prog, scriptFlags, name, index, version, flags, priorities int
}

var (
	plainFileTriggerTags = fileTriggerTags{
		tag.FILETRIGGERSCRIPTS, tag.FILETRIGGERSCRIPTPROG, tag.FILETRIGGERSCRIPTFLAGS,
		tag.FILETRIGGERNAME, tag.FILETRIGGERINDEX, tag.FILETRIGGERVERSION, tag.FILETRIGGERFLAGS,
		tag.FILETRIGGERPRIORITIES,
	}
	transFileTriggerTags = fileTriggerTags{
		tag.TRANSFILETRIGGERSCRIPTS, tag.TRANSFILETRIGGERSCRIPTPROG, tag.TRANSFILETRIGGERSCRIPTFLAGS,
		tag.TRANSFILETRIGGERNAME, tag.TRANSFILETRIGGERINDEX, tag.TRANSFILETRIGGERVERSION, tag.TRANSFILETRIGGERFLAGS,
		tag.TRANSFILETRIGGERPRIORITIES,
	}
)

// addFileTriggers writes the FILETRIGGER* and TRANSFILETRIGGER* tags.
func (r *RPM) addFileTriggers(h *rpmhdr.Index) {
	for _, trans := range []bool{false, true} {
		var group []FileTrigger
		for _, t := range r.fileTriggers {
			if t.Transaction == trans {
				group = append(group, t)
			}
		}
		if len(group) == 0 {
			continue
		}
		tags := plainFileTriggerTags
		if trans {
			tags = transFileTriggerTags
		}
		type cond struct {
			prefix       string
			flags, index uint32
		}
		var (
			conds      []cond
			scripts    = make([]string, len(group))
			progs      = make([]string, len(group))
			flags      = make([]uint32, len(group))
			priorities = make([]uint32, len(group))
			anyFlag    bool
		)
		for i, t := range group {
			scripts[i] = t.Script.Script
			progs[i] = t.Script.interp()[0]
			flags[i] = uint32(t.Script.Flags)
			anyFlag = anyFlag || flags[i] != 0
			priorities[i] = DefaultTriggerPriority
			if t.Priority != 0 {
				priorities[i] = uint32(t.Priority)
			}
			kind, _ := t.Kind.sense()
			for _, p := range t.Prefixes {
				conds = append(conds, cond{p, uint32(kind), uint32(i)})
			}
		}
		slices.SortStableFunc(conds, func(a, b cond) int { return strings.Compare(a.prefix, b.prefix) })
		names := make([]string, len(conds))
		versions := make([]string, len(conds))
		cflags := make([]uint32, len(conds))
		index := make([]uint32, len(conds))
		for i, c := range conds {
			names[i], cflags[i], index[i] = c.prefix, c.flags, c.index
		}
		h.Add(tags.scripts, EntryStringSlice(scripts))
		h.Add(tags.prog, EntryStringSlice(progs))
		if anyFlag {
			h.Add(tags.scriptFlags, EntryUint32(flags))
		}
		h.Add(tags.name, EntryStringSlice(names))
		h.Add(tags.index, EntryUint32(index))
		h.Add(tags.version, EntryStringSlice(versions))
		h.Add(tags.flags, EntryUint32(cflags))
		h.Add(tags.priorities, EntryUint32(priorities))
	}
}

// scriptDeps returns the requirements on the interpreters of the scriptlets, as
// rpmbuild adds them: one per scriptlet with the INTERP bit and its scope, and a
// plain INTERP one for each trigger and file trigger.
func (r *RPM) scriptDeps() Relations {
	var deps Relations
	add := func(s Scriptlet, scope Sense) {
		if p := s.interp()[0]; p != LuaInterpreter {
			deps.addIfMissing(&Relation{Name: p, Sense: SenseInterp | scope})
		}
	}
	for kind, s := range r.scripts {
		if s.isSet() {
			add(s, scriptKindTags[kind].scope)
		}
	}
	for _, t := range r.triggers {
		add(t.Script, 0)
	}
	for _, t := range r.fileTriggers {
		add(t.Script, 0)
	}
	return deps
}
