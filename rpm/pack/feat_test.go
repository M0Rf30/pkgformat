package pack

import (
	"testing"
	"time"
)

// newFeat returns a package that exercises the features of rpm packages. The same
// package is described by testdata/interop/feat.spec, which rpmbuild turns into the
// reference the tests compare with.
func newFeat(t testing.TB, format int) *RPM {
	t.Helper()
	req := func(s string, sense Sense) *Relation {
		rel, err := NewRelation(s)
		if err != nil {
			t.Fatal(err)
		}
		rel.Sense |= sense
		return rel
	}
	r, err := NewRPM(RPMMetaData{
		Name: "feat", Version: "1.2.3", Release: "4", Epoch: 2, Format: format,
		Summary: "Feature test", Description: "Feature test description.",
		Translations: map[string]Translation{"de": {Summary: "Funktionstest", Description: "Beschreibung.", Group: "Misc"}},
		Licence:      "MIT", URL: "https://example.org/feat", Arch: "noarch", Group: "Misc", Vendor: "Acme",
		Packager: "Pack <p@example.org>", Distribution: "Acme Linux", BugURL: "https://example.org/bugs",
		BuildHost: "builder", BuildTime: time.Unix(1700000000, 0), ClampTime: time.Unix(1700000000, 0), OwnerDeps: true,
		Changelog: []ChangelogEntry{{Time: time.Unix(1704110400, 0), Author: "A <a@b> - 1.0-1", Text: "- one"}},
		Requires: Relations{
			req("bash >= 4", 0),
			req("coreutils", SenseScriptPre),
			req("coreutils", SenseScriptPost),
			req("grep", SenseScriptPreun|SenseScriptPostun),
			req("sed", SensePretrans),
			req("sed", SensePosttrans),
			req("gawk", SenseScriptVerify),
			req("(foo if bar)", SenseMeta),
			req("(a or b)", 0),
			req("x~1^2", 0),
		},
		Recommends:  Relations{req("rec1", 0)},
		Suggests:    Relations{req("sug1", 0)},
		Supplements: Relations{req("sup1", 0)},
		Enhances:    Relations{req("enh1", 0)},
		Provides:    Relations{req("virt = 1.0", 0)},
		Conflicts:   Relations{req("bad < 2", 0)},
		Obsoletes:   Relations{req("old < 1", 0)},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := func(name string, mode uint, body string) RPMFile {
		return RPMFile{Name: name, Mode: mode, Body: []byte(body), Owner: "root", Group: "root", MTime: 1700000000}
	}
	r.AddFile(RPMFile{Name: "/opt/feat", Mode: 040755, Owner: "root", Group: "root", MTime: 1700000000})
	r.AddFile(RPMFile{Name: "/opt/feat/bin", Mode: 040755, Owner: "root", Group: "root", MTime: 1700000000})
	hello := f("/opt/feat/bin/hello", 0755, "hello\n")
	hello.Owner, hello.Group, hello.Caps = "u1", "g1", "cap_net_raw=ep"
	r.AddFile(hello)
	hello2 := RPMFile{Name: "/opt/feat/bin/hello2", Mode: 0755, Owner: "u1", Group: "g1", MTime: 1700000000, Hardlink: "/opt/feat/bin/hello"}
	r.AddFile(hello2)
	r.AddFile(f("/opt/feat/bin/link", 0120777, "hello"))
	conf := f("/etc/feat.conf", 0644, "c\n")
	conf.Type = ConfigFile | NoReplaceFile
	conf.VerifyExclude = VerifyDigest | VerifySize | VerifyMTime
	r.AddFile(conf)
	de := f("/opt/feat/de.txt", 0644, "de\n")
	de.Lang = "de"
	r.AddFile(de)
	doc := f("/opt/feat/cls.txt", 0644, "cls\n")
	doc.Type = DocFile
	r.AddFile(doc)
	r.AddFile(RPMFile{Name: "/opt/feat/fifo", Mode: ModeFifo | 0644, Owner: "root", Group: "root", MTime: 1700000000})
	r.AddFile(RPMFile{Name: "/opt/feat/ghost", Owner: "root", Group: "root", MTime: 1700000000, Type: GhostFile})

	r.AddScriptlet(ScriptPretrans, Scriptlet{Script: "print(\"pretrans\")", Interpreter: []string{LuaInterpreter}})
	r.AddScriptlet(ScriptPrein, Scriptlet{Script: "echo pre %{name}", Flags: ScriptExpand})
	r.AddScriptlet(ScriptPostin, Scriptlet{Script: "echo post", Interpreter: []string{"/bin/sh", "-e"}})
	r.AddScriptlet(ScriptPreun, Scriptlet{Script: "echo preun", Flags: ScriptQFormat})
	r.AddScriptlet(ScriptPostun, Scriptlet{Script: "print(1)", Interpreter: []string{"/usr/bin/python3"}})
	r.AddScriptlet(ScriptPosttrans, Scriptlet{Script: "echo posttrans"})
	r.AddScriptlet(ScriptPreuntrans, Scriptlet{Script: "print(\"a\")", Interpreter: []string{LuaInterpreter}})
	r.AddScriptlet(ScriptPostuntrans, Scriptlet{Script: "echo b"})
	r.AddScriptlet(ScriptVerify, Scriptlet{Script: "echo verify"})
	r.AddTrigger(Trigger{Kind: TriggerPrein, Conditions: Relations{req("foo > 1", 0)}, Script: Scriptlet{Script: "echo tpre"}})
	r.AddTrigger(Trigger{Kind: TriggerIn, Conditions: Relations{req("bar", 0), req("baz >= 2.0", 0)},
		Script: Scriptlet{Script: "echo tin", Interpreter: []string{"/bin/bash"}}})
	r.AddTrigger(Trigger{Kind: TriggerUn, Conditions: Relations{req("bar", 0)}, Script: Scriptlet{Script: "echo tun"}})
	r.AddTrigger(Trigger{Kind: TriggerPostun, Conditions: Relations{req("bar < 3", 0)},
		Script: Scriptlet{Script: "print(\"tpostun\")", Interpreter: []string{LuaInterpreter}}})
	r.AddFileTrigger(FileTrigger{Kind: FileTriggerIn, Prefixes: []string{"/usr/lib"}, Priority: 100,
		Script: Scriptlet{Script: "echo fti", Interpreter: []string{"/bin/sh"}}})
	r.AddFileTrigger(FileTrigger{Kind: FileTriggerUn, Prefixes: []string{"/usr/share"}, Script: Scriptlet{Script: "echo ftu"}})
	r.AddFileTrigger(FileTrigger{Kind: FileTriggerPostun, Prefixes: []string{"/opt"}, Script: Scriptlet{Script: "echo ftpu"}})
	r.AddFileTrigger(FileTrigger{Kind: FileTriggerIn, Transaction: true, Prefixes: []string{"/usr/bin", "/usr/sbin"}, Priority: 5,
		Script: Scriptlet{Script: "echo tfti"}})
	r.AddFileTrigger(FileTrigger{Kind: FileTriggerUn, Transaction: true, Prefixes: []string{"/usr/lib"}, Script: Scriptlet{Script: "echo tftu"}})
	r.AddFileTrigger(FileTrigger{Kind: FileTriggerPostun, Transaction: true, Prefixes: []string{"/lib"}, Script: Scriptlet{Script: "echo tftpu"}})
	return r
}
