package repodata

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

func moduleFixtures(t *testing.T) []string {
	t.Helper()

	files, err := filepath.Glob(filepath.Join("testdata", "modules", "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no module fixtures: %v", err)
	}

	var out []string

	for _, f := range files {
		if !strings.HasSuffix(f, ".libmodulemd.yaml") {
			out = append(out, f)
		}
	}

	return out
}

func parseModules(t *testing.T, text string) *ModuleSet {
	t.Helper()

	set, err := ParseModulemd(strings.NewReader(text), ModulemdLimits{})
	if err != nil {
		t.Fatalf("ParseModulemd: %v", err)
	}

	return set
}

func parseModulesFile(t *testing.T, name string) *ModuleSet {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "modules", name))
	if err != nil {
		t.Fatal(err)
	}

	return parseModules(t, string(data))
}

func writeModules(t *testing.T, set *ModuleSet) string {
	t.Helper()

	var buf bytes.Buffer
	if err := WriteModules(&buf, set); err != nil {
		t.Fatalf("WriteModules: %v", err)
	}

	return buf.String()
}

// WriteModules produces what libmodulemd's own writer produces for the same
// content: the references are dumps of the fixtures through libmodulemd 2.15.4
// (testdata/modules/generate.sh). The only difference is the order of the
// locales of a translations document, which libmodulemd takes from a hash
// table, so that reference is compared after parsing.
func TestWriteModulesMatchesLibmodulemd(t *testing.T) {
	for _, f := range moduleFixtures(t) {
		t.Run(filepath.Base(f), func(t *testing.T) {
			name := filepath.Base(f)
			got := writeModules(t, parseModulesFile(t, name))

			want, err := os.ReadFile(strings.TrimSuffix(f, ".yaml") + ".libmodulemd.yaml")
			if err != nil {
				t.Fatal(err)
			}

			if len(parseModules(t, string(want)).Translations) != 0 {
				if !reflect.DeepEqual(parseModules(t, got), parseModules(t, string(want))) {
					t.Errorf("parsed output differs from libmodulemd's:\n%s", got)
				}

				return
			}

			if got != string(want) {
				t.Errorf("output differs from libmodulemd's:\n%s", firstDifference(got, string(want)))
			}
		})
	}
}

// canonicalModules keys the documents of a set, to compare sets whose order
// differs (the writer orders documents, the input may not).
func canonicalModules(set *ModuleSet) map[string]ModuleDocument {
	out := make(map[string]ModuleDocument)

	for _, d := range set.Defaults {
		out[fmt.Sprintf("defaults %s %d", d.Module, d.Modified)] = d
	}

	for _, o := range set.Obsoletes {
		out[fmt.Sprintf("obsoletes %s:%s:%s %v", o.Module, o.Stream, o.Context, o.Modified)] = o
	}

	for _, tr := range set.Translations {
		out[fmt.Sprintf("translations %s:%s %d", tr.Module, tr.Stream, tr.Modified)] = tr
	}

	for _, st := range set.Streams {
		out["stream "+st.NSVCA()] = st
	}

	return out
}

func firstDifference(got, want string) string {
	g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := range min(len(g), len(w)) {
		if g[i] != w[i] {
			return fmt.Sprintf("line %d:\n got %q\nwant %q", i+1, g[i], w[i])
		}
	}

	return fmt.Sprintf("lengths differ: %d and %d lines", len(g), len(w))
}

// Writing normalizes a document (sets are sorted and deduplicated), and what
// it wrote reads back unchanged: the second generation equals the first,
// down to the bytes of the output.
func TestModulemdRoundTrip(t *testing.T) {
	for _, f := range moduleFixtures(t) {
		t.Run(filepath.Base(f), func(t *testing.T) {
			first := parseModulesFile(t, filepath.Base(f))
			text := writeModules(t, first)

			second := parseModules(t, text)
			if len(canonicalModules(first)) != len(canonicalModules(second)) {
				t.Fatalf("documents: %d, then %d", len(canonicalModules(first)), len(canonicalModules(second)))
			}

			if again := writeModules(t, second); again != text {
				t.Fatalf("second write differs:\n%s", firstDifference(again, text))
			}

			third := parseModules(t, writeModules(t, second))
			if !reflect.DeepEqual(canonicalModules(second), canonicalModules(third)) {
				t.Fatal("round trip changed the content")
			}
		})
	}
}

func TestParseStreamV2Spec(t *testing.T) {
	set := parseModulesFile(t, "spec-stream-v2.yaml")
	if len(set.Streams) != 1 || len(set.Defaults)+len(set.Obsoletes)+len(set.Translations) != 0 {
		t.Fatalf("got %d streams and %d other documents", len(set.Streams), len(set.Defaults)+len(set.Obsoletes)+len(set.Translations))
	}

	s := set.Streams[0]

	if s.Name != "foo" || s.Stream != "latest" || s.Version != 20160927144203 || s.Context != "c0ffee43" || s.Arch != "x86_64" || s.StaticContext {
		t.Errorf("identity: %+v", s)
	}

	if got := s.NSVCA(); got != "foo:latest:20160927144203:c0ffee43:x86_64" {
		t.Errorf("NSVCA = %q", got)
	}

	if s.Summary != "An example module" || !strings.HasPrefix(s.Description, "A module for the demonstration of the metadata format. Also, the obligatory") {
		t.Errorf("texts: %q %q", s.Summary, s.Description)
	}

	if strings.Contains(s.Description, "\n") {
		t.Errorf("a folded description must be one line: %q", s.Description)
	}

	if len(s.ServiceLevels) != 4 || s.ServiceLevels["rawhide"].EOL != "2077-10-23" {
		t.Errorf("service levels: %+v", s.ServiceLevels)
	}

	if !reflect.DeepEqual(s.License, ModuleLicense{Module: []string{"MIT"}, Content: []string{"Apache-2.0", "GPL-1.0-or-later OR Artistic-1.0-Perl"}}) {
		t.Errorf("license: %+v", s.License)
	}

	if !reflect.DeepEqual(s.XMD, map[string]any{"some_key": "some_data"}) {
		t.Errorf("xmd: %#v", s.XMD)
	}

	if len(s.Dependencies) != 4 {
		t.Fatalf("dependencies: %d", len(s.Dependencies))
	}

	if got := s.Dependencies[1].BuildRequires["buildtools"]; !reflect.DeepEqual(got, []string{"v1", "v2"}) {
		t.Errorf("buildtools = %v", got)
	}

	if got, ok := s.Dependencies[3].Requires["extras"]; !ok || len(got) != 0 {
		t.Errorf("an empty stream list must stay present: %v, %v", got, ok)
	}

	if got := s.Dependencies[0].Requires["platform"]; !reflect.DeepEqual(got, []string{"-f27", "-f28", "-epel7"}) {
		t.Errorf("excluded streams = %v", got)
	}

	if s.References.Community != "http://www.example.com/" || s.References.Tracker == "" || s.References.Documentation == "" {
		t.Errorf("references: %+v", s.References)
	}

	if p := s.Profiles["minimal"]; p.Description != "Minimal profile installing only the bar package." || !reflect.DeepEqual(p.RPMs, []string{"bar"}) {
		t.Errorf("profile minimal: %+v", p)
	}

	if len(s.Profiles) != 4 || !reflect.DeepEqual(s.API, []string{"bar", "bar-extras", "bar-devel", "baz", "xxx"}) ||
		!reflect.DeepEqual(s.Filter, []string{"baz-nonfoo"}) || !reflect.DeepEqual(s.Demodularized, []string{"bar-old"}) {
		t.Errorf("profiles %d, api %v, filter %v, demodularized %v", len(s.Profiles), s.API, s.Filter, s.Demodularized)
	}

	bo := s.BuildOpts
	if bo == nil || bo.Macros != "%demomacro 1\n%demomacro2 %{demomacro}23\n" || len(bo.Whitelist) != 4 || !reflect.DeepEqual(bo.Arches, []string{"i686", "x86_64"}) {
		t.Errorf("buildopts: %+v", bo)
	}

	bar := s.Components.RPMs["bar"]
	if bar.Name != "bar-real" || bar.Repository != "https://pagure.io/bar.git" || bar.Cache != "https://example.com/cache" || bar.Ref != "26ca0c0" || bar.BuildOnly {
		t.Errorf("component bar: %+v", bar)
	}

	baz := s.Components.RPMs["baz"]
	if !baz.Buildroot || !baz.SRPMBuildroot || baz.BuildOrder != -1 {
		t.Errorf("component baz: %+v", baz)
	}

	xxx := s.Components.RPMs["xxx"]
	if !reflect.DeepEqual(xxx.Arches, []string{"i686", "x86_64"}) || !reflect.DeepEqual(xxx.Multilib, []string{"x86_64"}) {
		t.Errorf("component xxx: %+v", xxx)
	}

	inc := s.Components.Modules["includedmodule"]
	if inc.Ref != "somecoolbranchname" || inc.BuildOrder != 100 || inc.Repository != "https://pagure.io/includedmodule.git" {
		t.Errorf("module component: %+v", inc)
	}

	if len(s.Artifacts.RPMs) != 7 {
		t.Errorf("artifacts: %v", s.Artifacts.RPMs)
	}

	e := s.Artifacts.RPMMap["sha256"]["ee47083ed80146eb2c84e9a94d0836393912185dcda62b9d93ee0c2ea5dc795b"]
	if e.Name != "bar" || e.Epoch != 0 || e.Version != "1.23" || e.Release != "1.module_deadbeef" || e.Arch != "x86_64" {
		t.Errorf("rpm-map entry: %+v", e)
	}

	if e.NEVRA() != "bar-0:1.23-1.module_deadbeef.x86_64" {
		t.Errorf("NEVRA = %q", e.NEVRA())
	}
}

func TestParseDefaultsObsoletesTranslationsSpec(t *testing.T) {
	d := parseModulesFile(t, "spec-defaults-v1.yaml").Defaults
	if len(d) != 1 {
		t.Fatalf("defaults: %d", len(d))
	}

	want := &ModuleDefaults{
		Module: "foo", Modified: 201812071200, Stream: "x.y",
		Profiles: map[string][]string{"x.y": {}, "bar": {"baz", "snafu"}},
		Intents: map[string]ModuleDefaultsIntent{
			"desktop": {Stream: "y.z", Profiles: map[string][]string{"y.z": {"blah"}, "x.y": {"other"}}},
			"server":  {Stream: "x.y", Profiles: map[string][]string{"x.y": {}}},
		},
	}
	if !reflect.DeepEqual(d[0], want) {
		t.Errorf("defaults = %+v\nwant     %+v", d[0], want)
	}

	o := parseModulesFile(t, "spec-obsoletes-v1.yaml").Obsoletes
	if len(o) != 1 {
		t.Fatalf("obsoletes: %d", len(o))
	}

	wantO := &ModuleObsoletes{
		Module: "nodejs", Stream: "11", Context: "aabbccddee",
		Modified:    time.Date(2018, 5, 23, 14, 25, 0, 0, time.UTC),
		EOLDate:     time.Date(2020, 3, 19, 0, 0, 0, 0, time.UTC),
		Message:     "Module stream nodejs:11 is no longer supported. It is recommended to switch to nodejs:12",
		ObsoletedBy: &ModuleObsoletedBy{Module: "nodejs", Stream: "12"},
	}
	if !reflect.DeepEqual(o[0], wantO) {
		t.Errorf("obsoletes = %+v\nwant      %+v", o[0], wantO)
	}

	tr := parseModulesFile(t, "spec-translations-v1.yaml").Translations
	if len(tr) != 1 || tr[0].Module != "foo" || tr[0].Stream != "latest" || tr[0].Modified != 201805231425 || len(tr[0].Locales) != 3 {
		t.Fatalf("translations: %+v", tr)
	}

	ja := tr[0].Locales["ja"]
	if ja.Summary != "モジュールの例" || ja.Profiles["profile_a"] != "プロファイルの例" {
		t.Errorf("ja = %+v", ja)
	}
}

func TestParseRealRepositories(t *testing.T) {
	r9 := parseModulesFile(t, "rocky9-appstream.yaml")
	if len(r9.Streams) != 4 || len(r9.Defaults) != 3 {
		t.Fatalf("rocky 9: %d streams, %d defaults", len(r9.Streams), len(r9.Defaults))
	}

	for _, s := range r9.Streams {
		if !s.StaticContext || s.Arch == "" || s.Version == 0 || len(s.Artifacts.RPMs) == 0 || s.XMD == nil || len(s.XMD) != 0 {
			t.Errorf("%s: %+v", s.NSVCA(), s)
		}
	}

	// A numeric-looking key stays text: "10.11" is a stream, not a float.
	for _, d := range r9.Defaults {
		if d.Module == "mariadb" && !reflect.DeepEqual(d.Profiles["10.11"], []string{"server"}) {
			t.Errorf("mariadb profiles: %v", d.Profiles)
		}
	}

	r8 := parseModulesFile(t, "rocky8-appstream.yaml")

	var gotWhitelist, gotMultilib, gotBuildOnly bool

	for _, s := range r8.Streams {
		if s.BuildOpts != nil && len(s.BuildOpts.Whitelist) != 0 {
			gotWhitelist = true
		}

		for _, c := range s.Components.RPMs {
			gotMultilib = gotMultilib || len(c.Multilib) != 0
			gotBuildOnly = gotBuildOnly || c.BuildOnly
		}
	}

	if len(r8.Streams) != 4 || !gotWhitelist || !gotMultilib {
		t.Errorf("rocky 8: %d streams, whitelist %v, multilib %v, buildonly %v", len(r8.Streams), gotWhitelist, gotMultilib, gotBuildOnly)
	}

	f := parseModulesFile(t, "fedora38-obsoletes.yaml")
	if len(f.Obsoletes) != 3 {
		t.Fatalf("obsoletes: %d", len(f.Obsoletes))
	}

	if o := f.Obsoletes[1]; o.Module != "perl" || o.Stream != "5.30" || o.ObsoletedBy == nil || o.ObsoletedBy.Stream != "5.32" ||
		!o.Modified.Equal(time.Date(2022, 1, 24, 8, 54, 0, 0, time.UTC)) {
		t.Errorf("perl obsoletes: %+v", o)
	}

	if o := f.Obsoletes[2]; !strings.Contains(o.Message, "Please switch to perl-IO-Socket-SSL:2.074") {
		t.Errorf("a folded message must be joined: %q", o.Message)
	}
}

func TestModuleStreamNSVCA(t *testing.T) {
	for _, tc := range []struct {
		s    ModuleStream
		want string
	}{
		{ModuleStream{Name: "n", Stream: "s", Version: 3, Context: "c", Arch: "a"}, "n:s:3:c:a"},
		{ModuleStream{Name: "n", Stream: "s", Version: 3, Context: "c"}, "n:s:3:c"},
		{ModuleStream{Name: "n", Stream: "s", Version: 3}, "n:s:3"},
		{ModuleStream{Name: "n", Stream: "s"}, "n:s"},
		{ModuleStream{Name: "n", Stream: "s", Context: "c"}, "n:s::c"},
		{ModuleStream{Name: "n"}, "n"},
	} {
		if got := tc.s.NSVCA(); got != tc.want {
			t.Errorf("%+v: NSVCA = %q, want %q", tc.s, got, tc.want)
		}
	}
}

// The groups of a modules.yaml come in libmodulemd's order whatever the order
// of the set.
func TestWriteModulesOrder(t *testing.T) {
	stream := func(name, stream string, version uint64) *ModuleStream {
		return &ModuleStream{
			Name: name, Stream: stream, Version: version, Summary: "s", Description: "d",
			License: ModuleLicense{Module: []string{"MIT"}},
		}
	}

	set := &ModuleSet{
		Streams:  []*ModuleStream{stream("b", "1", 2), stream("a", "2", 1), stream("b", "1", 1), stream("a", "1", 5)},
		Defaults: []*ModuleDefaults{{Module: "b", Stream: "1"}, {Module: "a", Stream: "2"}},
		Obsoletes: []*ModuleObsoletes{{
			Module: "a", Stream: "1", Message: "gone", Modified: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		}},
		Translations: []*ModuleTranslations{{Module: "a", Stream: "2", Modified: 1}, {Module: "a", Stream: "1", Modified: 1}},
	}

	var order []string

	err := ReadModulemd(strings.NewReader(writeModules(t, set)), ModulemdLimits{}, func(doc ModuleDocument) error {
		switch d := doc.(type) {
		case *ModuleStream:
			order = append(order, "stream "+d.NSVCA())
		case *ModuleDefaults:
			order = append(order, "defaults "+d.Module)
		case *ModuleObsoletes:
			order = append(order, "obsoletes "+d.Module+":"+d.Stream)
		case *ModuleTranslations:
			order = append(order, "translations "+d.Module+":"+d.Stream)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"defaults a", "obsoletes a:1", "translations a:1", "translations a:2", "stream a:1:5", "stream a:2:1",
		"defaults b", "stream b:1:1", "stream b:1:2",
	}
	if !reflect.DeepEqual(order, want) {
		t.Errorf("order = %v\nwant    %v", order, want)
	}

	if got := writeModules(t, &ModuleSet{}); got != "" {
		t.Errorf("an empty set wrote %q", got)
	}
}

func TestReadModulemdKinds(t *testing.T) {
	const stream = "document: modulemd\nversion: 2\ndata:\n  name: n\n  stream: s\n  summary: s\n  description: d\n  license:\n    module: [MIT]\n"

	for name, tc := range map[string]struct {
		text string
		want error
	}{
		"v1 stream":          {"---\ndocument: modulemd\nversion: 1\ndata:\n  name: n\n", ErrUnsupportedModulemd},
		"future defaults":    {"---\ndocument: modulemd-defaults\nversion: 2\ndata:\n  module: n\n", ErrUnsupportedModulemd},
		"unknown document":   {"---\ndocument: modulemd-packager\nversion: 3\ndata: {}\n", ErrUnsupportedModulemd},
		"no data":            {"---\ndocument: modulemd\nversion: 2\n", ErrInvalidModulemd},
		"not a mapping":      {"---\n- a\n- b\n", ErrInvalidModulemd},
		"scalar document":    {"---\njust text\n", ErrInvalidModulemd},
		"null document":      {"---\n~\n", ErrInvalidModulemd},
		"bad yaml":           {"---\ndocument: [unclosed\n", ErrInvalidModulemd},
		"bad version":        {"---\ndocument: modulemd\nversion: two\ndata: {}\n", ErrInvalidModulemd},
		"repeated key":       {"---\n" + stream + "  name: m\n", ErrInvalidModulemd},
		"alias":              {"---\n" + stream + "  xmd: &a {k: v}\n  references: *a\n", ErrInvalidModulemd},
		"alias value":        {"---\n" + stream + "  xmd: {k: &a v, j: *a}\n", ErrInvalidModulemd},
		"data not a map":     {"---\ndocument: modulemd\nversion: 2\ndata: [a]\n", ErrInvalidModulemd},
		"complex key":        {"---\n" + stream + "  ? [a]\n  : b\n", ErrInvalidModulemd},
		"missing name":       {"---\ndocument: modulemd\nversion: 2\ndata:\n  stream: s\n", ErrInvalidModulemd},
		"missing license":    {"---\ndocument: modulemd\nversion: 2\ndata:\n  name: n\n  stream: s\n  summary: s\n  description: d\n", ErrInvalidModulemd},
		"bad version field":  {"---\n" + stream + "  version: 1.5\n", ErrInvalidModulemd},
		"bad bool":           {"---\n" + stream + "  static_context: maybe\n", ErrInvalidModulemd},
		"list as scalar":     {"---\n" + stream + "  arch: [x]\n", ErrInvalidModulemd},
		"scalar as list":     {"---\n" + stream + "  api:\n    rpms: x\n", ErrInvalidModulemd},
		"bad eol":            {"---\n" + stream + "  servicelevels:\n    rawhide:\n      eol: soon\n", ErrInvalidModulemd},
		"bad dependencies":   {"---\n" + stream + "  dependencies: x\n", ErrInvalidModulemd},
		"bad dep item":       {"---\n" + stream + "  dependencies: [x]\n", ErrInvalidModulemd},
		"bad profile":        {"---\n" + stream + "  profiles:\n    p: x\n", ErrInvalidModulemd},
		"order and after":    {"---\n" + stream + "  components:\n    rpms:\n      a: {rationale: r, buildorder: 1, buildafter: [b]}\n", ErrInvalidModulemd},
		"bad buildorder":     {"---\n" + stream + "  components:\n    modules:\n      a: {rationale: r, buildorder: x}\n", ErrInvalidModulemd},
		"bad epoch":          {"---\n" + stream + "  artifacts:\n    rpm-map:\n      sha256:\n        ab:\n          name: n\n          epoch: -1\n", ErrInvalidModulemd},
		"incomplete rpm-map": {"---\n" + stream + "  artifacts:\n    rpm-map:\n      sha256:\n        ab:\n          name: n\n", ErrInvalidModulemd},
		"xmd scalar":         {"---\n" + stream + "  xmd: text\n", ErrInvalidModulemd},
		"defaults no module": {"---\ndocument: modulemd-defaults\nversion: 1\ndata:\n  stream: s\n", ErrInvalidModulemd},
		"defaults modified":  {"---\ndocument: modulemd-defaults\nversion: 1\ndata:\n  module: m\n  modified: yesterday\n", ErrInvalidModulemd},
		"defaults profiles":  {"---\ndocument: modulemd-defaults\nversion: 1\ndata:\n  module: m\n  profiles: x\n", ErrInvalidModulemd},
		"intent not map":     {"---\ndocument: modulemd-defaults\nversion: 1\ndata:\n  module: m\n  intents:\n    a: b\n", ErrInvalidModulemd},
		"obsoletes date":     {"---\ndocument: modulemd-obsoletes\nversion: 1\ndata:\n  modified: 2020-01-01\n  module: m\n  stream: s\n  message: x\n", ErrInvalidModulemd},
		"obsoletes message":  {"---\ndocument: modulemd-obsoletes\nversion: 1\ndata:\n  modified: 2020-01-01T00:00Z\n  module: m\n  stream: s\n", ErrInvalidModulemd},
		"obsoleted_by half":  {"---\ndocument: modulemd-obsoletes\nversion: 1\ndata:\n  modified: 2020-01-01T00:00Z\n  module: m\n  stream: s\n  message: x\n  obsoleted_by:\n    module: m\n", ErrInvalidModulemd},
		"translations name":  {"---\ndocument: modulemd-translations\nversion: 1\ndata:\n  stream: s\n", ErrInvalidModulemd},
		"translations shape": {"---\ndocument: modulemd-translations\nversion: 1\ndata:\n  module: m\n  stream: s\n  translations:\n    ja: x\n", ErrInvalidModulemd},
		"translated profile": {"---\ndocument: modulemd-translations\nversion: 1\ndata:\n  module: m\n  stream: s\n  translations:\n    ja:\n      profiles:\n        p: [x]\n", ErrInvalidModulemd},
		"invalid utf-8":      {"---\n" + stream + "  context: \xff\n", ErrInvalidModulemd},
		"second doc bad":     {"---\n" + stream + "...\n---\ndocument: modulemd\nversion: 2\ndata: x\n", ErrInvalidModulemd},
		"smuggled document":  {"---\n" + stream + "--- {document: x, version: 1, data: {}}\n", ErrUnsupportedModulemd},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseModulemd(strings.NewReader(tc.text), ModulemdLimits{})
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}

			if errors.Is(err, ErrTooLarge) {
				t.Errorf("%v must not be a size error", err)
			}
		})
	}
}

func TestReadModulemdEmptyInput(t *testing.T) {
	for _, text := range []string{"", "\n", "---\n...\n", "# nothing\n---\n", "---\n---\n...\n"} {
		set, err := ParseModulemd(strings.NewReader(text), ModulemdLimits{})
		if err != nil || len(set.Streams)+len(set.Defaults)+len(set.Obsoletes)+len(set.Translations) != 0 {
			t.Errorf("%q: %v, %+v", text, err, set)
		}
	}
}

func TestReadModulemdLimits(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "modules", "spec-stream-v2.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	text := string(data)

	for name, tc := range map[string]struct {
		text string
		lim  ModulemdLimits
	}{
		"whole file":     {text, ModulemdLimits{MaxBytes: int64(len(text) - 1)}},
		"document":       {text, ModulemdLimits{MaxDocumentBytes: 1000}},
		"long line":      {"---\nk: " + strings.Repeat("x", 5000) + "\n", ModulemdLimits{MaxDocumentBytes: 4096}},
		"list entries":   {text, ModulemdLimits{MaxEntries: 3}},
		"mapping keys":   {text, ModulemdLimits{MaxEntries: 5}},
		"xmd depth":      {"---\ndocument: modulemd\nversion: 2\ndata:\n  xmd: " + strings.Repeat("[", 10) + strings.Repeat("]", 10) + "\n", ModulemdLimits{MaxDepth: 4}},
		"xmd list":       {"---\ndocument: modulemd\nversion: 2\ndata:\n  xmd: {k: [a, b, c]}\n", ModulemdLimits{MaxEntries: 2}},
		"dependencies":   {"---\ndocument: modulemd\nversion: 2\ndata:\n  dependencies: [{}, {}, {}]\n", ModulemdLimits{MaxEntries: 2}},
		"many documents": {strings.Repeat("---\ndocument: modulemd-defaults\nversion: 1\ndata:\n  module: m\n...\n", 20), ModulemdLimits{MaxBytes: 500}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseModulemd(strings.NewReader(tc.text), tc.lim)
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("err = %v, want ErrTooLarge", err)
			}
		})
	}

	// Within the limits the same input parses.
	if _, err := ParseModulemd(strings.NewReader(text), ModulemdLimits{MaxBytes: int64(len(text)), MaxDocumentBytes: len(text) + 1, MaxEntries: 100, MaxDepth: 4}); err != nil {
		t.Fatalf("within limits: %v", err)
	}
}

func TestReadModulemdStreams(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "modules", "rocky9-appstream.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	// Documents are delivered one at a time: stopping at the first leaves the
	// rest unread.
	r := bytes.NewReader(data)
	stop := errors.New("stop")
	calls := 0

	err = ReadModulemd(iotest.OneByteReader(r), ModulemdLimits{}, func(doc ModuleDocument) error {
		calls++

		if _, ok := doc.(*ModuleDefaults); !ok {
			t.Errorf("first document is a %T", doc)
		}

		return stop
	})
	if !errors.Is(err, stop) || calls != 1 {
		t.Errorf("err = %v after %d calls", err, calls)
	}

	if r.Len() == 0 {
		t.Error("the whole input was read before the first document was delivered")
	}

	boom := errors.New("boom")

	err = ReadModulemd(io.MultiReader(bytes.NewReader(data[:100]), iotest.ErrReader(boom)), ModulemdLimits{}, func(ModuleDocument) error { return nil })
	if !errors.Is(err, boom) {
		t.Errorf("a failing reader: %v", err)
	}
}

func TestReadModulemdNoTrailingTerminator(t *testing.T) {
	set := parseModules(t, "---\ndocument: modulemd-defaults\nversion: 1\ndata:\n  module: a\n---\ndocument: modulemd-defaults\nversion: 1\ndata:\n  module: b")
	if len(set.Defaults) != 2 || set.Defaults[1].Module != "b" {
		t.Errorf("defaults: %+v", set.Defaults)
	}

	set = parseModules(t, "document: modulemd-defaults\r\nversion: 1\r\ndata:\r\n  module: a\r\n...\r\n")
	if len(set.Defaults) != 1 {
		t.Errorf("CRLF: %+v", set.Defaults)
	}
}

func TestParseXMD(t *testing.T) {
	set := parseModules(t, `---
document: modulemd
version: 2
data:
  name: n
  stream: s
  summary: s
  description: d
  license: {module: [MIT]}
  xmd:
    flag: TRUE
    other: FALSE
    lower: true
    number: 42
    float: 1.50
    nested:
      list: [a, 1, TRUE, {k: v}]
      empty: {}
    mbs:
      scmurl: https://example.com/x.git
...
`)

	want := map[string]any{
		"flag": true, "other": false, "lower": "true", "number": "42", "float": "1.50",
		"nested": map[string]any{"list": []any{"a", "1", true, map[string]any{"k": "v"}}, "empty": map[string]any{}},
		"mbs":    map[string]any{"scmurl": "https://example.com/x.git"},
	}
	if got := set.Streams[0].XMD; !reflect.DeepEqual(got, want) {
		t.Errorf("xmd = %#v\nwant  %#v", got, want)
	}

	out := writeModules(t, set)
	if !strings.Contains(out, "    flag: TRUE\n") || !strings.Contains(out, "      empty: {}\n") || !strings.Contains(out, "    number: \"42\"\n") {
		t.Errorf("xmd written as:\n%s", out)
	}

	if !reflect.DeepEqual(parseModules(t, out), set) {
		t.Error("xmd changed across a write")
	}
}

func validStream() *ModuleStream {
	return &ModuleStream{
		Name: "n", Stream: "s", Summary: "s", Description: "d",
		License: ModuleLicense{Module: []string{"MIT"}},
	}
}

func TestWriteModulesRejects(t *testing.T) {
	mod := func(f func(*ModuleStream)) *ModuleSet {
		s := validStream()
		f(s)

		return &ModuleSet{Streams: []*ModuleStream{s}}
	}

	for name, set := range map[string]*ModuleSet{
		"no name":        mod(func(s *ModuleStream) { s.Name = "" }),
		"no stream":      mod(func(s *ModuleStream) { s.Stream = "" }),
		"no summary":     mod(func(s *ModuleStream) { s.Summary = "" }),
		"no description": mod(func(s *ModuleStream) { s.Description = "" }),
		"no license":     mod(func(s *ModuleStream) { s.License = ModuleLicense{} }),
		"rpm order and after": mod(func(s *ModuleStream) {
			s.Components.RPMs = map[string]ModuleRPMComponent{"a": {Rationale: "r", BuildOrder: 1, BuildAfter: []string{"b"}}}
		}),
		"module order and after": mod(func(s *ModuleStream) {
			s.Components.Modules = map[string]ModuleModuleComponent{"a": {Rationale: "r", BuildOrder: 1, BuildAfter: []string{"b"}}}
		}),
		"rpm-map": mod(func(s *ModuleStream) {
			s.Artifacts.RPMMap = map[string]map[string]ModuleRPMMapEntry{"sha256": {"ab": {Name: "n"}}}
		}),
		"eol": mod(func(s *ModuleStream) {
			s.ServiceLevels = map[string]ModuleServiceLevel{"rawhide": {EOL: "next year"}}
		}),
		"xmd type": mod(func(s *ModuleStream) { s.XMD = map[string]any{"n": 1} }),
		"xmd nested type": mod(func(s *ModuleStream) {
			s.XMD = map[string]any{"l": []any{map[string]any{"f": 1.5}}}
		}),
		"xmd depth": mod(func(s *ModuleStream) {
			var v any = "x"
			for range DefaultMaxModulemdDepth + 2 {
				v = []any{v}
			}

			s.XMD = map[string]any{"deep": v}
		}),
		"invalid utf-8": mod(func(s *ModuleStream) { s.Summary = "bad \xff text" }),
		"defaults":      {Defaults: []*ModuleDefaults{{}}},
		"obsoletes":     {Obsoletes: []*ModuleObsoletes{{Module: "m", Stream: "s"}}},
		"translations":  {Translations: []*ModuleTranslations{{Module: "m"}}},
	} {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := WriteModules(&buf, set); !errors.Is(err, ErrInvalidModulemd) {
				t.Fatalf("err = %v, want ErrInvalidModulemd", err)
			}
		})
	}

	if err := WriteModuleDocument(io.Discard, nil); !errors.Is(err, ErrUnsupportedModulemd) {
		t.Errorf("a nil document: %v", err)
	}
}

func TestWriteModulesWriterFails(t *testing.T) {
	boom := errors.New("disk full")

	set := &ModuleSet{Streams: []*ModuleStream{validStream()}}
	if err := WriteModules(failWriter{boom}, set); !errors.Is(err, boom) {
		t.Errorf("err = %v", err)
	}

	// A document that fails validation writes nothing, not even its header.
	var buf bytes.Buffer

	bad := validStream()
	bad.Summary = ""

	if err := WriteModuleDocument(&buf, bad); err == nil || buf.Len() != 0 {
		t.Errorf("err = %v, wrote %q", err, buf.String())
	}
}

type failWriter struct{ err error }

func (f failWriter) Write([]byte) (int, error) { return 0, f.err }

// Texts with quirks survive a write: leading and trailing blanks, line
// breaks, numbers, indicators, long and non-ASCII values.
func TestWriteModulesTextsRoundTrip(t *testing.T) {
	texts := append(oddTexts(), "", " leading", "\nstarts", "\n", "  \n  ", "nul\x00byte", "nel\u0085x", "ls\u2028x", "ps\u2029x", "bom\ufeffx", "del\x7f",
		"0000000000000000000000000000000000000000000000000000000000000000000000000000 ", "  indented\n    more\nback")

	for _, text := range texts {
		s := validStream()
		s.Summary = text + "!"
		s.Description = text + "?"
		s.Context = text
		s.Profiles = map[string]ModuleProfile{text + ".": {Description: text + "!", RPMs: []string{text + "-x"}}}
		s.XMD = map[string]any{text + ".": text + "!"}

		set := &ModuleSet{Streams: []*ModuleStream{s}}

		var buf bytes.Buffer
		if err := WriteModules(&buf, set); err != nil {
			t.Fatalf("%q: %v", text, err)
		}

		got, err := ParseModulemd(&buf, ModulemdLimits{})
		if err != nil {
			t.Fatalf("%q: reading back: %v\n%s", text, err, buf.String())
		}

		if !reflect.DeepEqual(got, set) {
			t.Errorf("%q: read back %+v", text, got.Streams[0])
		}
	}
}

func TestModuleLooksNumeric(t *testing.T) {
	for s, want := range map[string]bool{
		"": true, "1": true, "10": true, "1.5": true, "-1": true, "+1": true, ".5": true, "-.5": true, "1.5e3": true, "1.5E+3": true,
		"1.5e-3": true, "0x1f": true, "0xFF": true, "0o17": true, ".nan": true, ".inf": true, "-.inf": true, "+.inf": true,
		"1.2.3": false, "1e5": false, "0x": false, "0xg": false, "0o8": false, "1.5e3e4": false, "1.5e+-3": false, "a": false, "el8": false,
		"1a": false, "-": false, ".": false, "+": false, "v1": false, "1.": true, "10.11": true, "9": true, "rhel9": false, "-f27": false,
	} {
		if got := mmLooksNumeric(s); got != want {
			t.Errorf("mmLooksNumeric(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestWriteModulesSetsAreSorted(t *testing.T) {
	s := validStream()
	s.License.Module = []string{"MIT", "BSD", "MIT"}
	s.API = []string{"b", "a", "b"}
	s.Dependencies = []ModuleDependency{
		{Requires: map[string][]string{"platform": {"el9", "el8"}, "a": nil}},
		{},
	}
	s.Components.RPMs = map[string]ModuleRPMComponent{
		"z": {Rationale: "r", BuildAfter: []string{"y", "x"}, Arches: []string{"x86_64", "aarch64"}},
		"a": {Rationale: "r", BuildOnly: true, Buildroot: true},
	}

	out := writeModules(t, &ModuleSet{Streams: []*ModuleStream{s}})

	for _, want := range []string{
		"    module:\n    - BSD\n    - MIT\n", "  api:\n    rpms:\n    - a\n    - b\n",
		"  dependencies:\n  - requires:\n      a: []\n      platform: [el8, el9]\n  - {}\n",
		"      a:\n        rationale: r\n        buildroot: true\n        buildonly: true\n      z:\n        rationale: r\n        buildafter:\n        - x\n        - y\n        arches: [aarch64, x86_64]\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

// Like libmodulemd, a component needs no rationale: it is written as {}.
func TestWriteModulesComponentWithoutRationale(t *testing.T) {
	s := validStream()
	s.Components.RPMs = map[string]ModuleRPMComponent{"a": {}}
	s.Components.Modules = map[string]ModuleModuleComponent{"m": {}}

	out := writeModules(t, &ModuleSet{Streams: []*ModuleStream{s}})
	if !strings.Contains(out, "      a: {}\n") || !strings.Contains(out, "      m: {}\n") {
		t.Fatalf("components are not written as {}:\n%s", out)
	}

	got := parseModules(t, out)
	if !reflect.DeepEqual(canonicalModules(got), canonicalModules(&ModuleSet{Streams: []*ModuleStream{s}})) {
		t.Errorf("read back as %+v", got.Streams[0].Components)
	}
}

func TestWriteModulesModuleComponentsAndObsoletes(t *testing.T) {
	s := validStream()
	s.StaticContext = true
	s.Components.Modules = map[string]ModuleModuleComponent{
		"m": {Rationale: "r", Repository: "https://x/y.git", Ref: "main", BuildAfter: []string{"b"}, BuildOnly: true},
	}
	s.BuildOpts = &ModuleBuildOpts{}

	o := &ModuleObsoletes{
		Module: "m", Stream: "1", Context: "c", Message: "gone", Reset: true,
		Modified:    time.Date(2020, 1, 2, 3, 4, 59, 0, time.FixedZone("x", 3600)),
		EOLDate:     time.Date(2021, 5, 6, 0, 0, 0, 0, time.UTC),
		ObsoletedBy: &ModuleObsoletedBy{Module: "m", Stream: "2"},
	}
	set := &ModuleSet{Streams: []*ModuleStream{s}, Obsoletes: []*ModuleObsoletes{o}}
	out := writeModules(t, set)

	for _, want := range []string{
		"  static_context: true\n", "  buildopts:\n    rpms: {}\n",
		"      m:\n        rationale: r\n        repository: https://x/y.git\n        ref: main\n        buildafter:\n        - b\n        buildonly: true\n",
		"  modified: 2020-01-02T02:04Z\n  reset: true\n  module: m\n  stream: \"1\"\n  context: c\n  eol_date: 2021-05-06T00:00Z\n  message: gone\n  obsoleted_by:\n    module: m\n    stream: \"2\"\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}

	got := parseModules(t, out)
	o.Modified = o.Modified.UTC().Truncate(time.Minute)

	if !reflect.DeepEqual(got, set) {
		t.Errorf("read back\n%+v\nwant\n%+v", got.Obsoletes[0], o)
	}
}

// Writing is idempotent: a document, once written, reads and writes back to
// the same bytes. This is the property the fuzz tests rely on.
func TestWriteModulesIdempotentOnOddInput(t *testing.T) {
	for _, text := range []string{
		"---\ndocument: modulemd\nversion: 2\ndata:\n  name: n\n  stream: 1.0\n  summary: 2\n  description: |\n    a\n\n    b\n  license: {module: [MIT]}\n  api: {rpms: []}\n  profiles: {p: {}}\n  components: {rpms: {}}\n  artifacts: {rpms: []}\n",
		"---\ndocument: modulemd-translations\nversion: 1\ndata:\n  module: m\n  stream: s\n  translations: {}\n",
		"---\ndocument: modulemd-defaults\nversion: 1\ndata:\n  module: m\n  profiles: {}\n  intents: {}\n",
	} {
		first := writeModules(t, parseModules(t, text))
		if second := writeModules(t, parseModules(t, first)); second != first {
			t.Errorf("not idempotent:\n%s\n%s", first, second)
		}
	}
}
