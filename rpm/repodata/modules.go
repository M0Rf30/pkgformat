package repodata

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/M0Rf30/pkgformat/internal/limitio"
)

// MergeModules concatenates the modulemd documents of several modules.yaml
// files into one, in order. A document an earlier file already provided (the
// same module stream version and context, the same defaults or obsoletes
// record) is dropped, so the first source wins like it does for packages. It
// returns the number of documents written; a source over [DefaultMaxModulesDocument] fails with [ErrTooLarge]; a file whose documents cannot be
// parsed contributes none of them.
func MergeModules(w io.Writer, sources []io.Reader) (int, error) {
	seen := make(map[string]struct{})
	n := 0

	for _, src := range sources {
		data, err := limitio.ReadAll(src, DefaultMaxModulesDocument, ErrTooLarge)
		if err != nil {
			return n, fmt.Errorf("repodata: reading modules.yaml: %w", err)
		}

		for _, doc := range splitYAMLDocuments(string(data)) {
			key, ok := moduleKey(doc)
			if !ok {
				continue
			}

			if _, dup := seen[key]; dup {
				continue
			}

			seen[key] = struct{}{}

			if _, err := io.WriteString(w, "---\n"+doc+"\n"); err != nil {
				return n, fmt.Errorf("repodata: writing modules.yaml: %w", err)
			}

			n++
		}
	}

	return n, nil
}

// splitYAMLDocuments splits a multi-document stream at its "---" lines; the
// "..." terminators modulemd uses stay with their document.
func splitYAMLDocuments(text string) []string {
	var (
		docs []string
		cur  []string
	)

	flush := func() {
		if d := strings.TrimSpace(strings.Join(cur, "\n")); d != "" && d != "..." {
			docs = append(docs, d)
		}

		cur = cur[:0]
	}

	for line := range strings.SplitSeq(text, "\n") {
		if strings.TrimRight(line, " \t\r") == "---" {
			flush()
			continue
		}

		cur = append(cur, strings.TrimRight(line, "\r"))
	}

	flush()

	return docs
}

// moduleKey is the identity of a modulemd, modulemd-defaults or
// modulemd-obsoletes document.
func moduleKey(doc string) (string, bool) {
	var parsed struct {
		Document string         `yaml:"document"`
		Data     map[string]any `yaml:"data"`
	}

	if err := yaml.Unmarshal([]byte(doc), &parsed); err != nil || parsed.Document == "" {
		return "", false
	}

	var b strings.Builder

	b.WriteString(parsed.Document)

	switch parsed.Document {
	case "modulemd", "modulemd-packager":
		for _, f := range []string{"name", "stream", "version", "context", "arch"} {
			b.WriteString("|" + yamlScalar(parsed.Data[f]))
		}
	case "modulemd-defaults":
		b.WriteString("|" + yamlScalar(parsed.Data["module"]))
	default:
		for _, f := range []string{"module", "stream", "context", "modified", "message"} {
			b.WriteString("|" + yamlScalar(parsed.Data[f]))
		}
	}

	return b.String(), true
}

func yamlScalar(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	}

	return fmt.Sprint(v)
}

// DefaultMaxModulesDocument is the size [ModuleIndex.Add] allows a modules.yaml.
const DefaultMaxModulesDocument int64 = 1 << 30

// ModuleIndex records which module streams a repository offers, to filter
// modular packages the way dnf does when no module is enabled: the packages of
// a non-default stream of a module that has a default stream are blocked.
// The zero value is empty and ready to use; an empty index blocks nothing.
type ModuleIndex struct {
	defaultStream map[string]string   // module -> default stream
	streamRPMs    map[string][]string // "module:stream" -> NEVRA artifacts
	blocked       map[string]struct{}
}

// modulemdDoc is one document of a modules.yaml, either "modulemd" (a stream
// and its rpm artifacts) or "modulemd-defaults" (the default stream of a
// module). Both use the stream field: the stream of the document in the first
// kind, the default stream of Module in the second.
type modulemdDoc struct {
	Document string `yaml:"document"`
	Data     struct {
		Name      string `yaml:"name"`
		Stream    string `yaml:"stream"`
		Module    string `yaml:"module"`
		Artifacts struct {
			RPMs []string `yaml:"rpms"`
		} `yaml:"artifacts"`
	} `yaml:"data"`
}

// Add reads a modules.yaml (already decompressed, see [OpenMetadata]) into the
// index; maxSize bounds it (0 selects [DefaultMaxModulesDocument]) and a larger
// document fails with [ErrTooLarge]. Malformed documents are skipped; the
// first default stream of a module wins. Streams and defaults may come from
// different files: the blocked set covers everything added so far.
func (m *ModuleIndex) Add(r io.Reader, maxSize int64) error {
	if maxSize <= 0 {
		maxSize = DefaultMaxModulesDocument
	}

	if m.defaultStream == nil {
		m.defaultStream = make(map[string]string)
		m.streamRPMs = make(map[string][]string)
	}

	capped := limitio.Capped(r, maxSize+1, ErrTooLarge)
	dec := yaml.NewDecoder(capped)

	for {
		var doc modulemdDoc

		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}

		if err != nil {
			// A malformed document is skipped, as dnf does; the decoder
			// resumes at the next document, or fails again and ends below.
			var typeErr *yaml.TypeError
			if errors.As(err, &typeErr) {
				continue
			}

			// A document cut at the limit fails to parse, or the reader
			// fails; the limit is the error to report.
			if _, limitErr := capped.Read(nil); errors.Is(limitErr, ErrTooLarge) {
				return limitErr
			}

			break
		}

		m.addDoc(&doc)
	}

	m.rebuild()

	return nil
}

func (m *ModuleIndex) addDoc(doc *modulemdDoc) {
	switch doc.Document {
	case "modulemd":
		if doc.Data.Name == "" || doc.Data.Stream == "" {
			return
		}

		key := doc.Data.Name + ":" + doc.Data.Stream
		m.streamRPMs[key] = append(m.streamRPMs[key], doc.Data.Artifacts.RPMs...)
	case "modulemd-defaults":
		if doc.Data.Module == "" || doc.Data.Stream == "" {
			return
		}

		if _, ok := m.defaultStream[doc.Data.Module]; !ok {
			m.defaultStream[doc.Data.Module] = doc.Data.Stream
		}
	}
}

// rebuild recomputes the blocked set: the artifacts of every non-default
// stream of a module that has a default. A denylist, not an allowlist, because
// some releases ship the default stream's document with an empty artifact list
// while its packages are still in primary.xml.
func (m *ModuleIndex) rebuild() {
	m.blocked = make(map[string]struct{})

	for module, def := range m.defaultStream {
		prefix := module + ":"

		for key, rpms := range m.streamRPMs {
			if !strings.HasPrefix(key, prefix) || key == prefix+def {
				continue
			}

			for _, nvra := range rpms {
				m.blocked[nvra] = struct{}{}
			}
		}
	}
}

// DefaultStream returns the default stream of a module.
func (m *ModuleIndex) DefaultStream(module string) (string, bool) {
	s, ok := m.defaultStream[module]

	return s, ok
}

// Defaults returns the number of modules that have a default stream.
func (m *ModuleIndex) Defaults() int { return len(m.defaultStream) }

// Blocked reports whether the package belongs to a non-default stream, so a
// repository client must not offer it. nevra is the string [PackageNEVRA]
// builds. Non-modular packages are never blocked.
func (m *ModuleIndex) Blocked(release, nevra string) bool {
	if !IsModularPackage(release) {
		return false
	}

	_, ok := m.blocked[nevra]

	return ok
}

// IsModularPackage reports whether the release marks a module-stream build:
// modular packages carry ".module+" in it.
func IsModularPackage(release string) bool {
	return strings.Contains(release, ".module+")
}

// PackageNEVRA builds the key modules.yaml artifacts use,
// "name-epoch:version-release.arch", with an absent epoch as "0".
func PackageNEVRA(name, epoch, version, release, arch string) string {
	if epoch == "" {
		epoch = "0"
	}

	return name + "-" + epoch + ":" + version + "-" + release + "." + arch
}
