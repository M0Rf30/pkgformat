package pacman

import (
	"fmt"
	"strings"
)

// MaxInstallBytes bounds the .INSTALL scriptlet of a package.
const MaxInstallBytes = 4 << 20

// Scriptlets are the bodies of the six hooks pacman runs from a package's
// .INSTALL file. Each field holds the shell commands of one hook, without the
// "name() { ... }" wrapper; an empty field means the hook is not defined.
type Scriptlets struct {
	PreInstall  string
	PostInstall string
	PreUpgrade  string
	PostUpgrade string
	PreRemove   string
	PostRemove  string

	// UpgradeFallback makes an undefined PreUpgrade run the PreInstall body and
	// an undefined PostUpgrade run the PostInstall body, so a package that only
	// declares install hooks sees them on upgrades too.
	UpgradeFallback bool

	// Preamble is shell text placed before the hooks, typically the helper
	// functions the hooks call. It is written verbatim.
	Preamble string
}

// Empty reports whether no hook is defined (the package has no .INSTALL).
func (s *Scriptlets) Empty() bool {
	return s == nil || (s.PreInstall == "" && s.PostInstall == "" && s.PreUpgrade == "" &&
		s.PostUpgrade == "" && s.PreRemove == "" && s.PostRemove == "")
}

// Hooks renders the six function definitions, without the Preamble. It is what
// a caller scans to decide which helper functions the Preamble must carry.
func (s *Scriptlets) Hooks() string {
	preUpgrade, postUpgrade := s.PreUpgrade, s.PostUpgrade

	if s.UpgradeFallback {
		if preUpgrade == "" {
			preUpgrade = s.PreInstall
		}

		if postUpgrade == "" {
			postUpgrade = s.PostInstall
		}
	}

	var b strings.Builder

	for _, h := range []struct{ name, body string }{
		{"pre_install", s.PreInstall},
		{"post_install", s.PostInstall},
		{"pre_upgrade", preUpgrade},
		{"post_upgrade", postUpgrade},
		{"pre_remove", s.PreRemove},
		{"post_remove", s.PostRemove},
	} {
		if h.body != "" {
			fmt.Fprintf(&b, "\n%s() {\n%s\n}", h.name, h.body)
		}
	}

	b.WriteString("\n")

	return b.String()
}

// Render returns the content of the .INSTALL file: the Preamble followed by the
// hook functions. It is nil when no hook is defined.
func (s *Scriptlets) Render() []byte {
	if s.Empty() {
		return nil
	}

	return []byte(s.Preamble + s.Hooks())
}
