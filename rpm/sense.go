package rpm

import (
	"strings"

	"github.com/M0Rf30/pkgformat/rpm/tag"
)

// Sense holds the sense flags (the RPMSENSE_* bits) of a dependency: a
// comparison (less, greater, equal, or a combination) and the roles the
// dependency plays, such as being needed by a scriptlet of the package. The
// bits are those of the tag package, so a Sense converts to and from the
// uint32 stored in the REQUIREFLAGS family of tags.
type Sense uint32

// The comparison and role bits, as typed values; they equal the tag.RPMSENSE_*
// constants.
const (
	SenseAny           Sense = tag.RPMSENSE_ANY
	SenseLess          Sense = tag.RPMSENSE_LESS
	SenseGreater       Sense = tag.RPMSENSE_GREATER
	SenseEqual         Sense = tag.RPMSENSE_EQUAL
	SensePosttrans     Sense = tag.RPMSENSE_POSTTRANS
	SensePrereq        Sense = tag.RPMSENSE_PREREQ
	SensePretrans      Sense = tag.RPMSENSE_PRETRANS
	SenseInterp        Sense = tag.RPMSENSE_INTERP
	SenseScriptPre     Sense = tag.RPMSENSE_SCRIPT_PRE
	SenseScriptPost    Sense = tag.RPMSENSE_SCRIPT_POST
	SenseScriptPreun   Sense = tag.RPMSENSE_SCRIPT_PREUN
	SenseScriptPostun  Sense = tag.RPMSENSE_SCRIPT_POSTUN
	SenseScriptVerify  Sense = tag.RPMSENSE_SCRIPT_VERIFY
	SenseMissingOK     Sense = tag.RPMSENSE_MISSINGOK
	SensePreuntrans    Sense = tag.RPMSENSE_PREUNTRANS
	SensePostuntrans   Sense = tag.RPMSENSE_POSTUNTRANS
	SenseRPMLib        Sense = tag.RPMSENSE_RPMLIB
	SenseKeyring       Sense = tag.RPMSENSE_KEYRING
	SenseConfig        Sense = tag.RPMSENSE_CONFIG
	SenseRich          Sense = tag.RPMSENSE_RICH
	SenseTriggerIn     Sense = tag.RPMSENSE_TRIGGERIN
	SenseTriggerUn     Sense = tag.RPMSENSE_TRIGGERUN
	SenseTriggerPostun Sense = tag.RPMSENSE_TRIGGERPOSTUN
	SenseTriggerPrein  Sense = tag.RPMSENSE_TRIGGERPREIN

	senseCompareMask = SenseLess | SenseGreater | SenseEqual
)

// Has reports whether every bit of mask is set.
func (s Sense) Has(mask Sense) bool { return s&mask == mask }

// Comparison returns the comparison bits only: any combination of
// [SenseLess], [SenseGreater] and [SenseEqual].
func (s Sense) Comparison() Sense { return s & senseCompareMask }

// Versioned reports whether the sense carries a version comparison.
func (s Sense) Versioned() bool { return s&senseCompareMask != 0 }

// String renders the comparison bits the way the flags attribute of repodata
// does: "LT", "GT", "EQ", "LE" or "GE", and "" for anything else (no
// comparison, or the contradictory less-and-greater).
func (s Sense) String() string {
	switch s & senseCompareMask {
	case SenseLess:
		return "LT"
	case SenseGreater:
		return "GT"
	case SenseEqual:
		return "EQ"
	case SenseLess | SenseEqual:
		return "LE"
	case SenseGreater | SenseEqual:
		return "GE"
	default:
		return ""
	}
}

// Operator renders the comparison bits as the operator of a spec file: "<",
// ">", "=", "<=" or ">=", and "" when there is no (valid) comparison.
func (s Sense) Operator() string {
	switch s & senseCompareMask {
	case SenseLess:
		return "<"
	case SenseGreater:
		return ">"
	case SenseEqual:
		return "="
	case SenseLess | SenseEqual:
		return "<="
	case SenseGreater | SenseEqual:
		return ">="
	default:
		return ""
	}
}

// Roles names the role bits that are set, the way rpm prints them in
// `rpm -q --requires` ("pre", "post", "preun", "postun", "pretrans",
// "posttrans", "preuntrans", "postuntrans", "verify", "interp", "prereq",
// "meta", "rpmlib", "keyring", "config", "missingok"), in a stable order.
func (s Sense) Roles() []string {
	var out []string

	for _, r := range []struct {
		bit  Sense
		name string
	}{
		{SensePrereq, "prereq"}, {SenseScriptPre, "pre"}, {SenseScriptPost, "post"},
		{SenseScriptPreun, "preun"}, {SenseScriptPostun, "postun"},
		{SensePretrans, "pretrans"}, {SensePosttrans, "posttrans"},
		{SensePreuntrans, "preuntrans"}, {SensePostuntrans, "postuntrans"},
		{SenseScriptVerify, "verify"}, {SenseInterp, "interp"},
		{SenseRPMLib, "rpmlib"}, {SenseKeyring, "keyring"},
		{SenseConfig, "config"}, {SenseMissingOK, "missingok"},
	} {
		if s&r.bit != 0 {
			out = append(out, r.name)
		}
	}

	return out
}

// IsPre reports whether the requirement is needed before the package is
// installed: it is a Requires(pre) or Requires(post) dependency, or a legacy
// PreReq. It is what the pre attribute of repodata means. Use [Sense.Has] with
// [SenseScriptPre] to test for Requires(pre) alone.
func (s Sense) IsPre() bool { return s&(SensePrereq|SenseScriptPre|SenseScriptPost) != 0 }

// IsPost reports a Requires(post) dependency.
func (s Sense) IsPost() bool { return s&SenseScriptPost != 0 }

// IsPreun reports a Requires(preun) dependency.
func (s Sense) IsPreun() bool { return s&SenseScriptPreun != 0 }

// IsPostun reports a Requires(postun) dependency.
func (s Sense) IsPostun() bool { return s&SenseScriptPostun != 0 }

// IsPretrans reports a Requires(pretrans) dependency.
func (s Sense) IsPretrans() bool { return s&SensePretrans != 0 }

// IsPosttrans reports a Requires(posttrans) dependency.
func (s Sense) IsPosttrans() bool { return s&SensePosttrans != 0 }

// IsUntrans reports a Requires(preuntrans) or Requires(postuntrans)
// dependency.
func (s Sense) IsUntrans() bool { return s&(SensePreuntrans|SensePostuntrans) != 0 }

// IsMissingOK reports a dependency that need not be satisfied
// (Requires(missingok)).
func (s Sense) IsMissingOK() bool { return s&SenseMissingOK != 0 }

// IsKeyring reports a requirement on a key of the rpm keyring.
func (s Sense) IsKeyring() bool { return s&SenseKeyring != 0 }

// IsConfig reports the implicit config(name) dependency that ties a
// configuration file to its package.
func (s Sense) IsConfig() bool { return s&SenseConfig != 0 }

// IsRich reports the rich marker rpm sets on the dependency while it parses
// it. The marker is not stored in packages: use [Dependency.IsRich], which
// recognises a rich dependency by its name.
func (s Sense) IsRich() bool { return s&SenseRich != 0 }

// IsRPMLib reports an rpmlib(...) feature requirement.
func (s Sense) IsRPMLib() bool { return s&SenseRPMLib != 0 }

// IsPrereq reports a legacy PreReq dependency.
func (s Sense) IsPrereq() bool { return s&SensePrereq != 0 }

// IsInterp reports the dependency on the interpreter of a scriptlet.
func (s Sense) IsInterp() bool { return s&SenseInterp != 0 }

// IsScriptVerify reports a Requires(verify) dependency.
func (s Sense) IsScriptVerify() bool { return s&SenseScriptVerify != 0 }

// SenseFlagsString renders the comparison bits of flags as the flags attribute
// of repodata: "LT", "GT", "EQ", "LE" or "GE". An unversioned dependency
// yields "". It is [Sense.String].
func SenseFlagsString[T ~uint32](flags T) string { return Sense(flags).String() }

// IsRichName reports whether a dependency name is a rich (boolean) dependency:
// rich dependencies are written in parentheses, "(a if b)".
func IsRichName(name string) bool { return strings.HasPrefix(name, "(") }
