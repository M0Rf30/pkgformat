package pacman

import (
	"fmt"
	"strings"
)

// ErrInvalidSigLevel reports a SigLevel value that names an unknown option. It
// wraps ErrInvalidConfig.
var ErrInvalidSigLevel = fmt.Errorf("%w: invalid SigLevel", ErrInvalidConfig)

// SigCheck says when signatures are checked: the "Never", "Optional" and
// "Required" options of a SigLevel.
type SigCheck uint8

// The values of SigCheck.
const (
	// SigCheckUnset means no level was given; the zero value.
	SigCheckUnset SigCheck = iota
	// SigNever suppresses signature checking, even for a signature present.
	SigNever
	// SigOptional checks a signature that is present and accepts its absence.
	SigOptional
	// SigRequired fails on a missing or invalid signature.
	SigRequired
)

// SigTrust says which signing keys are acceptable: the "TrustedOnly" and
// "TrustAll" options of a SigLevel.
type SigTrust uint8

// The values of SigTrust.
const (
	// SigTrustedOnly accepts fully trusted keys only; the default.
	SigTrustedOnly SigTrust = iota
	// SigTrustAll accepts keys of marginal or unknown trust.
	SigTrustAll
)

// SigPolicy is the signature policy of one kind of object, a package or a
// database.
//
// Trust is carried for fidelity with pacman.conf: a gpg.Keyring holds public
// keys without trust levels, so every key in it counts as fully trusted and
// SigTrustedOnly and SigTrustAll verify alike.
type SigPolicy struct {
	Check SigCheck
	Trust SigTrust
}

// VerifyMode maps the policy onto the client's VerifyMode. An unset policy
// maps to VerifyNone; the Client falls back to its own default before asking.
func (p SigPolicy) VerifyMode() VerifyMode {
	switch p.Check {
	case SigRequired:
		return VerifyRequired
	case SigOptional:
		return VerifyIfPresent
	default:
		return VerifyNone
	}
}

// String returns the pacman-conf rendering: "Never", "Optional" or "Required"
// followed, unless Never, by "TrustedOnly" or "TrustAll" ("" when unset).
func (p SigPolicy) String() string {
	return strings.Join(p.words(""), " ")
}

func (p SigPolicy) words(prefix string) []string {
	var check string

	switch p.Check {
	case SigNever:
		return []string{prefix + "Never"}
	case SigOptional:
		check = "Optional"
	case SigRequired:
		check = "Required"
	default:
		return nil
	}

	trust := "TrustedOnly"
	if p.Trust == SigTrustAll {
		trust = "TrustAll"
	}

	return []string{prefix + check, prefix + trust}
}

// SigLevel is a signature verification level as libalpm models it: one
// policy for packages and one for databases. The zero value is "not
// specified", for which a Client falls back to its ClientOptions.
type SigLevel struct {
	Package  SigPolicy
	Database SigPolicy
}

// DefaultSigLevel is libalpm's built-in level, "Required TrustedOnly" for
// packages and databases.
func DefaultSigLevel() SigLevel {
	p := SigPolicy{Check: SigRequired, Trust: SigTrustedOnly}

	return SigLevel{Package: p, Database: p}
}

// IsZero reports a level nothing was specified for.
func (l SigLevel) IsZero() bool {
	return l == SigLevel{}
}

// ParseSigLevel parses the value of a SigLevel option on top of
// DefaultSigLevel, like pacman does for the global option.
func ParseSigLevel(s string) (SigLevel, error) {
	return DefaultSigLevel().Apply(s)
}

// Apply returns l modified by the options of a SigLevel value, processed left
// to right with later options overriding earlier ones, as pacman does. The
// options are "Never", "Optional", "Required", "TrustedOnly" and "TrustAll",
// each of which may carry a "Package" or "Database" prefix to affect that
// object only. Separate options with spaces; the names are case-sensitive.
func (l SigLevel) Apply(s string) (SigLevel, error) {
	for _, tok := range splitSpaces(s) {
		var err error

		if l, err = l.applyToken(tok); err != nil {
			return SigLevel{}, err
		}
	}

	return l, nil
}

func (l SigLevel) applyToken(tok string) (SigLevel, error) {
	pkg, db := true, true
	name := tok

	switch {
	case strings.HasPrefix(tok, "Package"):
		name, db = strings.TrimPrefix(tok, "Package"), false
	case strings.HasPrefix(tok, "Database"):
		name, pkg = strings.TrimPrefix(tok, "Database"), false
	}

	var edit func(*SigPolicy)

	switch name {
	case "Never":
		edit = func(p *SigPolicy) { p.Check = SigNever }
	case "Optional":
		edit = func(p *SigPolicy) { p.Check = SigOptional }
	case "Required":
		edit = func(p *SigPolicy) { p.Check = SigRequired }
	case "TrustedOnly":
		edit = func(p *SigPolicy) { p.Trust = SigTrustedOnly }
	case "TrustAll":
		edit = func(p *SigPolicy) { p.Trust = SigTrustAll }
	default:
		return l, fmt.Errorf("%w: %q", ErrInvalidSigLevel, tok)
	}

	if pkg {
		edit(&l.Package)
	}

	if db {
		edit(&l.Database)
	}

	return l, nil
}

// Tokens returns the level as pacman-conf prints it, one option per element:
// "PackageRequired", "PackageTrustedOnly", "DatabaseOptional" and so on. A
// policy that is Never has no trust option; an unset one has no option at all.
func (l SigLevel) Tokens() []string {
	return append(l.Package.words("Package"), l.Database.words("Database")...)
}

// String returns Tokens joined by spaces, a value ParseSigLevel reads back.
func (l SigLevel) String() string {
	return strings.Join(l.Tokens(), " ")
}

// splitSpaces splits a configuration value at spaces, as pacman splits its
// list options; empty fields are dropped.
func splitSpaces(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ' ' })
}
