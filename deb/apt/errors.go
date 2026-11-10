package apt

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/M0Rf30/pkgformat/deb"
)

var (
	// ErrTooLarge reports input over a size limit.
	ErrTooLarge = errors.New("apt: input too large")
	// ErrIntegrity reports a downloaded file whose size or digest differs from
	// what the verified Release or the package index declared.
	ErrIntegrity = errors.New("apt: integrity check failed")
	// ErrNoPackagesIndex reports a component and architecture that the Release
	// does not list. apt treats that as nothing to fetch.
	ErrNoPackagesIndex = errors.New("apt: no Packages index listed")
	// ErrNoSources reports an update without any source.
	ErrNoSources = errors.New("apt: no sources configured")
	// ErrNoListsDir reports an update without a lists directory.
	ErrNoListsDir = errors.New("apt: no lists directory given")
	// ErrPackageNotFound reports a package that is not in the index, or has no
	// downloadable file.
	ErrPackageNotFound = errors.New("apt: package not found in index")
	// ErrNoBaseURL reports an indexed package whose repository URL is unknown,
	// so it cannot be downloaded.
	ErrNoBaseURL = errors.New("apt: package has no repository URL")
	// ErrInvalidIndexEntry reports an index entry that cannot be downloaded
	// safely: a malformed SHA256, an out-of-range Size, or an unsafe Filename.
	ErrInvalidIndexEntry = errors.New("apt: invalid package index entry")
	// ErrDependencyDepth is returned by ResolveDeps for a dependency chain
	// deeper than maxResolveDepth, which only a hostile or corrupt index
	// produces.
	ErrDependencyDepth = errors.New("apt: dependency chain too deep")
	// ErrResolveLimit is returned by ResolveDeps when backtracking over
	// alternatives and versions exceeds its step budget, which only a hostile
	// or corrupt index produces.
	ErrResolveLimit = errors.New("apt: dependency resolution exceeded its step limit")
	// ErrUnsatisfiable is matched by an [UnsatisfiedError]: a dependency no
	// available package satisfies.
	ErrUnsatisfiable = errors.New("apt: unsatisfiable dependency")
	// ErrConflict is matched by a [ConflictError]: a package that conflicts
	// with, or breaks, an installed or selected one.
	ErrConflict = errors.New("apt: conflicting packages")
)

// UnsatisfiedError reports a dependency that no available package satisfies:
// no version of the name meets the constraint, or every candidate was refused
// (see Causes). It matches [ErrUnsatisfiable].
type UnsatisfiedError struct {
	// Package is the package whose dependency it is ("name:arch version"), or
	// "" for a name given to ResolveDeps.
	Package string
	// Dependency is the dependency as written ("foo (>= 2) | bar").
	Dependency string
	// Reason says why nothing satisfied it when no candidate was tried.
	Reason string
	// Causes are the errors of the candidates that were tried, in order.
	Causes []error
}

// maxShownCauses bounds how many candidate failures Error prints.
const maxShownCauses = 4

// Error describes the dependency and, when there are any, the reasons.
func (e *UnsatisfiedError) Error() string {
	var sb strings.Builder

	sb.WriteString("apt: cannot satisfy ")
	sb.WriteString(e.Dependency)

	if e.Package != "" {
		sb.WriteString(" of ")
		sb.WriteString(e.Package)
	}

	if e.Reason != "" {
		sb.WriteString(": ")
		sb.WriteString(e.Reason)
	}

	for i, cause := range e.Causes {
		if i == maxShownCauses {
			fmt.Fprintf(&sb, "\n\t... and %d more", len(e.Causes)-i)

			break
		}

		sb.WriteString("\n\t")
		sb.WriteString(strings.ReplaceAll(cause.Error(), "\n", "\n\t"))
	}

	return sb.String()
}

// Is matches ErrUnsatisfiable.
func (e *UnsatisfiedError) Is(target error) bool { return target == ErrUnsatisfiable }

// Unwrap exposes the candidate failures to errors.Is and errors.As.
func (e *UnsatisfiedError) Unwrap() []error { return e.Causes }

// ConflictError reports a package that cannot be installed because it
// conflicts with, or breaks, a package that is installed or already selected,
// or the other way round. It matches [ErrConflict].
type ConflictError struct {
	// Package is the package that was refused ("name:arch version").
	Package string
	// With is the package it clashes with.
	With string
	// WithInstalled is true when With is installed, false when it was selected
	// earlier in the same resolution.
	WithInstalled bool
	// Kind is "Conflicts" or "Breaks".
	Kind string
	// Relation is the relation as written in the declaring package.
	Relation string
	// Reverse is true when With declares the relation and Package is the
	// target; false when Package declares it.
	Reverse bool
}

// Error names both packages and the relation.
func (e *ConflictError) Error() string {
	state := "selected"
	if e.WithInstalled {
		state = "installed"
	}

	if e.Reverse {
		return fmt.Sprintf("apt: cannot install %s: %s package %s %s %s",
			e.Package, state, e.With, strings.ToLower(e.Kind), e.Relation)
	}

	return fmt.Sprintf("apt: cannot install %s: it %s %s, which is %s as %s",
		e.Package, strings.ToLower(e.Kind), e.Relation, state, e.With)
}

// Is matches ErrConflict.
func (e *ConflictError) Is(target error) bool { return target == ErrConflict }

// UpdateError is the error Update returns when sources fail: one error for
// each (source, architecture) or component that did not update. The indexes
// that did update are in place regardless.
type UpdateError struct {
	Errors []error
}

// Error lists the failures, one per line.
func (e *UpdateError) Error() string {
	msgs := make([]string, len(e.Errors))
	for i, err := range e.Errors {
		msgs[i] = err.Error()
	}

	return strings.Join(msgs, "\n")
}

// Unwrap exposes the failures to errors.Is and errors.As.
func (e *UpdateError) Unwrap() []error { return e.Errors }

// newUpdateError returns nil without failures, else an UpdateError holding
// them; nested UpdateErrors are flattened.
func newUpdateError(errs []error) error {
	var flat []error

	for _, err := range errs {
		if err == nil {
			continue
		}

		if ue, ok := err.(*UpdateError); ok { //nolint:errorlint // flattening our own type only
			flat = append(flat, ue.Errors...)
		} else {
			flat = append(flat, err)
		}
	}

	if len(flat) == 0 {
		return nil
	}

	return &UpdateError{Errors: flat}
}

// IsVerificationError reports whether err is solely a signature verification
// failure (unknown signer or no trust anchor) and not a network or I/O error.
// A caller that already fetched enough indexes can downgrade such an error to a
// warning.
//
// For the UpdateError that Update returns, "solely" means every failure in it
// is one: a network error next to a trust error is not downgraded.
func IsVerificationError(err error) bool {
	if err == nil {
		return false
	}

	var ue *UpdateError
	if errors.As(err, &ue) {
		return len(ue.Errors) > 0 && !slices.ContainsFunc(ue.Errors, func(e error) bool {
			return !IsVerificationError(e)
		})
	}

	return errors.Is(err, deb.ErrUnknownSigner) || errors.Is(err, deb.ErrNoTrustAnchor)
}
