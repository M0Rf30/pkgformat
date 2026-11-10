package apt

import (
	"errors"
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
)

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
