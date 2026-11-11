package source

import "errors"

// Errors reported by the package; test with errors.Is.
var (
	// ErrInvalid is returned for a document that is not valid deb822 of the
	// expected kind: a field is missing or malformed.
	ErrInvalid = errors.New("source: invalid document")
	// ErrUnsupportedFormat is returned for a source format this package cannot
	// unpack or build ("3.0 (git)", "3.0 (custom)", unknown formats).
	ErrUnsupportedFormat = errors.New("source: unsupported source format")
	// ErrChecksum is returned when a file does not match the size or the
	// checksum the .dsc lists for it.
	ErrChecksum = errors.New("source: checksum mismatch")
	// ErrMissingFile is returned when a file the .dsc lists is not available.
	ErrMissingFile = errors.New("source: file listed by the .dsc is missing")
	// ErrUnexpectedFile is returned for a file in the .dsc that does not
	// belong to the source format.
	ErrUnexpectedFile = errors.New("source: unexpected file for the source format")
	// ErrTooLarge is returned when a document or an unpacked tree exceeds a
	// limit.
	ErrTooLarge = errors.New("source: size limit exceeded")
	// ErrPatch is returned when a patch is malformed or does not apply
	// cleanly (fuzz 0).
	ErrPatch = errors.New("source: patch does not apply")
	// ErrUnsafe is returned for an archive entry or a patch that names a path
	// outside the target directory, or a special file.
	ErrUnsafe = errors.New("source: unsafe path or file type")
	// ErrNotSigned is returned by the Verify functions for a document that
	// carries no clear-signed wrapper.
	ErrNotSigned = errors.New("source: document is not signed")
	// ErrLocalChanges is returned by Build when the orig files of the tree
	// differ from the orig tarball plus the quilt series.
	ErrLocalChanges = errors.New("source: tree differs from the orig tarball plus the patches")
	// ErrDestExists is returned when the unpack or build target exists and the
	// options do not allow replacing it.
	ErrDestExists = errors.New("source: target already exists")
)
