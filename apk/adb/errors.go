package adb

import (
	"errors"
	"fmt"
)

// Sentinel errors. Functions wrap them with context: match with [errors.Is].
var (
	// ErrInvalid wraps every structural problem found while reading an
	// APKv3 file: a bad header, a malformed block, a value that points
	// outside the ADB block, or a package or index that does not follow its
	// schema. The more specific errors below also match it.
	ErrInvalid = errors.New("adb: invalid apk v3 file")

	// ErrCompression is returned for a compression header that is not valid
	// or names an algorithm or level that is not supported.
	ErrCompression = fmt.Errorf("%w: unsupported compression", ErrInvalid)
	// ErrSchema is returned for a file whose schema magic is not the one
	// asked for, and for a value whose type does not fit the schema.
	ErrSchema = fmt.Errorf("%w: schema mismatch", ErrInvalid)
	// ErrBlock is returned for a block that is malformed or out of order.
	ErrBlock = fmt.Errorf("%w: bad block", ErrInvalid)
	// ErrTooComplex is returned when decoding would exceed a limit on the
	// work or the memory an ADB block may cause.
	ErrTooComplex = fmt.Errorf("%w: exceeds a decoding limit", ErrInvalid)
	// ErrDigest is returned when the content of a file does not match the
	// digest recorded for it in the ADB block.
	ErrDigest = fmt.Errorf("%w: file digest mismatch", ErrInvalid)
	// ErrUnsafePath is returned for an entry name that is empty, absolute or
	// holds a "." or ".." element, or a control character.
	ErrUnsafePath = fmt.Errorf("%w: unsafe path", ErrInvalid)

	// ErrNoKeyring is returned when a signature is to be checked and no key
	// is trusted.
	ErrNoKeyring = errors.New("adb: no trusted keys")
	// ErrUnsigned is returned when a file has no signature block.
	ErrUnsigned = errors.New("adb: not signed")
	// ErrUntrusted is returned when no signature of the file is by a trusted
	// key.
	ErrUntrusted = errors.New("adb: no signature by a trusted key")
	// ErrBadSignature is returned when a trusted key is named by a signature
	// that does not verify.
	ErrBadSignature = errors.New("adb: signature does not verify")

	// ErrInvalidSpec is returned for a package or index description that
	// cannot be written.
	ErrInvalidSpec = errors.New("adb: invalid spec")
	// ErrInvalidKey is returned for a key that is unusable: an unsupported
	// type or curve, or an RSA modulus out of bounds.
	ErrInvalidKey = errors.New("adb: invalid key")
	// ErrTooLarge is returned when a value does not fit the format: an ADB
	// block over 256 MiB, or a signature over 2 KiB.
	ErrTooLarge = errors.New("adb: value too large for the format")
	// ErrUnsafeEntry is returned by Extract for an entry that would be
	// written outside the target directory.
	ErrUnsafeEntry = errors.New("adb: unsafe entry")
	// ErrDataTooLarge is returned by Extract when a limit on the bytes or
	// the entries is reached.
	ErrDataTooLarge = errors.New("adb: package exceeds an extraction limit")
)

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

func schemaErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrSchema, fmt.Sprintf(format, args...))
}

func blockErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrBlock, fmt.Sprintf(format, args...))
}

func specErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidSpec, fmt.Sprintf(format, args...))
}
