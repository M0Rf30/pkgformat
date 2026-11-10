package deb

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// SourceDateEpochVar is the environment variable of the reproducible-builds
// convention that carries the time packages are stamped with.
const SourceDateEpochVar = "SOURCE_DATE_EPOCH"

// SourceDateEpoch reads SOURCE_DATE_EPOCH, the number of seconds since the
// Unix epoch, as the time for Spec.ModTime. ok is false when the variable is
// unset or empty; a value that is not a non-negative integer fails with
// ErrInvalidSpec.
func SourceDateEpoch() (t time.Time, ok bool, err error) {
	v, set := os.LookupEnv(SourceDateEpochVar)
	if !set || v == "" {
		return time.Time{}, false, nil
	}

	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return time.Time{}, false, fmt.Errorf("%w: %s=%q is not a non-negative integer", ErrInvalidSpec, SourceDateEpochVar, v)
	}

	return time.Unix(n, 0).UTC(), true, nil
}
