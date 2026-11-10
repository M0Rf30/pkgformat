/*
 * Copyright (c) SAS Institute, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package rpm

import (
	"errors"
	"fmt"
)

// Errors returned for malformed or oversized packages. Match them with
// errors.Is: the returned errors wrap them with details.
var (
	// ErrNotRPM means the input does not start with the lead of an RPM.
	ErrNotRPM = errors.New("rpm: not an rpm package")
	// ErrUnsupportedVersion means the lead announces a major version older than 3.
	ErrUnsupportedVersion = errors.New("rpm: unsupported package version")
	// ErrInvalidHeader means a header is malformed: bad magic, an entry that
	// points outside the data, a truncated string, a missing identity tag.
	ErrInvalidHeader = errors.New("rpm: invalid header")
	// ErrHeaderTooLarge means a header, or one of its arrays, exceeds the
	// limits set for the read.
	ErrHeaderTooLarge = errors.New("rpm: header too large")
)

// NoSuchTagError is returned when a tag does not exist in the header
type NoSuchTagError struct {
	Tag int
}

func (err NoSuchTagError) Error() string {
	return fmt.Sprintf("No such entry %d", err.Tag)
}

// NewNoSuchTagError creates a NoSuchTagError for a given tag
func NewNoSuchTagError(id int) NoSuchTagError {
	return NoSuchTagError{Tag: id}
}
