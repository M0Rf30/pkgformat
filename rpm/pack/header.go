// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pack

import "github.com/M0Rf30/pkgformat/rpm/internal/header"

// ErrHeaderTooLarge is returned when a header does not fit the 31 bit offsets and
// counts of the rpm header format.
var ErrHeaderTooLarge = header.ErrHeaderTooLarge

// IndexEntry represents an RPM header index entry containing type, count, and data.
// Create it with the Entry* functions.
type IndexEntry = header.Entry

// EntryInt16 creates an IndexEntry from a slice of int16 values.
func EntryInt16(value []int16) IndexEntry {
	return header.Integers(value)
}

// EntryUint16 creates an IndexEntry from a slice of uint16 values.
func EntryUint16(value []uint16) IndexEntry {
	return header.Integers(value)
}

// EntryInt32 creates an IndexEntry from a slice of int32 values.
func EntryInt32(value []int32) IndexEntry {
	return header.Integers(value)
}

// EntryUint32 creates an IndexEntry from a slice of uint32 values.
func EntryUint32(value []uint32) IndexEntry {
	return header.Integers(value)
}

// EntryInt64 creates an IndexEntry from a slice of int64 values (RPM INT64 type, used by RPM v6).
func EntryInt64(value []int64) IndexEntry {
	return header.Integers(value)
}

// EntryUint64 creates an IndexEntry from a slice of uint64 values (RPM INT64 type, used by RPM v6).
func EntryUint64(value []uint64) IndexEntry {
	return header.Integers(value)
}

// EntryString creates an IndexEntry from a string value.
func EntryString(value string) IndexEntry {
	return header.String(value)
}

// EntryBytes creates an IndexEntry from a byte slice.
func EntryBytes(value []byte) IndexEntry {
	return header.Bytes(value)
}

// EntryStringSlice creates an IndexEntry from a slice of strings.
func EntryStringSlice(value []string) IndexEntry {
	return header.Strings(value)
}
