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
	"regexp"
	"strings"
)

var (
	R_NONALNUMTILDE = regexp.MustCompile(`^([^a-zA-Z0-9~]*)(.*)$`)
	R_NUM           = regexp.MustCompile(`^([\d]+)(.*)$`)
	R_ALPHA         = regexp.MustCompile(`^([a-zA-Z]+)(.*)$`)
)

// VersionSlice provides the Sort interface for sorting version strings.
type VersionSlice []string

// Len is the number of elements in the collection.
func (vs VersionSlice) Len() int {
	return len(vs)
}

// Less reports wheather the element with index i should sort before the
// element with index j.
func (vs VersionSlice) Less(i, j int) bool {
	return Vercmp(vs[i], vs[j]) == -1
}

// Swap swaps the elements with indexes i and j.
func (vs VersionSlice) Swap(i, j int) {
	s1 := vs[i]
	vs[i] = vs[j]
	vs[j] = s1
}

// Vercmp compares two version strings using the same algorithm as rpm uses.
// Returns -1 if first < second, 1 if first > second, and 0 if first == second.
//
// It runs in time linear in the length of the inputs, which may come from
// untrusted package headers.
func Vercmp(first, second string) int {
	// The historical regexp based implementation could not match a string
	// that has a newline after its first alphanumeric character, and then
	// reported the versions as equal. Keep that behaviour.
	if hasNewlineAfterToken(first) || hasNewlineAfterToken(second) {
		return 0
	}
	for first != "" || second != "" {
		// Ignore junk at beginning of version.
		first = skipJunk(first)
		second = skipJunk(second)

		// Handle the tilde separator, it sorts before everything else.
		if strings.HasPrefix(first, "~") {
			if !strings.HasPrefix(second, "~") {
				return -1
			}
			first, second = first[1:], second[1:]
			continue
		}
		if strings.HasPrefix(second, "~") {
			return 1
		}

		// If we ran to the end of either, we are finished with the loop.
		if first == "" || second == "" {
			break
		}

		// Grab the first completely alpha or completely numeric segment.
		var seg1, seg2 string
		isnum := isDigit(first[0])
		if isnum {
			if !isDigit(second[0]) {
				// numeric segments are always newer than alpha segments.
				return 1
			}
			seg1, first = splitWhile(first, isDigit)
			seg2, second = splitWhile(second, isDigit)
			// Throw away any leading zeros.
			seg1 = strings.TrimLeft(seg1, "0")
			seg2 = strings.TrimLeft(seg2, "0")
			// Whichever number has more digits wins
			if len(seg1) != len(seg2) {
				if len(seg1) < len(seg2) {
					return -1
				}
				return 1
			}
		} else {
			if !isAlpha(second[0]) {
				// alpha segment against a numeric one
				return -1
			}
			seg1, first = splitWhile(first, isAlpha)
			seg2, second = splitWhile(second, isAlpha)
		}

		if seg1 < seg2 {
			return -1
		} else if seg1 > seg2 {
			return 1
		}
	}

	if first == "" && second == "" {
		return 0
	}
	if first != "" {
		return 1
	}
	return -1
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlpha(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }

func isJunk(c byte) bool { return !isDigit(c) && !isAlpha(c) && c != '~' }

func skipJunk(s string) string {
	i := 0
	for i < len(s) && isJunk(s[i]) {
		i++
	}
	return s[i:]
}

func splitWhile(s string, pred func(byte) bool) (head, rest string) {
	i := 0
	for i < len(s) && pred(s[i]) {
		i++
	}
	return s[:i], s[i:]
}

func hasNewlineAfterToken(s string) bool {
	return strings.Contains(skipJunk(s), "\n")
}
