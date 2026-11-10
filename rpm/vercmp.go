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

import "strings"

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

// Vercmp compares two version strings the way rpm does (rpmvercmp in rpm
// 4.15 and later, including the tilde and caret operators). Returns -1 if
// first < second, 1 if first > second, and 0 if first == second.
//
// The versions are split into runs of digits and runs of letters; anything
// else only separates them. A run of digits is compared as a number, and
// always sorts after a run of letters. A tilde sorts before everything,
// even the end of the version ("1.0~rc1" < "1.0"). A caret sorts after the
// end of the version but before any other character ("1.0" < "1.0^git1" <
// "1.0.1" and "1.0^git1" < "1.0a"). Letters are ASCII only; like in C, a
// version ends at the first NUL byte.
//
// It runs in time linear in the length of the inputs, which may come from
// untrusted package headers.
func Vercmp(first, second string) int {
	first, second = cutNUL(first), cutNUL(second)
	if first == second {
		return 0
	}
	for first != "" || second != "" {
		// Ignore junk at beginning of version.
		first = skipJunk(first)
		second = skipJunk(second)

		// Handle the tilde separator, it sorts before everything else.
		if startsWith(first, '~') || startsWith(second, '~') {
			if !startsWith(first, '~') {
				return 1
			}
			if !startsWith(second, '~') {
				return -1
			}
			first, second = first[1:], second[1:]
			continue
		}

		// Handle the caret separator. Like the tilde, except that it
		// sorts after the end of the version: if one of the versions ends
		// (it is the base version), the other one is higher.
		if startsWith(first, '^') || startsWith(second, '^') {
			if first == "" {
				return -1
			}
			if second == "" {
				return 1
			}
			if !startsWith(first, '^') {
				return 1
			}
			if !startsWith(second, '^') {
				return -1
			}
			first, second = first[1:], second[1:]
			continue
		}

		// If we ran to the end of either, we are finished with the loop.
		if first == "" || second == "" {
			break
		}

		// Grab the first completely alpha or completely numeric segment.
		var seg1, seg2 string
		isnum := isDigit(first[0])
		if isnum {
			seg1, first = splitWhile(first, isDigit)
			seg2, second = splitWhile(second, isDigit)
		} else {
			seg1, first = splitWhile(first, isAlpha)
			seg2, second = splitWhile(second, isAlpha)
		}

		// The segments are of different types: one numeric, the other
		// alpha (so empty here). Numeric segments are always newer than
		// alpha segments.
		if seg2 == "" {
			if isnum {
				return 1
			}
			return -1
		}

		if isnum {
			// Throw away any leading zeros: whichever number has more
			// digits wins.
			seg1 = strings.TrimLeft(seg1, "0")
			seg2 = strings.TrimLeft(seg2, "0")
			if len(seg1) != len(seg2) {
				if len(seg1) < len(seg2) {
					return -1
				}
				return 1
			}
		}

		// Do not return if they are equal: there may be more segments.
		if seg1 < seg2 {
			return -1
		} else if seg1 > seg2 {
			return 1
		}
	}

	// All segments compared identically, but the separating characters may
	// differ: whichever version still has characters left over wins.
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

func isJunk(c byte) bool { return !isDigit(c) && !isAlpha(c) && c != '~' && c != '^' }

func startsWith(s string, c byte) bool { return s != "" && s[0] == c }

func cutNUL(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i]
	}
	return s
}

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
