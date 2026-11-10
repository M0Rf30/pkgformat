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

package header

import "fmt"

// LeadSize is the size of the lead, the fixed block at the start of every rpm.
const LeadSize = 96

// Lead returns the 96 byte lead of a v4 package for the given name and
// version-release.
func Lead(name, fullVersion string) []byte {
	// RPM format = 0xedabeedb
	// version 3.0 = 0x0300
	// type binary = 0x0000
	// machine archnum (i386?) = 0x0001
	// name ( 66 bytes, with null termination)
	// osnum (linux?) = 0x0001
	// sig type (header-style) = 0x0005
	// reserved 16 bytes of 0x00
	n := []byte(fmt.Sprintf("%s-%s", name, fullVersion))
	if len(n) > 65 {
		n = n[:65]
	}
	n = append(n, make([]byte, 66-len(n))...)
	b := []byte{0xed, 0xab, 0xee, 0xdb, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01}
	b = append(b, n...)
	b = append(b, []byte{0x00, 0x01, 0x00, 0x05}...)
	b = append(b, make([]byte, 16)...)
	return b
}

// LeadV6 returns the lead of a v6 package: major 4, archnum 0, osnum 0, which
// is what rpm 6 writes.
func LeadV6(name, fullVersion string) []byte {
	b := Lead(name, fullVersion)
	b[4] = 0x04
	b[8], b[9] = 0, 0
	b[76], b[77] = 0, 0
	return b
}
