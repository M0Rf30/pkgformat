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

const (
	// FormatV4 selects the classic RPM v4 package format. It is the default.
	FormatV4 = 4
	// FormatV6 selects the RPM v6 package format written by rpm >= 6.0.
	FormatV6 = 6
)

// v6SigReserved is the size of the reserved space in the signature header of an
// unsigned v6 package, as written by rpmbuild 6. Signatures shrink it so that the
// total signature header size stays the same, which lets rpmsign add signatures
// in place.
const v6SigReserved = 4128
