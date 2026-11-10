/*
 * Copyright (c) SAS Institute Inc.
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

package fileutil

/* Stubs for file operations that aren't meaningful on windows */

import (
	"errors"
	"os"
)

func HasLinks(info os.FileInfo) bool {
	return false
}

func Mkfifo(path string, mode uint32) error {
	return nil
}

func Mknod(path string, mode uint32, dev uint64) error {
	return errors.ErrUnsupported
}

func Mkdev(major, minor uint32) uint64 {
	return uint64(major)<<8 | uint64(minor)
}
