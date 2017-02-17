// +build windows

/*
 * Minio Cloud Storage, (C) 2017 Minio, Inc.
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

package cmd

import (
	"os"
	"strings"

	os2 "github.com/minio/minio/pkg/x/os"
)

// Wrapper around safe stat implementation to avoid windows bugs.
func osStat(name string) (os.FileInfo, error) {
	return os2.Stat(name)
}

// isValidVolname verifies a volname name in accordance with object
// layer requirements.
func isValidVolname(volname string) bool {
	if len(volname) < 3 || len(volname) > 63 {
		return false
	}
	// Volname shouldn't have reserved characters on windows in it.
	return !strings.ContainsAny(volname, `\:*?\"<>|`)
}

// mkdirAll creates a directory named path,
// along with any necessary parents, and returns nil,
// or else returns an error. The permission bits perm are used
// for all directories that mkdirAll creates. If path is already
// a directory, mkdirAll does nothing and returns nil.
func mkdirAll(path string, perm os.FileMode) error {
	return os.MkdirAll(path, perm)
}

// removeAll removes path and any children it contains.
// It removes everything it can but returns the first error
// it encounters.  If the path does not exist, RemoveAll
// returns nil (no error).
func removeAll(path string) error {
	return os.RemoveAll(path)
}
