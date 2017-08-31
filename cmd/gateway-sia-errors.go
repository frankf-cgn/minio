/*
 * (C) 2017 David Gore <dvstate@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import "fmt"

// SiaServiceError is a custom error type used by Sia cache layer
type SiaServiceError struct {
	Code    string
	Message string
}

func (e SiaServiceError) Error() string {
	return fmt.Sprintf("Sia Error: %s", e.Message)
}
