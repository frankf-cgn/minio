/*
 * Minio Cloud Storage, (C) 2018 Minio, Inc.
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

package auth

import (
	"net/http"
	"testing"
)

type errorValidator struct{}

func (e errorValidator) Validate(r *http.Request) (map[string]interface{}, error) {
	return nil, ErrTokenExpired
}

func (e errorValidator) ID() ValidatorID {
	return "err"
}

func TestValidators(t *testing.T) {
	vrs := NewValidators()
	if err := vrs.Add(&errorValidator{}); err != nil {
		t.Fatal(err)
	}

	if err := vrs.Add(&errorValidator{}); err == nil {
		t.Fatal("Unexpected should return error for double inserts")
	}

	if _, err := vrs.Get("unknown"); err == nil {
		t.Fatal("Unexpected should return error for unknown validators")
	}

	v, err := vrs.Get("err")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = v.Validate(&http.Request{}); err != ErrTokenExpired {
		t.Fatalf("Expected error %s, got %s", ErrTokenExpired, err)
	}

	vids := vrs.List()
	if len(vids) == 0 || len(vids) > 1 {
		t.Fatalf("Unexpected number of vids %v", vids)
	}

	if vids[0] != "err" {
		t.Fatalf("Unexpected vid %v", vids[0])
	}
}
