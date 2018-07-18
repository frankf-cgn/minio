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
	"errors"
	"fmt"
	"net/http"
	"sync"
)

// ValidatorID - holds identification name authentication validator target.
type ValidatorID string

// Validator interface describes basic implementation
// requirements of various authentication providers.
type Validator interface {
	// Validate is a custom validator function for this provider,
	// each validation is authenticationType or provider specific.
	Validate(r *http.Request) (map[string]interface{}, error)

	// ID returns provider name of this provider.
	ID() ValidatorID
}

// ErrTokenExpired - error token expired
var (
	ErrTokenExpired    = errors.New("token expired")
	ErrInvalidDuration = errors.New("duration higher than token expiry")
)

// Validators - holds list of providers indexed by provider id.
type Validators struct {
	sync.RWMutex
	providers map[ValidatorID]Validator
}

// Add - adds unique provider to provider list.
func (list *Validators) Add(provider Validator) error {
	list.Lock()
	defer list.Unlock()

	if _, ok := list.providers[provider.ID()]; ok {
		return fmt.Errorf("provider %v already exists", provider.ID())
	}

	list.providers[provider.ID()] = provider
	return nil
}

// List - returns available provider IDs.
func (list *Validators) List() []ValidatorID {
	list.RLock()
	defer list.RUnlock()

	keys := []ValidatorID{}
	for k := range list.providers {
		keys = append(keys, k)
	}

	return keys
}

// Get - returns the provider for the given providerID, if not found
// returns an error.
func (list *Validators) Get(id ValidatorID) (p Validator, err error) {
	list.RLock()
	defer list.RUnlock()
	var ok bool
	if p, ok = list.providers[id]; !ok {
		return nil, fmt.Errorf("provider %v doesn't exist", id)
	}
	return p, nil
}

// NewValidators - creates Validators.
func NewValidators() *Validators {
	return &Validators{providers: make(map[ValidatorID]Validator)}
}
