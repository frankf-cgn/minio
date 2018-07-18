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

package policy

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"net/http"

	xnet "github.com/minio/minio/pkg/net"
)

// OpaArgs opa general purpose policy engine configuration.
type OpaArgs struct {
	URL       *xnet.URL `json:"url"`
	AuthToken string    `json:"authToken"`
}

// Validate - validate opa configuration params.
func (a *OpaArgs) Validate() error {
	return nil
}

// Opa - implements opa policy agent calls.
type Opa struct {
	args   OpaArgs
	client *http.Client
}

// NewOpa - initializes opa policy engine connector.
func NewOpa(args OpaArgs) *Opa {
	// No opa args.
	if args.URL == nil && args.AuthToken == "" {
		return nil
	}
	t := http.DefaultTransport.(*http.Transport)
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &Opa{
		args:   args,
		client: &http.Client{Transport: t},
	}
}

// IsAllowed - checks given policy args is allowed to continue the REST API.
func (o *Opa) IsAllowed(args Args) bool {
	// OPA input
	body := make(map[string]interface{})
	body["input"] = args

	inputBytes, err := json.Marshal(body)
	if err != nil {
		return false
	}

	req, err := http.NewRequest("POST", o.args.URL.String(), bytes.NewReader(inputBytes))
	if err != nil {
		return false
	}

	req.Header.Set("Content-Type", "application/json")
	if o.args.AuthToken != "" {
		req.Header.Set("Authorization", o.args.AuthToken)
	}

	resp, err := o.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Handle OPA response
	type opaResponse struct {
		Result struct {
			Allow bool `json:"allow"`
		} `json:"result"`
	}
	var result opaResponse
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false
	}

	return result.Result.Allow
}
