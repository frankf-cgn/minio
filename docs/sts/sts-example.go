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

package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"

	minio "github.com/minio/minio-go"
	"github.com/minio/minio-go/pkg/credentials"
	"github.com/minio/minio/pkg/auth"
)

// AssumedRoleUser - The identifiers for the temporary security credentials that
// the operation returns. Please also see https://docs.aws.amazon.com/goto/WebAPI/sts-2011-06-15/AssumedRoleUser
type AssumedRoleUser struct {
	Arn           string
	AssumedRoleID string `xml:"AssumeRoleId"`
	// contains filtered or unexported fields
}

// AssumeRoleWithClientGrantsResponse contains the result of successful AssumeRoleWithClientGrants request.
type AssumeRoleWithClientGrantsResponse struct {
	XMLName          xml.Name           `xml:"https://sts.amazonaws.com/doc/2011-06-15/ AssumeRoleWithClientGrantsResponse" json:"-"`
	Result           ClientGrantsResult `xml:"AssumeRoleWithClientGrantsResult"`
	ResponseMetadata struct {
		RequestID string `xml:"RequestId,omitempty"`
	} `xml:"ResponseMetadata,omitempty"`
}

// ClientGrantsResult - Contains the response to a successful AssumeRoleWithClientGrants
// request, including temporary credentials that can be used to make Minio API requests.
type ClientGrantsResult struct {
	AssumedRoleUser              AssumedRoleUser  `xml:",omitempty"`
	Audience                     string           `xml:",omitempty"`
	Credentials                  auth.Credentials `xml:",omitempty"`
	PackedPolicySize             int              `xml:",omitempty"`
	Provider                     string           `xml:",omitempty"`
	SubjectFromClientGrantsToken string           `xml:",omitempty"`
}

var endpoint string
var token string

func init() {
	flag.StringVar(&endpoint, "ep", "http://localhost:9000", "STS endpoint")
	flag.StringVar(&token, "t", "", "JWT access token from your identity provider")
}

func main() {
	flag.Parse()
	if token == "" {
		flag.PrintDefaults()
		return
	}

	v := url.Values{}
	v.Set("Action", "AssumeRoleWithClientGrants")
	v.Set("Token", token)

	u, err := url.Parse(endpoint)
	if err != nil {
		log.Fatal(err)
	}
	u.RawQuery = v.Encode()

	req, err := http.NewRequest("POST", u.String(), nil)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	a := AssumeRoleWithClientGrantsResponse{}
	if err = xml.NewDecoder(resp.Body).Decode(&a); err != nil {
		log.Fatal(err)
	}

	opts := &minio.Options{
		Creds: credentials.NewStaticV4(a.Result.Credentials.AccessKey,
			a.Result.Credentials.SecretKey,
			a.Result.Credentials.SessionToken,
		),
		BucketLookup: minio.BucketLookupAuto,
	}

	clnt, err := minio.NewWithOptions(u.Host, opts)
	if err != nil {
		log.Fatal(err)
	}

	clnt.MakeBucket("client-grants", "")

	fmt.Println("##### Credentials")
	c, err := json.MarshalIndent(a.Result.Credentials, "", "\t")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(c))
}
