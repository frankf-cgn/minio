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

package validator

import (
	"crypto"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/minio/minio/pkg/auth"
	xnet "github.com/minio/minio/pkg/net"
)

// JWTArgs - RSA authentication target arguments
type JWTArgs struct {
	WebKeyURL *xnet.URL `json:"jwksURL"`
	publicKey crypto.PublicKey
}

// Validate JWT authentication target arguments
func (r *JWTArgs) Validate() error {
	return nil
}

// UnmarshalJSON - decodes JSON data.
func (r *JWTArgs) UnmarshalJSON(data []byte) error {
	// subtype to avoid recursive call to UnmarshalJSON()
	type subJWTArgs JWTArgs
	var sr subJWTArgs

	if err := json.Unmarshal(data, &sr); err != nil {
		return err
	}

	ar := JWTArgs(sr)
	if ar.WebKeyURL == nil {
		*r = ar
		return nil
	}
	if err := ar.Validate(); err != nil {
		return err
	}

	t := http.DefaultTransport.(*http.Transport)
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	client := &http.Client{Transport: t}
	resp, err := client.Get(ar.WebKeyURL.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}
	var jwk JWKS
	if err = json.NewDecoder(resp.Body).Decode(&jwk); err != nil {
		return err
	}
	ar.publicKey, err = jwk.Keys[0].DecodePublicKey()
	if err != nil {
		return err
	}
	*r = ar
	return nil
}

// JWT - rs client grants provider details.
type JWT struct {
	args JWTArgs
}

func expToInt64(expI interface{}) (expAt int64, err error) {
	switch exp := expI.(type) {
	case float64:
		expAt = int64(exp)
	case int64:
		expAt = exp
	case json.Number:
		expAt, err = exp.Int64()
		if err != nil {
			return 0, err
		}
	default:
		return 0, errors.New("invalid expiry value")
	}
	return expAt, nil
}

func getDefaultExpiration(r *http.Request) (time.Duration, error) {
	defaultExpiryDuration := time.Duration(60) * time.Minute // Defaults to 1hr.
	if r.URL.Query().Get("DurationSeconds") != "" {
		expirySecs, err := strconv.ParseInt(r.URL.Query().Get("DurationSeconds"), 10, 64)
		if err != nil {
			return 0, err
		}
		// The duration, in seconds, of the role session.
		// The value can range from 900 seconds (15 minutes)
		// to 12 hours.
		if expirySecs < 900 || expirySecs > 43200 {
			return 0, errors.New("out of range value for duration in seconds")
		}

		defaultExpiryDuration = time.Duration(expirySecs) * time.Second
	}
	return defaultExpiryDuration, nil
}

// Validate - validates the access token.
func (p *JWT) Validate(r *http.Request) (map[string]interface{}, error) {
	token := r.URL.Query().Get("Token")
	keyFuncCallback := func(jwtToken *jwtgo.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwtgo.SigningMethodRSA); !ok {
			if _, ok = jwtToken.Method.(*jwtgo.SigningMethodECDSA); ok {
				return p.args.publicKey, nil
			}
			return nil, fmt.Errorf("Unexpected signing method: %v", jwtToken.Header["alg"])
		}
		return p.args.publicKey, nil
	}

	var claims jwtgo.MapClaims
	jwtToken, err := jwtgo.ParseWithClaims(token, &claims, keyFuncCallback)
	if err != nil {
		return nil, err
	}

	if !jwtToken.Valid {
		return nil, fmt.Errorf("Invalid token: %v", token)
	}

	expAt, err := expToInt64(claims["exp"])
	if err != nil {
		return nil, err
	}

	defaultExpiryDuration, err := getDefaultExpiration(r)
	if err != nil {
		return nil, err
	}

	if time.Unix(expAt, 0).UTC().Sub(time.Now().UTC()) < defaultExpiryDuration {
		defaultExpiryDuration = time.Unix(expAt, 0).UTC().Sub(time.Now().UTC())
	}

	expiry := time.Now().UTC().Add(defaultExpiryDuration).Unix()
	if expAt < expiry {
		claims["exp"] = strconv.FormatInt(expAt, 64)
	}

	return claims, nil

}

// ID returns the provider name and authentication type.
func (p *JWT) ID() auth.ValidatorID {
	return "jwt"
}

// NewJWT - initialize new jwt authenticator.
func NewJWT(args JWTArgs) *JWT {
	return &JWT{
		args: args,
	}
}
